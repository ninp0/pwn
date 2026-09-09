# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::SoapySDR do
  it 'reports close failure and retains the stream for cleanup retry' do
    handle = { device: :device, stream: :stream }
    allow(described_class).to receive(:SoapySDRDevice_deactivateStream).and_return(0)
    allow(described_class).to receive(:SoapySDRDevice_closeStream).and_return(-2)
    expect { described_class.stop_rx(handle: handle) }.to raise_error(/closeStream.*-2/)
    expect(handle[:stream]).to eq(:stream)
  end

  it 'closes a newly created stream when activation fails' do
    stream = FFI::MemoryPointer.new(:char)
    allow(described_class).to receive(:SoapySDRDevice_setupStream).and_return(stream)
    allow(described_class).to receive(:SoapySDRDevice_activateStream).and_return(-2)
    allow(described_class).to receive(:SoapySDRDevice_lastError).and_return('failed')
    expect(described_class).to receive(:SoapySDRDevice_closeStream).with(:device, stream)
    expect { described_class.start_rx(handle: { device: :device, channel: 0 }) }.to raise_error(/activateStream/)
  end

  it 'raises on overflow rather than disguising lost IQ as timeout' do
    allow(described_class).to receive(:SoapySDRDevice_readStream).and_return(-4)
    handle = { stream: :mock }
    expect { described_class.read_sync(handle: handle) }.to raise_error(/overrun.*-4/i)
    expect(handle[:overruns]).to eq(1)
  end

  it 'should display information for authors' do
    expect(PWN::FFI::SoapySDR).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::SoapySDR).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::SoapySDR).to respond_to :available?
  end

  it 'should report API info when libSoapySDR is present' do
    skip 'libSoapySDR not installed' unless PWN::FFI::SoapySDR.available?

    info = PWN::FFI::SoapySDR.info
    expect(info[:available]).to eq(true)
    expect(info[:api]).to match(/\d+\.\d+/)
  end
end
