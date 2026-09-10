# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::HackRF do
  it 'handles a missing shared library without native calls' do
    allow(described_class).to receive(:available?).and_return(false)
    expect(described_class.info).to include(available: false)
    expect { described_class.open }.to raise_error(RuntimeError, /libhackrf not available/)
  end

  it 'releases the GVL while native stop waits for callbacks' do
    source = File.read(File.expand_path('../../../../lib/pwn/ffi/hack_rf.rb', __dir__))
    expect(source).to match(/attach_function :hackrf_stop_rx, \[:pointer\], :int, blocking: true/)
  end

  it 'retains callback ownership when native stop fails' do
    callback = Object.new
    handle = { device: FFI::MemoryPointer.new(:char), callback: callback, queue: Queue.new }
    allow(described_class).to receive(:hackrf_stop_rx).and_return(-1)
    expect { described_class.stop_rx(handle: handle) }.to raise_error
    expect(handle[:callback]).to equal(callback)
  end

  it 'surfaces callback errors arriving while a reader waits' do
    handle = { queue: Queue.new }
    allow(described_class).to receive(:sleep) { handle[:error] = RuntimeError.new('callback failed') }
    expect { described_class.read_sync(handle: handle, timeout: 0.01) }.to raise_error('callback failed')
  end

  it 'bounds callback buffering and reports dropped IQ before returning more data' do
    allow(described_class).to receive(:available?).and_return(true)
    allow(described_class).to receive(:hackrf_start_rx).and_return(0)
    device = FFI::MemoryPointer.new(:char)
    handle = described_class.start_rx(device: device, max_queue: 1)
    bytes = FFI::MemoryPointer.new(:char, 4)
    bytes.put_bytes(0, 'abcd')
    transfer = described_class::Transfer.new
    transfer[:buffer] = bytes
    transfer[:buffer_length] = 4
    transfer[:valid_length] = 4
    2.times { handle[:callback].call(transfer.pointer) }
    expect(handle[:queue].size).to eq(1)
    expect(handle[:dropped_bytes]).to eq(4)
    expect { described_class.read_sync(handle: handle) }.to raise_error(/overrun/i)
  end

  it 'should display information for authors' do
    expect(PWN::FFI::HackRF).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::HackRF).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::HackRF).to respond_to :available?
  end

  it 'should report library info', :hack_rf_integration do
    expect(described_class.available?).to be(true), 'Install libhackrf and make it visible to the dynamic loader (PWN_TEST_HACK_RF=1).'

    info = PWN::FFI::HackRF.info
    expect(info[:available]).to eq(true)
    expect(info[:library_version]).to be_a(String)
  end
end
