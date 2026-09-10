# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::RTLSdr do
  it 'handles a missing shared library without native calls' do
    allow(described_class).to receive(:available?).and_return(false)
    expect { described_class.list_devices }.to raise_error(RuntimeError, /librtlsdr not available/)
    expect { described_class.open }.to raise_error(RuntimeError, /librtlsdr not available/)
  end

  it 'releases the GVL during native reads so DSP workers can run' do
    source = File.read(File.expand_path('../../../../lib/pwn/ffi/rtl_sdr.rb', __dir__))
    declaration = source[/attach_function :rtlsdr_read_sync,.*?(?=attach_function)/m]
    expect(declaration).to include('blocking: true')
  end

  it 'rejects incomplete IQ pairs instead of returning a misaligned stream' do
    allow(described_class).to receive(:rtlsdr_read_sync) do |_dev, buf, _size, count|
      buf.put_bytes(0, 'abc')
      count.write_int(3)
      0
    end
    expect { described_class.read_sync(device: FFI::MemoryPointer.new(:char), bytes: 4) }
      .to raise_error(/invalid.*length/i)
  end

  it 'should display information for authors' do
    expect(PWN::FFI::RTLSdr).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::RTLSdr).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::RTLSdr).to respond_to :available?
  end

  it 'maps device inventory using mocked USB calls' do
    allow(described_class).to receive(:available?).and_return(true)
    allow(described_class).to receive(:rtlsdr_get_device_count).and_return(1)
    allow(described_class).to receive(:rtlsdr_get_device_name).with(0).and_return('Mock tuner')
    expect(described_class).to receive(:rtlsdr_get_device_usb_strings) do |index, manufacturer, product, serial|
      expect(index).to eq(0)
      manufacturer.write_string('Test')
      product.write_string('SDR')
      serial.write_string('123')
      0
    end
    expect(described_class.list_devices).to eq([{ index: 0, name: 'Mock tuner', manufacturer: 'Test', product: 'SDR', serial: '123' }])
  end

  it 'loads the native inventory and read bindings without scanning USB', :rtl_sdr_integration do
    expect(described_class.available?).to be(true), 'Install librtlsdr and make it visible to the dynamic loader (PWN_TEST_RTL_SDR=1).'
    expect(described_class).to respond_to(:rtlsdr_get_device_count, :rtlsdr_read_sync)
  end

  it 'lists a connected RTL-SDR', :rtl_sdr_hardware do
    expect(described_class.available?).to be(true), 'Install librtlsdr before enabling PWN_TEST_RTL_SDR_HARDWARE=1.'
    expect(described_class.list_devices).not_to be_empty, 'Connect an RTL-SDR with USB permissions before enabling PWN_TEST_RTL_SDR_HARDWARE=1.'
  end
end
