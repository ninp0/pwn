# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::RTLSdr do
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

  it 'should list devices (possibly empty) when librtlsdr is present' do
    skip 'librtlsdr not installed' unless PWN::FFI::RTLSdr.available?

    list = PWN::FFI::RTLSdr.list_devices
    expect(list).to be_a(Array)
  end
end
