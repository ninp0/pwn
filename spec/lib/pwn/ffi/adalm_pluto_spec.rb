# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::AdalmPluto do
  it 'handles a missing shared library without native calls' do
    allow(described_class).to receive(:available?).and_return(false)
    expect(described_class.info).to include(available: false)
    expect(described_class.list_uris).to eq([])
  end

  it 'waits for a cancelled refill to return before destroying its buffer' do
    handle = { buffer: FFI::MemoryPointer.new(:char, 4) }
    entered = Queue.new
    resume = Queue.new
    completed = Queue.new
    allow(described_class).to receive(:iio_buffer_refill) do
      entered.push(true)
      resume.pop
      completed.push(true)
      -125
    end
    allow(described_class).to receive(:iio_buffer_cancel) { resume.push(true) }
    allow(described_class).to receive(:iio_buffer_destroy) { expect(completed.pop(true)).to eq(true) }
    reader = Thread.new do
      described_class.read_sync(handle: handle)
    rescue RuntimeError
      nil
    end
    entered.pop
    described_class.stop_rx(handle: handle)
  ensure
    resume&.push(true)
    reader&.join(1)
    reader&.kill if reader&.alive?
  end

  it 'releases the GVL during refills' do
    source = File.read(File.expand_path('../../../../lib/pwn/ffi/adalm_pluto.rb', __dir__))
    declaration = source[/attach_function :iio_buffer_refill[^\n]+/]
    expect(declaration).to include('blocking: true')
  end

  it 'rejects a truncated IQ scan rather than returning corrupt CS16' do
    handle = { buffer: FFI::MemoryPointer.new(:char, 4) }
    allow(described_class).to receive(:iio_buffer_refill).and_return(3)
    allow(described_class).to receive(:iio_buffer_start).and_return(handle[:buffer])
    expect { described_class.read_sync(handle: handle) }.to raise_error(/invalid.*length/i)
  end

  it 'destroys an RX buffer only once across repeated stops' do
    handle = { buffer: FFI::MemoryPointer.new(:char) }
    allow(described_class).to receive(:iio_buffer_cancel)
    expect(described_class).to receive(:iio_buffer_destroy).once
    2.times { described_class.stop_rx(handle: handle) }
    expect(handle[:buffer]).to be_nil
  end

  it 'should display information for authors' do
    expect(PWN::FFI::AdalmPluto).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::AdalmPluto).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::AdalmPluto).to respond_to :available?
  end

  it 'should report library info', :adalm_pluto_integration do
    expect(described_class.available?).to be(true), 'Install compatible libiio and make it visible to the dynamic loader (PWN_TEST_ADALM_PLUTO=1).'

    info = PWN::FFI::AdalmPluto.info
    expect(info[:available]).to eq(true)
    expect(info[:major]).to be_a(Integer)
    expect(info[:minor]).to be_a(Integer)
  end

  it 'maps URIs and releases the mocked scan without hardware discovery' do
    allow(described_class).to receive(:available?).and_return(true)
    scan = FFI::MemoryPointer.new(:char)
    entry = FFI::MemoryPointer.new(:char)
    entries = FFI::MemoryPointer.new(:pointer)
    entries.write_pointer(entry)
    expect(described_class).to receive(:iio_create_scan_context).with('usb,local', 0).and_return(scan)
    expect(described_class).to receive(:iio_scan_context_get_info_list) do |context, output|
      expect(context).to eq(scan)
      output.write_pointer(entries)
      1
    end
    allow(described_class).to receive(:iio_context_info_get_uri).with(entry).and_return('usb:mock')
    allow(described_class).to receive(:iio_context_info_get_description).with(entry).and_return('Mock Pluto')
    expect(described_class).to receive(:iio_context_info_list_free).with(entries)
    expect(described_class).to receive(:iio_scan_context_destroy).with(scan)
    expect(described_class.list_uris(backends: 'usb,local')).to eq([{ uri: 'usb:mock', description: 'Mock Pluto' }])
  end

  it 'should appear in PWN::FFI.backends' do
    expect(PWN::FFI.backends).to have_key(:AdalmPluto)
  end
end
