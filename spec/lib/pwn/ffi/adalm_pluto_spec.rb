# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::AdalmPluto do
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

  it 'should report library info when libiio is present' do
    skip 'libiio not installed' unless PWN::FFI::AdalmPluto.available?

    info = PWN::FFI::AdalmPluto.info
    expect(info[:available]).to eq(true)
    expect(info[:major]).to be_a(Integer)
    expect(info[:minor]).to be_a(Integer)
  end

  it 'should list URIs (possibly empty) when libiio is present' do
    skip 'libiio not installed' unless PWN::FFI::AdalmPluto.available?

    # Restrict to usb,local so libiio does not attempt mDNS/DNS-SD (avahi)
    # discovery during the test suite — avoids the noisy
    #   "ERROR: Unable to create Avahi DNS-SD client :Daemon not running"
    # C-level stderr write on hosts where avahi-daemon is not running.
    list = PWN::FFI::AdalmPluto.list_uris(backends: 'usb,local')
    expect(list).to be_a(Array)
  end

  it 'should appear in PWN::FFI.backends' do
    expect(PWN::FFI.backends).to have_key(:AdalmPluto)
  end
end
