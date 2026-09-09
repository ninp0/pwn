# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

describe PWN::SDR::Decoder::GSM do
  it 'requires an explicit IQ source and rejects unsupported traffic modes before acquisition' do
    allow(PWN::SDR::Decoder::Base).to receive(:run_iq).and_raise('unexpected acquisition')
    expect { described_class.decode(freq_obj: {}) }.to raise_error(ArgumentError, /explicit/)
    expect { described_class.decode(mode: :traffic) }.to raise_error(NotImplementedError, /traffic/)
  end

  it 'decodes independently modulated GMSK IQ with timing and carrier offset' do
    frames = []
    result = described_class.decode(source: :file, file: File.expand_path('../../../../fixtures/sdr/gsm/sch.cs16', __dir__),
                                    sample_rate: 1_083_333, iq_format: :cs16, chunk_bytes: 113,
                                    interactive: false, output: StringIO.new, log_file: false,
                                    on_frame: ->(frame) { frames << frame })
    expect(result).to include(reason: :eof, frames: 1)
    expect(frames.first).to include(described_class.decode_sch(bits: sch_coded))
    expect(frames.first[:freq_offset_hz]).to be_within(500).of(6000)
  end

  it 'emits a verified IQ frame through a real pipe before source EOF' do
    reader, writer = IO.pipe
    emitted = Queue.new
    worker = Thread.new do
      described_class.decode(source: reader, sample_rate: 1_083_333, iq_format: :cs16,
                             chunk_bytes: 113, interactive: false, output: StringIO.new, log_file: false,
                             on_frame: ->(frame) { emitted << frame })
    end
    writer.write(File.binread(File.expand_path('../../../../fixtures/sdr/gsm/sch.cs16', __dir__)))
    frame = Timeout.timeout(3) { emitted.pop }
    expect(writer).not_to be_closed
    expect(worker).to be_alive
    expect(frame).to include(payload_hex: '03030100', input: 'iq')
    writer.close
    expect(Timeout.timeout(3) { worker.value }).to include(reason: :eof, frames: 1)
  ensure
    writer&.close unless writer&.closed?
    reader&.close unless reader&.closed?
    worker&.kill if worker&.alive?
  end

  it 'has identical one-shot and sample-at-a-time decoding, including noisy IQ' do
    raw = File.binread(File.expand_path('../../../../fixtures/sdr/gsm/sch.cs16', __dir__))
    iq = raw.unpack('s<*').map { |x| x / 32_768.0 }
    random = Random.new(912)
    iq = iq.map { |x| x + ((random.rand - 0.5) * 0.025) }
    outputs = [2, 46, iq.length].map do |size|
      frames = []
      demod = described_class::SCHDemodIQ.new(rate: 1_083_333)
      iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
      expect(demod.instance_variable_get(:@audio).length).to be < 595
      frames
    end
    expect(outputs.first.length).to eq(1)
    expect(outputs).to all(eq(outputs.first))
    expect(outputs.first.first).to include(payload_hex: '03030100')
  end

  it 'matches the optional native scanner against Ruby on independent IQ across chunk boundaries' do
    raw = File.binread(File.expand_path('../../../../fixtures/sdr/gsm/sch.cs16', __dir__))
    iq = raw.unpack('s<*').map { |x| x / 32_768.0 }
    random = Random.new(813)
    iq = iq.map { |x| x + ((random.rand - 0.5) * 0.02) }
    outputs = [false, true].product([2, 46, iq.length]).map do |native, size|
      frames = []
      demod = described_class::SCHDemodIQ.new(rate: 1_083_333, native: native)
      expect(demod.backend).to eq(:ruby) unless native
      expect(demod.backend).to eq(:native) if native && ENV['PWN_GSM_REQUIRE_NATIVE'] == '1'
      iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
      frames
    end
    expect(outputs.first.length).to eq(1)
    expect(outputs).to all(eq(outputs.first))
  end

  it 'falls back to Ruby when the optional scanner library cannot be loaded' do
    path = "../../../../ext/pwn_gsm/libpwn_gsm.#{RbConfig::CONFIG.fetch('DLEXT')}"
    allow(File).to receive(:expand_path).and_call_original
    allow(File).to receive(:expand_path).with(path, anything).and_return('/nonexistent/pwn-gsm-test/library')
    demod = described_class::SCHDemodIQ.new(rate: 1_083_333)
    expect(demod.backend).to eq(:ruby)
    raw = File.binread(File.expand_path('../../../../fixtures/sdr/gsm/sch.cs16', __dir__))
    frames = []
    demod.feed_iq(raw.unpack('s<*').map { |x| x / 32_768.0 }) { |frame| frames << frame }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(payload_hex: '03030100')
  end

  it 'rejects CRC-corrupt GMSK, noise, pure tones and truncated bursts' do
    root = File.expand_path('../../../../fixtures/sdr/gsm', __dir__)
    random = Random.new(10)
    stimuli = [File.binread("#{root}/bad-crc.cs16").unpack('s<*').map { |x| x / 32_768.0 },
               Array.new(4000) { random.rand - 0.5 },
               Array.new(2000) { |i| [Math.cos(i * 0.4), Math.sin(i * 0.4)] }.flatten,
               File.binread("#{root}/sch.cs16").unpack('s<*').first(1200).map { |x| x / 32_768.0 }]
    stimuli.product([false, true]).each do |iq, native|
      frames = []
      demod = described_class::SCHDemodIQ.new(rate: 1_083_333, native: native)
      iq.each_slice(74) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
      expect(frames).to eq([])
    end
  end

  # libosmocore tests/coding/coding_test.ok, SCH Encoding: 03 03 01 00.
  let(:sch_coded) { '111001110011000011100111001100001101001111000000000011010000011010110111111100'.chars.map(&:to_i) }

  it 'decodes a published SCH codeword with verified CRC and field bit ordering' do
    frame = described_class.decode_sch(bits: sch_coded)
    expect(frame).to include(decoded: true, checksum_verified: true, payload_hex: '03030100', bsic: 0, t1: 1542, t2: 0, t3p: 2)
  end

  it 'frames SCH bits incrementally and emits before the input stream ends' do
    burst = [0, 0, 0] + sch_coded.first(39) + described_class::SCH_ETSC + sch_coded.last(39) + [0, 0, 0]
    frames = []
    chunks = Enumerator.new do |y|
      burst.each_slice(7) { |chunk| y << chunk }
      expect(frames.length).to eq(1)
      y << Array.new(148, 0)
    end
    result = described_class.decode(mode: :sch_bits, bit_chunks: chunks, on_frame: ->(frame) { frames << frame })
    expect(result).to eq(frames)
    expect(frames.first).to include(payload_hex: '03030100', checksum_verified: true)
  end

  it 'rejects invalid codewords and malformed bits without successes' do
    expect(described_class.decode_sch(bits: Array.new(78, 0))).to be_nil
    expect { described_class.decode_sch(bits: [0, 1, 2]) }.to raise_error(ArgumentError)
    random = Random.new(128)
    expect(described_class.decode(mode: :sch_bits, bit_chunks: [Array.new(5000) { random.rand(2) }])).to eq([])
  end

  it 'corrects a channel bit error before checking SCH integrity' do
    noisy = sch_coded.dup
    noisy[15] ^= 1
    expect(described_class.decode_sch(bits: noisy)).to include(payload_hex: '03030100', checksum_verified: true)
  end

  it 'preserves FM phase across short IQ chunks' do
    iq = Array.new(100) { |i| [Math.cos(i * 0.2), Math.sin(i * 0.2)] }.flatten
    results = [iq.length, 2].map do |size|
      demod = described_class::DemodIQ.new(rate: 1_083_333)
      iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |_f| nil } }
      demod.instance_variable_get(:@audio)
    end
    expect(results.last).to eq(results.first)
    expect(results.first.length).to eq(99)
  end

  it 'labels frequency synchronization as synchronization-only' do
    demod = described_class::DemodIQ.new(rate: 1_083_332)
    audio = Array.new(592, 0.4) + Array.new(592 * 3) { |i| i.even? ? -0.7 : 0.8 }
    demod.instance_variable_set(:@audio, audio)
    frames = []
    demod.send(:scan) { |f| frames << f }
    demod.send(:scan) { |f| frames << f }
    expect(frames.length).to eq(1)
    expect(frames).to all(include(capability: 'synchronization-only', decoded: false))
  end

  it 'rejects noninteger binary-looking symbols' do
    expect { described_class.decode_sch(bits: Array.new(78, 0.0)) }.to raise_error(ArgumentError)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::GSM
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::GSM
    expect(help_response).to respond_to :help
  end
end
