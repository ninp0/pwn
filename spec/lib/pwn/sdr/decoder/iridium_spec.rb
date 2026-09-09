# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::Iridium do
  let(:fixture_dir) { File.expand_path('../../../../fixtures/sdr/iridium', __dir__) }
  let(:vectors) { JSON.parse(File.read(File.join(fixture_dir, 'vectors.json')), symbolize_names: true) }

  it 'decodes independently received ring alert framing, BCH and geographic payload' do
    vectors.each do |vector|
      frame = described_class.decode_ring_alert(bits: vector[:bits])
      expect(frame).to include(protocol: 'IRIDIUM', frame_type: 'IRA', decoded: true,
                               sat: vector[:sat], beam: vector[:beam], integrity: 'BCH(31,21)+parity')
      expect(frame[:latitude]).to be_within(0.005).of(vector[:latitude])
      expect(frame[:longitude]).to be_within(0.005).of(vector[:longitude])
      expect(frame[:pages]).to eq([])
    end
  end

  it 'corrects every single and double bit error in the interleaved IRA header' do
    bits = vectors.first[:bits]
    positions = (24...120).to_a
    (positions.map { |pos| [pos] } + positions.combination(2).to_a).each do |flips|
      damaged = bits.dup
      flips.each { |pos| damaged[pos] = damaged[pos] == '0' ? '1' : '0' }
      frame = described_class.decode_ring_alert(bits: damaged)
      expect(frame).to include(sat: 109, beam: 23, corrected_bits: flips.length)
    end
  end

  it 'rejects uncorrectable, truncated and nonbinary IRA frames' do
    bits = vectors.first[:bits]
    damaged = bits.dup
    [24, 25, 30].each { |pos| damaged[pos] = damaged[pos] == '0' ? '1' : '0' }
    [damaged, bits[0, 119], bits[0, 183], "#{bits}x", '0' * 184].each do |bad|
      expect { described_class.decode_ring_alert(bits: bad) }.to raise_error(ArgumentError)
    end
  end

  it 'decodes captured synchronized symbol IQ through the public file API' do
    require 'stringio'
    require 'digest'
    vectors.each do |vector|
      file = File.join(fixture_dir, vector[:file])
      expect(Digest::SHA256.file(file).hexdigest).to eq(vector[:sha256])
      frames = []
      described_class.decode(mode: :ira_symbols_iq, source: :file, file: file,
                             iq_format: :cs16, sample_rate: 25_000, interactive: false,
                             output: StringIO.new, log_file: false, on_frame: ->(frame) { frames << frame })
      expect(frames.length).to eq(1)
      expect(frames.first).to include(sat: vector[:sat], beam: vector[:beam], source: 'symbol-iq', decoded: true)
    end
  end

  it 'pins the independent source rows and unscaled float IQ hashes' do
    require 'digest'
    rows = File.readlines(File.join(fixture_dir, 'source-rows.tsv'))
    expect(rows.length).to eq(vectors.length)
    vectors.each_with_index do |vector, index|
      expect(Digest::SHA256.hexdigest(rows[index])).to eq(vector[:source_row_sha256])
      expect(Digest::SHA256.file(File.join(fixture_dir, vector[:cf32_file])).hexdigest).to eq(vector[:cf32_sha256])
    end
  end

  it 'does not swallow callback failures as corrupt packets' do
    demod = described_class::RingAlertSymbolsIQ.new
    iq = File.binread(File.join(fixture_dir, vectors.first[:cf32_file])).unpack('e*')
    expect { demod.feed_iq(iq) { raise ArgumentError, 'callback failed' } }.to raise_error(ArgumentError, 'callback failed')
  end

  it 'emits an IRA payload before stream EOF across odd byte chunks' do
    require 'timeout'
    require 'stringio'
    reader, writer = IO.pipe
    frames = Queue.new
    worker = Thread.new do
      described_class.decode(mode: :ira_symbols_iq, source: reader, iq_format: :cs16, sample_rate: 25_000,
                             chunk_bytes: 7, interactive: false, output: StringIO.new, log_file: false,
                             on_frame: ->(frame) { frames << frame })
    end
    writer.write(File.binread(File.join(fixture_dir, vectors.first[:file])))
    frame = Timeout.timeout(5) { frames.pop }
    expect(frame).to include(frame_type: 'IRA', sat: 109, beam: 23, decoded: true)
    expect(writer).not_to be_closed
    writer.close
    Timeout.timeout(5) { worker.value }
  ensure
    writer&.close unless writer&.closed?
    reader&.close unless reader&.closed?
    worker&.kill if worker&.alive?
    worker&.join
  end

  it 'rejects acquisition and unsupported rates before touching the shared runner' do
    allow(PWN::SDR::Decoder::Base).to receive(:run_iq) { raise 'unexpected source acquisition' }
    expect { described_class.decode(mode: :ira_symbols_iq) }.to raise_error(ArgumentError, /Explicit/)
    expect { described_class.decode(mode: :ira_symbols_iq, source: :rtlsdr, file: 'ignored.cs16') }.to raise_error(ArgumentError, /Explicit/)
    expect { described_class.decode(mode: :ira_symbols_iq, sample_rate: 2_000_000) }.to raise_error(ArgumentError, /25000/)
  end

  it 'separates detection from unsupported raw IQ decoding' do
    expect(described_class).to respond_to(:detect)
    expect { described_class.decode(freq_obj: {}) }.to raise_error(NotImplementedError, /IQ/)
  end

  it 'emits an observation through the public detector before IQ source EOF' do
    require 'timeout'
    require 'stringio'
    reader, writer = IO.pipe
    frames = Queue.new
    worker = Thread.new do
      described_class.detect(freq_obj: {}, source: reader, iq_format: :cs16, sample_rate: 8000,
                             interactive: false, output: StringIO.new, log_file: false,
                             on_frame: ->(frame) { frames << frame })
    end
    iq = (([0.01] * 80) + ([1.0] * 40) + ([0.01] * 80)).flat_map { |amp| [amp, 0.0] }
    writer.write(iq.map { |v| (v * 16_000).round }.pack('s<*'))
    frame = Timeout.timeout(5) { frames.pop }
    expect(frame).to include(capability: 'detector-only', decoded: false, event: 'burst')
    expect(writer).not_to be_closed
    writer.close
    Timeout.timeout(5) { worker.value }
  ensure
    writer&.close unless writer&.closed?
    reader&.close unless reader&.closed?
    worker&.kill if worker&.alive?
    worker&.join
  end

  it 'emits no observations from constant noise-floor IQ' do
    demod = described_class::DemodIQ.new(rate: 8000, protocol: 'IRIDIUM', modulation: 'DE-QPSK')
    frames = []
    demod.feed_iq(Array.new(800) { [0.01, 0.0] }.flatten) { |frame| frames << frame }
    expect(frames).to eq([])
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::Iridium
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::Iridium
    expect(help_response).to respond_to :help
  end
end
