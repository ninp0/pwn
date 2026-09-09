# frozen_string_literal: true

require 'spec_helper'
require 'timeout'
require 'digest'

describe PWN::SDR::Decoder::LTE do
  it 'separates detection from unsupported raw IQ decoding' do
    expect(described_class).to respond_to(:detect)
    expect { described_class.decode(freq_obj: {}) }.to raise_error(NotImplementedError, /IQ/)
  end

  if File.file?(File.expand_path('../../../../../ext/pwn_lte/libpwn_lte.so', __dir__)) || ENV['PWN_TEST_LTE_NATIVE'] == '1'
    it 'decodes the pinned upstream PBCH IQ subframe with native OFDM, channel estimation and CRC' do
      # Lossless float read, then deterministic 16-bit quantization at half gain.
      raw = File.binread(File.expand_path('../../../../fixtures/sdr/lte/signal.1.92M.dat', __dir__), 15_360)
                .unpack('e*').map { |v| (v * 16_000).round }.pack('s<*')
      frames = []
      result = described_class.decode(mode: :pbch_sf0_iq, pci: 150,
                                      source: StringIO.new(raw), iq_format: :cs16,
                                      sample_rate: 1_920_000, chunk_bytes: 998,
                                      interactive: false, output: StringIO.new, log_file: false,
                                      on_frame: ->(frame) { frames << frame })
      expect(result[:reason]).to eq(:eof)
      expect(frames.length).to eq(1)
      expect(frames.first).to include(protocol: 'LTE', event: 'mib', decoded: true,
                                      checksum_verified: true, payload_hex: '681c00',
                                      pci: 150, ports: 2, prb: 50, sfn_msb: 28)
    end

    it 'acquires PCI and SF0 timing from upstream IQ before decoding a CRC-verified MIB' do
      raw = File.binread(File.expand_path('../../../../fixtures/sdr/lte/signal.1.92M.dat', __dir__))
                .unpack('e*').map { |v| (v * 16_000).round }.pack('s<*')
      frames = []
      result = described_class.decode(mode: :pbch_iq, source: StringIO.new(("\x00" * (137 * 4)) + raw),
                                      iq_format: :cs16, chunk_bytes: 997, interactive: false,
                                      output: StringIO.new, log_file: false,
                                      on_frame: ->(frame) { frames << frame })
      expect(result[:reason]).to eq(:eof)
      expect(frames.length).to eq(1)
      expect(frames.first).to include(event: 'mib', decoded: true, checksum_verified: true,
                                      payload_hex: '681c00', pci: 150, pci_source: 'pss-sss',
                                      timing_sample: 137, prb: 50, ports: 2,
                                      capability: 'acquired-pbch-mib')
    end

    it 'acquires across overlapping search windows with carrier offset and emits before EOF' do
      original = File.binread(File.expand_path('../../../../fixtures/sdr/lte/signal.1.92M.dat', __dir__)).unpack('e*')
      shifted = original.each_slice(2).with_index.flat_map do |(re, im), index|
        value = Complex(re, im) * Complex.polar(1, 2 * Math::PI * 1200 * index / 1_920_000)
        [value.real, value.imaginary]
      end
      raw = (Array.new(8501 * 2, 0.0) + shifted + Array.new(4000, 0.0))
            .map { |value| (value * 16_000).round }.pack('s<*')
      reader, writer = IO.pipe
      frames = Queue.new
      worker = Thread.new do
        described_class.decode(mode: :pbch_iq, source: reader, iq_format: :cs16,
                               chunk_bytes: 997, interactive: false, output: StringIO.new,
                               log_file: false, on_frame: ->(frame) { frames << frame })
      end
      writer.write(raw)
      frame = Timeout.timeout(10) { frames.pop }
      expect(writer).not_to be_closed
      expect(frame).to include(payload_hex: '681c00', pci: 150, timing_sample: 8501, checksum_verified: true)
      # The upstream capture already has approximately -500 Hz CFO.
      expect(frame[:cfo_hz]).to be_within(150).of(700)
      writer.close
      expect(Timeout.timeout(10) { worker.value }[:reason]).to eq(:eof)
      expect(frames).to be_empty
    ensure
      writer&.close unless writer&.closed?
      reader&.close unless reader&.closed?
      worker&.kill if worker&.alive?
      worker&.join
    end

    it 'does not turn noise, incomplete SF0, or PSS/SSS without PBCH into decoded MIBs' do
      original = File.binread(File.expand_path('../../../../fixtures/sdr/lte/signal.1.92M.dat', __dir__), 15_360).unpack('e*')
      random = Random.new(36_212)
      [Array.new(19_200, 0.0), Array.new(19_200) { random.rand - 0.5 },
       original.first(2800), original.first(1920) + Array.new(17_280, 0.0)].each do |iq|
        demod = described_class::AcquiredPBCHIQ.new
        frames = []
        iq.each_slice(998) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
        demod.flush { |frame| frames << frame }
        expect(frames).to eq([])
      end
    end

    it 'rejects wrong-PCI and zero-energy IQ without decoded-success frames' do
      iq = File.binread(File.expand_path('../../../../fixtures/sdr/lte/signal.1.92M.dat', __dir__), 15_360).unpack('e*')
      [[151, iq], [150, Array.new(3840, 0.0)]].each do |pci, samples|
        frames = []
        described_class::PBCHIQ.new(pci: pci).feed_iq(samples) { |frame| frames << frame }
        expect(frames).to eq([])
      end
    end

    it 'rejects an incomplete subframe instead of padding it into a successful decode' do
      demod = described_class::PBCHIQ.new(pci: 150)
      demod.feed_iq([0.0, 0.0]) { |frame| raise frame.inspect }
      expect { demod.flush }.to raise_error(ArgumentError, /truncated/)
    end

    it 'emits before pipe EOF and preserves chunk boundaries' do
      raw = File.binread(File.expand_path('../../../../fixtures/sdr/lte/signal.1.92M.dat', __dir__), 15_360)
                .unpack('e*').map { |v| (v * 16_000).round }.pack('s<*')
      reader, writer = IO.pipe
      frames = Queue.new
      worker = Thread.new do
        described_class.decode(mode: :pbch_sf0_iq, pci: 150, source: reader,
                               iq_format: :cs16, chunk_bytes: 997, interactive: false,
                               output: StringIO.new, log_file: false,
                               on_frame: ->(frame) { frames << frame })
      end
      writer.write(raw)
      frame = Timeout.timeout(5) { frames.pop }
      expect(writer).not_to be_closed
      expect(frame).to include(payload_hex: '681c00', checksum_verified: true)
      writer.close
      expect(Timeout.timeout(5) { worker.value }[:reason]).to eq(:eof)
    ensure
      writer&.close unless writer&.closed?
      reader&.close unless reader&.closed?
      worker&.kill if worker&.alive?
      worker&.join
    end
  end

  it 'refuses unsupported PHY settings instead of silently using another waveform' do
    [{ cyclic_prefix: :extended }, { duplex: :tdd }, { tx_ports: 1 }].each do |setting|
      expect do
        described_class.decode({ mode: :pbch_sf0_iq, pci: 150, source: StringIO.new }.merge(setting))
      end.to raise_error(NotImplementedError, /FDD.*normal.*two/)
    end
  end

  it 'pins the upstream IQ fixture rather than synthesizing expected PBCH bits' do
    path = File.expand_path('../../../../fixtures/sdr/lte/signal.1.92M.dat', __dir__)
    expect(Digest::SHA256.file(path).hexdigest).to eq('d658e615c10c8e65b8c190d7cf2592237fd430411936b4d82c7b30c008c1ab21')
  end

  it 'refuses missing PCI, wrong rate and automatic or hardware sources before opening a backend' do
    expect(described_class::PBCHIQ).not_to receive(:new)
    expect { described_class.decode(mode: :pbch_sf0_iq, source: StringIO.new) }.to raise_error(ArgumentError, /PCI/)
    expect { described_class.decode(mode: :pbch_sf0_iq, pci: 150, sample_rate: 2_000_000) }.to raise_error(ArgumentError, /sample_rate/)
    [nil, :rtlsdr, { kind: :hackrf }].each do |source|
      expect { described_class.decode(mode: :pbch_sf0_iq, pci: 150, source: source) }.to raise_error(ArgumentError, /offline/)
    end
  end

  it 'resamples fixed source windows rather than resetting at transport boundaries' do
    dsp = PWN::SDR::Decoder::DSP
    iq = Array.new(800) { |i| Math.sin(i * 0.1) }
    inputs = [iq.length, 14].map do |size|
      windows = []
      allow(dsp).to receive(:resample_iq) do |opts|
        windows << opts[:iq].dup
        []
      end
      demod = described_class::DemodIQ.new(rate: 8000)
      iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |_f| nil } }
      windows
    end
    expect(inputs.first).not_to be_empty
    expect(inputs.last).to eq(inputs.first)
  end

  it 'labels a PSS observation as cell-search only, not decoded traffic' do
    demod = described_class::DemodIQ.new(rate: described_class::FS_BASE)
    allow(demod).to receive(:search_pss).and_return(nid2: 1, pos: 100, ratio: 10, cfo_hz: 0)
    frames = []
    demod.feed_iq(Array.new(38_400, 0.1)) { |f| frames << f }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(capability: 'cell-search-only', decoded: false, nid1: nil, pci: nil)
  end

  it 'rejects deterministic white IQ noise rather than identifying a cell' do
    random = Random.new(36_211)
    iq = Array.new(38_400) { random.rand - 0.5 }
    frames = []
    described_class::DemodIQ.new(rate: described_class::FS_BASE).feed_iq(iq) { |frame| frames << frame }
    expect(frames).to eq([])
  end

  it 'detects a TS 36.211 PSS waveform without fabricating a PCI or payload' do
    # Independent inverse OFDM construction, root u=29 / N_ID_2=1.
    pss = Array.new(128) do |t|
      (0...62).sum do |m|
        n = m < 31 ? m : m + 1
        k = m < 31 ? m - 31 : m - 30
        Complex.polar(1.0 / 128, (-Math::PI * 29 * n * (n + 1) / 63) + (2 * Math::PI * k * t / 128))
      end
    end
    pss = pss.flat_map { |z| [z.real, z.imaginary] }
    iq = Array.new(38_400, 0.0)
    iq[800, pss.length] = pss
    frames = []
    described_class::DemodIQ.new(rate: described_class::FS_BASE).feed_iq(iq) { |frame| frames << frame }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(nid2: 1, pci: nil, decoded: false)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::LTE
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::LTE
    expect(help_response).to respond_to :help
  end
end
