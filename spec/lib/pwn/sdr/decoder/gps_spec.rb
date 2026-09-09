# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::GPS do
  it 'requires explicit IQ files and never selects RF hardware' do
    expect(described_class).to respond_to(:detect)
    expect(PWN::SDR::Decoder::Base).not_to receive(:run_iq)
    expect { described_class.decode(freq_obj: {}) }.to raise_error(ArgumentError, /explicit/)
    expect { described_class.decode(mode: :unknown) }.to raise_error(ArgumentError, /mode/)
  end

  if ENV['PWN_GPS_IQ_FIXTURE']
    it 'tracks external CTTC IQ into parity-validated LNAV while the receiver is running' do
      frames = []
      receiver_pid = nil
      allow(Process).to receive(:spawn).and_wrap_original do |original, *args, **kwargs|
        receiver_pid = original.call(*args, **kwargs)
      end
      before_eof = false
      callback = lambda do |frame|
        frames << frame
        source = File.realpath(ENV.fetch('PWN_GPS_IQ_FIXTURE'))
        fd = Dir["/proc/#{receiver_pid}/fd/*"].find do |path|
          File.realpath(path) == source
        rescue StandardError
          false
        end
        position = File.read("/proc/#{receiver_pid}/fdinfo/#{File.basename(fd)}")[/^pos:\s+(\d+)/, 1].to_i if fd
        before_eof ||= !position.nil? && position < File.size(source)
      end
      result = described_class.decode(
        mode: :iq, source: :file, file: ENV.fetch('PWN_GPS_IQ_FIXTURE'),
        sample_rate: 4_000_000, iq_format: :cs16, duration: 90,
        on_frame: callback, stop: -> { !frames.empty? }
      )
      expect(result[:frames]).not_to be_empty
      expect(frames).to all(include(decoded: true, checksum_verified: true, capability: 'iq-lnav-decode'))
      expect(result[:reason]).to eq(:stopped)
      expect(before_eof).to be(true)
      expect { Process.kill(0, receiver_pid) }.to raise_error(Errno::ESRCH)
    end
  end

  it 'fails clearly when the optional native receiver is absent and removes its workspace' do
    require 'tempfile'
    require 'tmpdir'
    directory = nil
    allow(Dir).to receive(:mktmpdir).and_wrap_original do |original, *args, &block|
      original.call(*args) do |path|
        directory = path
        block.call(path)
      end
    end
    Tempfile.create('gps-iq') do |file|
      file.write("\x00" * 4000)
      file.flush
      expect do
        described_class.decode(source: :file, file: file.path, gnss_sdr: '/nonexistent/pwn-gnss-sdr')
      end.to raise_error(LoadError, /optional native/)
    end
    expect(File.exist?(directory)).to be(false)
  end

  it 'surfaces native failures instead of reporting a successful decode' do
    require 'tempfile'
    Tempfile.create('gps-iq') do |file|
      file.write("\x00" * 4000)
      file.flush
      expect do
        described_class.decode(source: :file, file: file.path, gnss_sdr: '/bin/false')
      end.to raise_error(IOError, /gnss-sdr failed/)
      expect do
        described_class.decode(source: :file, file: file.path, iq_format: :cu8)
      end.to raise_error(ArgumentError, /iq_format/)
    end
  end

  # Synthetic IS-GPS-200 LNAV words, parity independently encoded with
  # RTKLIB src/rtkcmn.c decode_word parity matrix; includes D30* inversion.
  let(:lnav_bits) do
    %w[22c00012 000c8134 0e600002 00000029 3fffffd6 00000029 3fffffd6 00000029 3fffffd6 0000008c].flat_map do |hex|
      format('%030b', hex.to_i(16)).chars.map(&:to_i)
    end
  end

  it 'restores monitor data inversion before independently checking parity' do
    previous = 0
    monitor = lnav_bits.each_slice(30).map do |bits|
      raw = bits.join.to_i(2)
      word = previous.odd? ? raw ^ 0x3fffffc0 : raw
      previous = raw & 3
      format('%030b', word)
    end.join
    expect(described_class.decode_monitor(nav_message: monitor, prn: 7)).to include(
      prn: 7, checksum_verified: true, capability: 'iq-lnav-decode', tow_next_seconds: 600
    )
    monitor[65] = monitor[65] == '1' ? '0' : '1'
    expect(described_class.decode_monitor(nav_message: monitor, prn: 7)).to be_nil
  end

  it 'parses bounded native monitor protobuf without accepting malformed packets' do
    packet = "\x0a\x01G\x12\x021C\x18\x07\x20\x01\x2a\xac\x02".b + ('0' * 300)
    expect(described_class::IQTracker.parse_packet(packet: packet)).to eq(system: 'G', signal: '1C', prn: 7, tow_ms: 1, nav_message: '0' * 300)
    expect(described_class::IQTracker.parse_packet(packet: packet[0...-1])).to be_nil
    expect(described_class::IQTracker.parse_packet(packet: "\xff" * 30)).to be_nil
  end

  it 'decodes the captured CTTC monitor fixture without double inversion' do
    require 'json'
    fixture = JSON.parse(File.read(File.expand_path('../../../../fixtures/sdr/gps/cttc-lnav.json', __dir__)), symbolize_names: true)
    frame = described_class.decode_monitor(fixture[:monitor])
    expect(frame).to eq(fixture[:expected])
    expect(frame[:tow_next_seconds] * 1000).to eq(fixture[:monitor][:tow_ms])
  end

  it 'decodes a framed LNAV subframe with all ten word parity checks' do
    frames = described_class.decode(mode: :lnav_bits, bit_chunks: [lnav_bits])
    expect(frames.length).to eq(1)
    expect(frames.first).to include(decoded: true, checksum_verified: true, subframe_id: 1, tow_next_seconds: 600, week_mod1024: 230)
    expect(frames.first[:payload_hex]).to start_with('8b0000003204')
    expect(frames.first[:payload_hex].length).to eq(60)
  end

  it 'streams arbitrary chunks and inverted symbols before EOF' do
    frames = []
    chunks = Enumerator.new do |y|
      ([0, 1, 0] + lnav_bits.map { |b| b ^ 1 }).each_slice(11) { |chunk| y << chunk }
      expect(frames.length).to eq(1)
    end
    expect(described_class.decode(mode: :lnav_bits, bit_chunks: chunks, on_frame: ->(f) { frames << f })).to eq(frames)
  end

  it 'rejects corruption in every word, truncated frames, noise and malformed symbols' do
    10.times do |word|
      corrupt = lnav_bits.dup
      corrupt[(word * 30) + 12] ^= 1
      expect(described_class.decode(mode: :lnav_bits, bit_chunks: [corrupt])).to eq([])
    end
    expect(described_class.decode(mode: :lnav_bits, bit_chunks: [lnav_bits.first(299)])).to eq([])
    random = Random.new(200)
    expect(described_class.decode(mode: :lnav_bits, bit_chunks: [Array.new(4000) { random.rand(2) }])).to eq([])
    expect { described_class.decode_subframe(bits: [2]) }.to raise_error(ArgumentError)
    expect { described_class.decode(mode: :lnav_bits, bit_chunks: [[0, 2]]) }.to raise_error(ArgumentError)
  end

  it 'drains every complete acquisition window in a chunk without waiting for another feed' do
    demod = described_class::DemodIQ.new(rate: described_class::ACQ_RATE)
    allow(demod).to receive(:acquire).and_return([{ prn: 1, cn0_db_hz: 20 }], [{ prn: 2, cn0_db_hz: 20 }])
    frames = []
    demod.feed_iq(Array.new(2046 * 2 * 2, 0.1)) { |f| frames << f }
    expect(frames.map { |f| f[:prn] }).to eq([1, 2])
    expect(frames).to all(include(capability: 'acquisition-only', decoded: false))
  end

  it 'rejects noninteger binary-looking symbols' do
    expect { described_class.decode_subframe(bits: Array.new(300, 0.0)) }.to raise_error(ArgumentError)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::GPS
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::GPS
    expect(help_response).to respond_to :help
  end
end
