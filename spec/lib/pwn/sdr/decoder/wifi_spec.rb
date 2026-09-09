# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

describe PWN::SDR::Decoder::WiFi do
  it 'matches the independent IEEE 802.11b draft section 18.2.3.6 PLCP CRC example' do
    # Published transmit-order bits: 01010000 00000000 00000011 00000000;
    # published CRC: 01011011 01010111. Octets here are LSB-first on air.
    expect(described_class.plcp_crc(bytes: [0x0a, 0x00, 0xc0, 0x00])).to eq(0xeada)
  end

  # Synthetic RF modulation from the published PHY, not a recorded WiFi capture.
  def wifi_iq(mac, corrupt_header: false)
    header = [10, 0, mac.bytesize * 8].pack('CCv')
    crc = 0xffff
    header.bytes.each do |byte|
      8.times do |bit|
        feedback = ((crc >> 15) & 1) ^ ((byte >> bit) & 1)
        crc = (crc << 1) & 0xffff
        crc ^= 0x1021 if feedback == 1
      end
    end
    crc_bits = (crc ^ 0xffff).to_s(2).rjust(16, '0').chars.map(&:to_i)
    crc_bits[0] ^= 1 if corrupt_header
    bits = ([1] * 128) + [0xf3a0].pack('v').unpack1('b*').chars.map(&:to_i)
    bits += header.unpack1('b*').chars.map(&:to_i) + crc_bits + mac.unpack1('b*').chars.map(&:to_i)
    registers = [1, 1, 0, 1, 1, 0, 0]
    phase = 1.0
    barker = [1, -1, 1, 1, -1, 1, 1, 1, -1, -1, -1]
    bits.flat_map do |bit|
      scrambled = bit ^ registers[3] ^ registers[6]
      registers = [scrambled] + registers.first(6)
      phase *= -1 if scrambled == 1
      barker.flat_map { |chip| [chip * phase * 0.8, 0.0] }
    end
  end

  let(:ack) do
    body = ['d4000000010203040506'].pack('H*')
    body + [Zlib.crc32(body)].pack('V')
  end

  it 'acquires and decodes a long-preamble 1 Mbps DSSS ACK from unaligned streaming IQ' do
    demod = described_class::DSSSIQ.new(rate: 11_000_000)
    frames = []
    iq = ([0.0, 0.0] * 7) + wifi_iq(ack)
    iq.each_slice(146) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(decoded: true, integrity: 'plcp-crc16-and-mac-fcs32',
                                    type: 1, subtype: 13, receiver: '01:02:03:04:05:06')
  end

  [22_000_000, 44_000_000].each do |rate|
    it "recovers DSSS at #{rate} without duplicate phase-lane frames" do
      iq = wifi_iq(ack).each_slice(2).flat_map { |pair| pair * (rate / 11_000_000) }
      frames = []
      demod = described_class::DSSSIQ.new(rate: rate)
      iq.each_slice(214) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
      expect(frames.length).to eq(1)
      expect(frames.first[:receiver]).to eq('01:02:03:04:05:06')
    end
  end

  it 'parses a beacon SSID and channel after both PHY and MAC integrity checks' do
    body = ['80000000ffffffffffff0011223344550011223344551000'].pack('H*')
    body << [123, 100, 0x431].pack('Q<vv') << [0, 4].pack('CC') << 'test' << [3, 1, 6].pack('C*')
    mac = body + [Zlib.crc32(body)].pack('V')
    frames = []
    described_class::DSSSIQ.new(rate: 11_000_000).feed_iq(wifi_iq(mac)) { |f| frames << f }
    expect(frames.first).to include(type: 0, subtype: 8, ssid: 'test', channel: 6,
                                    transmitter: '00:11:22:33:44:55', bssid: '00:11:22:33:44:55')
  end

  it 'parses four-address QoS data without claiming to decrypt protected payloads' do
    body = [0x0388, 0].pack('vv') + ['00112233445566778899aabbccddeeff001120003344556677880500'].pack('H*')
    body << ['aaaa030000000800'].pack('H*') << 'payload'
    mac = body + [Zlib.crc32(body)].pack('V')
    frame = described_class.parse_frame(bytes: mac)
    expect(frame).to include(type: 2, source_address: '33:44:55:66:77:88',
                             destination: 'cc:dd:ee:ff:00:11', qos_control: 5, ethertype: 0x0800)
    protected_body = body.dup
    protected_body.setbyte(1, protected_body.getbyte(1) | 0x40)
    protected_frame = described_class.parse_frame(bytes: protected_body + [Zlib.crc32(protected_body)].pack('V'))
    expect(protected_frame).to include(protected: true)
    expect(protected_frame).not_to have_key(:ethertype)
  end

  def data_fragment(number, more, payload, protected_frame: false)
    fc = 0x0008 | (more ? 0x0400 : 0) | (protected_frame ? 0x4000 : 0)
    body = [fc, 0].pack('vv') + ['00112233445566778899aabbccddeeff0011'].pack('H*') + [(7 << 4) | number].pack('v') + payload
    body + [Zlib.crc32(body)].pack('V')
  end

  it 'reassembles plaintext MAC fragments through the public IQ decoder' do
    first = data_fragment(0, true, "#{['aaaa030000000800'].pack('H*')}first")
    last = data_fragment(1, false, 'second')
    iq = wifi_iq(first) + ([0.0, 0.0] * 30) + wifi_iq(last)
    raw = iq.map { |sample| ((sample * 127.5) + 127.5).round }.pack('C*')
    frames = []
    described_class.decode(source: StringIO.new(raw), interactive: false, log_file: false, output: StringIO.new,
                           on_frame: ->(frame) { frames << frame })
    complete = frames.find { |frame| frame[:reassembled] }
    expect(complete).to include(ethertype: 0x0800, network_payload_hex: 'firstsecond'.unpack1('H*'), fragments: 2)
  end

  it 'does not join missing, expired, protected or oversized MAC fragments' do
    first = described_class.parse_frame(bytes: data_fragment(0, true, 'hello'))
    last = described_class.parse_frame(bytes: data_fragment(1, false, 'world'))
    reassembler = described_class::MACReassembler.new
    expect(reassembler.feed(last, sample_time: 0)).not_to have_key(:reassembled)
    reassembler.feed(first, sample_time: 0)
    expect(reassembler.feed(last, sample_time: 2)).not_to have_key(:reassembled)
    reassembler.feed(first, sample_time: 3)
    protected_frame = described_class.parse_frame(bytes: data_fragment(1, false, 'ciphertext', protected_frame: true))
    expect(reassembler.feed(protected_frame, sample_time: 3.1)).not_to have_key(:reassembled)
    expect(reassembler.feed(last, sample_time: 3.2)).not_to have_key(:reassembled)
    reassembler.feed(first.merge(payload_hex: ('x' * 2400).unpack1('H*')), sample_time: 4)
    expect(reassembler.instance_variable_get(:@pending)).to be_empty
  end

  it 'routes public decode to DSSS and rejects unsupported modes/rates explicitly' do
    raw = wifi_iq(ack).map { |sample| ((sample * 127.5) + 127.5).round }.pack('C*')
    frames = []
    result = described_class.decode(freq_obj: {}, source: StringIO.new(raw),
                                    interactive: false, log_file: false, output: StringIO.new,
                                    on_frame: ->(frame) { frames << frame })
    expect(result[:frames]).to eq(1)
    expect(frames.first[:decoded]).to be(true)
    expect { described_class.decode(mode: :ofdm) }.to raise_error(ArgumentError, /mode/)
    expect { described_class.decode(sample_rate: 2_000_000) }.to raise_error(ArgumentError, /MHz/)
  end

  it 'rejects bad FCS, bad PLCP CRC, truncated packets and seeded noise without fake frames' do
    corrupt = ack.dup
    corrupt.setbyte(8, corrupt.getbyte(8) ^ 1)
    random = Random.new(433)
    inputs = [wifi_iq(corrupt), wifi_iq(ack, corrupt_header: true), wifi_iq(ack)[0...-22],
              Array.new(20_000) { (random.rand - 0.5) * 0.2 }]
    inputs.each do |iq|
      frames = []
      demod = described_class::DSSSIQ.new(rate: 11_000_000)
      iq.each_slice(118) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
      demod.flush { |f| frames << f }
      expect(frames).to be_empty
    end
  end

  it 'emits a decoded WiFi frame while the input pipe is still open' do
    reader, writer = IO.pipe
    frame_queue = Queue.new
    raw = wifi_iq(ack).map { |sample| ((sample * 127.5) + 127.5).round }.pack('C*')
    worker = Thread.new do
      described_class.decode(freq_obj: {}, source: reader, chunk_bytes: 318, interactive: false,
                             duration: 2, log_file: false, output: StringIO.new,
                             on_frame: ->(frame) { frame_queue << frame })
    end
    writer.write(raw)
    frame = Timeout.timeout(2) { frame_queue.pop }
    expect(writer).not_to be_closed
    expect(frame[:decoded]).to be(true)
    writer.close
    expect(worker.value[:reason]).to eq(:eof)
  ensure
    writer&.close unless writer&.closed?
    reader&.close unless reader&.closed?
    worker&.kill
    worker&.join
  end

  %i[WiFi RFID RTL433].each do |name|
    it "exposes #{name} energy detection separately" do
      mod = PWN::SDR::Decoder.const_get(name)
      raw = (([0.01] * 80) + ([1.0] * 120) + ([0.01] * 40)).flat_map { |x| [(x * 127).round + 128, 128] }.pack('C*')
      frames = []
      mod.detect(freq_obj: { freq: 433_920_000 }, source: StringIO.new(raw), sample_rate: 8000,
                 interactive: false, log_file: false, output: StringIO.new, on_frame: ->(frame) { frames << frame })
      expect(frames.length).to eq(1)
      expect(frames.first).to include(decoded: false, capability: 'detector-only')
    end
  end

  %i[WiFi RFID RTL433 Iridium].each do |name|
    it "flushes #{name}'s unfinished burst once without adding synthetic samples" do
      mod = PWN::SDR::Decoder.const_get(name)
      klass = mod.const_defined?(:DetectorIQ, false) ? mod::DetectorIQ : mod::DemodIQ
      demod = klass.new(rate: 8000, protocol: name.to_s, modulation: 'energy')
      iq = (([0.01] * 80) + ([1.0] * 120)).flat_map { |x| [x, 0.0] }
      frames = []
      demod.feed_iq(iq) { |f| frames << f }
      expect(frames).to be_empty
      2.times { demod.flush { |f| frames << f } }
      expect(frames.length).to eq(1)
      expect(frames.first).to include(duration_ms: 15, truncated: true, decoded: false)
    end

    it "measures #{name} burst duration from samples independently of chunk sizes" do
      mod = PWN::SDR::Decoder.const_get(name)
      klass = mod.const_defined?(:DetectorIQ, false) ? mod::DetectorIQ : mod::DemodIQ
      iq = (([0.01] * 80) + ([1.0] * 120) + ([0.01] * 40)).flat_map { |x| [x, 0.0] }
      results = [iq.length, 6].map do |size|
        demod = klass.new(rate: 8000, protocol: name.to_s, modulation: 'energy')
        frames = []
        iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
        frames
      end
      expect(results.first.length).to eq(1)
      expect(results.first.first[:duration_ms]).to eq(15)
      expect(results.first.first).to include(capability: 'detector-only', decoded: false)
      expect(results.last).to eq(results.first)
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::WiFi
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::WiFi
    expect(help_response).to respond_to :help
  end
end
