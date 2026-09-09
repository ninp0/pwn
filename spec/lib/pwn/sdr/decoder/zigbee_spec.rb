# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::ZigBee do
  it 'parses version-2 NWK and unicast APS fields without inventing application data' do
    # Field layout independently specified in Scapy zigbee.py ZigbeeNWK/AppDataPayload.
    bytes = ['08007856BC9A1E2A0001060004010242010100'].pack('H*').bytes
    expect(described_class.parse_nwk(bytes: bytes)).to include(
      destination: '5678', source: '9ABC', radius: 30, sequence: 42,
      aps: include(destination_endpoint: 1, source_endpoint: 2, cluster_id: '0006',
                   profile_id: '0104', counter: 66, payload_hex: '010100')
    )
    expect(described_class.parse_nwk(bytes: bytes[0, 10])).to be_nil
  end

  it 'authenticates RFC 3610 packet vector 1 and rejects altered MICs' do
    args = { key: ['C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF'].pack('H*'),
             nonce: ['00000003020100A0A1A2A3A4A5'].pack('H*'),
             aad: (0..7).to_a.pack('C*'),
             ciphertext: ['588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384'].pack('H*'),
             mic: ['17E8D12CFDF926E0'].pack('H*') }
    expect(described_class.decrypt_ccm(args)).to eq((8..30).to_a.pack('C*'))
    expect(described_class.decrypt_ccm(args.merge(mic: "\x00" * 8))).to be_nil
  end

  it 'authenticates NWK security with a supplied key and keeps missing-key data ciphertext' do
    # Independently generated with cryptography AESCCM, 128-bit key 00..0f, MIC32.
    bytes = ['08027856bc9a1e2a2d0100000008070605040302010060d57939f38362f77fae159cf9d44d'].pack('H*').bytes
    key = (0..15).to_a.pack('C*')
    expect(described_class.parse_nwk(bytes: bytes)).to include(payload_hex: nil, authentication_verified: false,
                                                               ciphertext_hex: '60D57939F38362F77FAE15')
    expect(described_class.parse_nwk(bytes: bytes, network_keys: { 0 => key })).to include(
      authentication_verified: true, aps: include(payload_hex: '010100')
    )
    bytes[-1] ^= 1
    expect(described_class.parse_nwk(bytes: bytes, network_keys: { 0 => key })).to be_nil
    # Empty secured NWK data cannot contain the mandatory APS header.
    empty = bytes[0, 22] + [0, 0, 0, 0]
    expect(described_class.parse_nwk(bytes: empty, network_keys: { 0 => key })).to be_nil
  end

  it 'authenticates APS data-key frames independently of NWK integrity' do
    bytes = ['200106000401024225010000000807060504030201747c3cb8adb84c'].pack('H*').bytes
    expect(described_class.parse_aps(bytes: bytes, link_key: (0..15).to_a.pack('C*'))).to include(
      authentication_verified: true, payload_hex: '010100'
    )
    bytes[-1] ^= 1
    expect(described_class.parse_aps(bytes: bytes, link_key: (0..15).to_a.pack('C*'))).to be_nil
  end

  it 'does not claim APS decoding for unauthenticated ciphertext or invalid upper layers' do
    data = ['08027856bc9a1e2a2d0100000008070605040302010060d57939f38362f77fae159cf9d44d'].pack('H*').bytes
    mac = [0x41, 0x88, 42, 0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A] + data
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: mac, init: 0, refin: true, refout: true)
    expect(described_class.parse_mpdu(bytes: mac + [crc & 255, crc >> 8])).to include(capability: 'zigbee-nwk-secured')
    data[-1] ^= 1
    mac = mac[0, 9] + data
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: mac, init: 0, refin: true, refout: true)
    frame = described_class.parse_mpdu(bytes: mac + [crc & 255, crc >> 8], network_keys: { 0 => (0..15).to_a.pack('C*') })
    expect(frame).to include(nwk: nil, nwk_status: 'invalid-or-unsupported', capability: '802.15.4-2003/2006-mac')
  end

  it 'exposes an explicitly separate detector entry point' do
    expect(described_class).to respond_to(:detect)
  end

  it 'retains the SHR and PHR across a partial MPDU' do
    dsp = PWN::SDR::Decoder::DSP
    body = [2, 0, 42]
    crc = dsp.crc16(bytes: body, poly: 0x1021, init: 0, refin: true, refout: true)
    body += [crc & 255, crc >> 8]
    bytes = [0, 0, 0, 0, 0xA7, body.length] + body
    chips = bytes.flat_map { |b| [b & 15, b >> 4].flat_map { |n| described_class::PN_CHIPS[n] } }
    demod = described_class::DemodIQ.new(rate: 4_000_000)
    frames = []
    demod.feed_chips(chips[0, 400]) { |f| frames << f }
    expect(frames).to be_empty
    demod.feed_chips(chips[400..]) { |f| frames << f }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(seq: 42, fcs_ok: true)
  end

  it 'extracts MAC payload and source PAN and rejects corrupt or unsupported frames' do
    # IEEE 802.15.4-2006 MHR, short source/destination with PAN compression.
    bytes = [0x41, 0x88, 7, 0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A, 1, 2, 3]
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: bytes, poly: 0x1021, init: 0, refin: true, refout: true)
    packet = bytes + [crc & 255, crc >> 8]
    frame = described_class.parse_mpdu(bytes: packet)
    expect(frame).to include(decoded: true, fcs_ok: true, pan_id: '1234', src_pan_id: '1234',
                             src: '9ABC', dst: '5678', payload_hex: '010203')
    packet[-1] ^= 1
    expect(described_class.parse_mpdu(bytes: packet)).to be_nil
    expect(described_class.parse_mpdu(bytes: [2, 0])).to be_nil
  end

  it 'keeps encrypted MAC data opaque and does not claim MIC verification' do
    bytes = [0x49, 0x98, 7, 0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A,
             5, 1, 0, 0, 0, 0xAB, 0xCD, 1, 2, 3, 4]
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: bytes, poly: 0x1021, init: 0, refin: true, refout: true)
    frame = described_class.parse_mpdu(bytes: bytes + [crc & 255, crc >> 8])
    expect(frame).to include(encrypted: true, payload_hex: nil, ciphertext_hex: 'ABCD',
                             mic_hex: '01020304', authentication_verified: false, security_level: 5)
  end

  it 'decodes actual half-sine O-QPSK IQ across odd byte chunks before EOF' do
    require 'timeout'
    # IEEE 802.15.4-2006 Table 24, c0 is the LEFTMOST chip.
    pn = %w[D9C3522E ED9C3522 2ED9C352 22ED9C35 522ED9C3 3522ED9C C3522ED9 9C3522ED
            8C96077B B8C96077 7B8C9607 77B8C960 077B8C96 6077B8C9 96077B8C C96077B8]
    body = [0x41, 0x88, 42, 0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A] +
           ['08027856bc9a1e2a2d0100000008070605040302010060d57939f38362f77fae159cf9d44d'].pack('H*').bytes
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: body, init: 0, refin: true, refout: true)
    bytes = [0, 0, 0, 0, 0xA7, body.length + 2] + body + [crc & 255, crc >> 8]
    bad = body.dup
    bad[-1] ^= 1
    bad_crc = PWN::SDR::Decoder::DSP.crc16(bytes: bad, init: 0, refin: true, refout: true)
    bytes = [0, 0, 0, 0, 0xA7, bad.length + 2] + bad + [bad_crc & 255, bad_crc >> 8] + bytes
    chips = bytes.flat_map { |b| [b & 15, b >> 4].flat_map { |n| pn[n].to_i(16).to_s(2).rjust(32, '0').chars.map(&:to_i) } }
    iq = Array.new((chips.length + 2) * 4) do |t|
      i_idx = (t / 8) * 2
      q_idx = (((t - 4) / 8) * 2) + 1
      i = i_idx < chips.length ? ((chips[i_idx] * 2) - 1) * Math.sin(Math::PI * (t % 8) / 8) : 0
      q = q_idx >= 0 && q_idx < chips.length ? ((chips[q_idx] * 2) - 1) * Math.sin(Math::PI * ((t - 4) % 8) / 8) : 0
      [(i * 120).round, (q * 120).round]
    end.flatten.pack('c*')
    reader, writer = IO.pipe
    queue = Queue.new
    worker = Thread.new do
      described_class.decode(freq_obj: { freq: 2_405_000_000 }, sample_rate: 8_000_000,
                             network_keys: { 0 => (0..15).to_a.pack('C*') },
                             source: reader, iq_format: :cs8, interactive: false, output: StringIO.new,
                             log_file: false, on_frame: ->(frame) { queue << frame })
    end
    iq.bytes.each_slice(137) { |b| writer.write(b.pack('C*')) }
    expect(Timeout.timeout(3) { queue.pop }).to include(nwk: nil, nwk_status: 'invalid-or-unsupported', fcs_ok: true)
    expect(Timeout.timeout(3) { queue.pop }).to include(seq: 42, decoded: true, fcs_ok: true,
                                                        nwk: include(authentication_verified: true,
                                                                     aps: include(payload_hex: '010100')))
    expect(writer).not_to be_closed
    writer.close
    expect(Timeout.timeout(3) { worker.value }[:reason]).to eq(:eof)
  ensure
    writer&.close unless writer&.closed?
    worker&.kill
    worker&.join
    reader&.close unless reader&.closed?
  end

  it 'rejects reserved PHR bits, bad SHR and noise, while preserving repeated valid MPDUs' do
    body = [0x41, 0x88, 42, 0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A] +
           ['08027856bc9a1e2a2d0100000008070605040302010060d57939f38362f77fae159cf9d44d'].pack('H*').bytes
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: body, init: 0, refin: true, refout: true)
    bytes = [0, 0, 0, 0, 0xA7, body.length + 2] + body + [crc & 255, crc >> 8]
    chips_for = ->(data) { data.flat_map { |b| [b & 15, b >> 4].flat_map { |n| described_class::PN_CHIPS[n] } } }
    receiver = described_class::DemodIQ.new(rate: 8_000_000)
    frames = []
    invalid = bytes.dup
    invalid[5] |= 0x80
    receiver.feed_chips(chips_for.call(invalid)) { |f| frames << f }
    invalid = bytes.dup
    invalid[3] = 0xFF
    receiver.feed_chips(chips_for.call(invalid)) { |f| frames << f }
    receiver.feed_chips(Random.new(42).bytes(400).bytes.map { |b| b & 1 }) { |f| frames << f }
    expect(frames).to be_empty
    receiver.feed_chips(chips_for.call(bytes)) { |f| frames << f }
    receiver.feed_chips(chips_for.call(bytes)) { |f| frames << f }
    expect(frames.length).to eq(2)
  end

  it 'rejects non-O-QPSK PHY requests before opening sources' do
    expect { described_class.decode(source: StringIO.new, interactive: false, log_file: false, freq_obj: { freq: 2_405_000_000 }, phy: :bpsk) }.to raise_error(ArgumentError, /O-QPSK/)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::ZigBee
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::ZigBee
    expect(help_response).to respond_to :help
  end
end
