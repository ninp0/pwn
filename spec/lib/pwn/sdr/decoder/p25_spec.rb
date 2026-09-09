# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::P25 do
  it 'exposes an explicitly separate detector entry point' do
    expect(described_class).to respond_to(:detect)
  end

  it 'preserves FM and symbol input windows across transport chunks' do
    dsp = PWN::SDR::Decoder::DSP
    iq = Array.new(600) { |i| [Math.cos(i * 0.2), Math.sin(i * 0.2)] }.flatten
    results = [iq.length, 2].map do |size|
      windows = []
      allow(dsp).to receive(:slice_4fsk) do |opts|
        windows << opts[:samples].dup
        []
      end
      demod = described_class::DemodIQ.new(rate: 48_000)
      iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |_f| nil } }
      windows
    end
    expect(results.first).not_to be_empty
    expect(results.last).to eq(results.first)
  end

  it 'labels unchecked NID extraction instead of claiming decoded voice or data' do
    demod = described_class::DemodIQ.new(rate: 48_000)
    demod.instance_variable_set(:@dibits, described_class::FS_SYMS + Array.new(32, 0))
    frames = []
    demod.send(:scan) { |f| frames << f }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(capability: 'nid-only', decoded: false, checksum_verified: false)
  end

  # Offline encoder follows the published p25craft generator matrix and TIA
  # rate-1/2 constellation/interleaver, independently of the receiver below.
  # https://github.com/boatbod/op25/blob/master/op25/gr-op25_repeater/apps/tx/p25craft.py
  def tsbk_dibits(protected: false, last: true)
    block = [(protected ? 0x40 : 0) | (last ? 0x80 : 0), 0, 0, 0x10, 1, 0x23, 0x45, 0x67, 0x89, 0xAB]
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: block, init: 0, xorout: 0xFFFF)
    block += [crc >> 8, crc & 255]
    words = [[2, 12, 1, 15], [14, 0, 13, 3], [9, 7, 10, 4], [5, 11, 6, 8]]
    input = block.pack('C*').unpack1('B*').scan(/../).map { |s| s.to_i(2) } + [0]
    state = 0
    coded = input.flat_map do |value|
      word = words[state][value]
      state = value
      [word >> 2, word & 3]
    end
    air = (0..96).step(8).flat_map { |j| coded[j, 2] }
    [2, 4, 6].each { |i| (0..88).step(8) { |j| air.concat(coded[i + j, 2]) } }
    # NAC 0x293, DUID 7. BCH codeword independently calculated from p25craft.
    nid = 0x2937F88514ABAECC
    data = described_class::FS_SYMS + Array.new(32) { |i| (nid >> (62 - (i * 2))) & 3 } + air
    data.each_slice(35).flat_map { |part| part.length == 35 ? part + [1] : part }
  end

  it 'decodes all three independently checked blocks in one TSDU across chunk boundaries' do
    strip = ->(air) { air.each_with_index.reject { |_, i| i % 36 == 35 }.map(&:first) }
    data = strip.call(tsbk_dibits(last: false)) + strip.call(tsbk_dibits(last: false)).drop(56) + strip.call(tsbk_dibits).drop(56)
    air = data.each_slice(35).flat_map { |part| part.length == 35 ? part + [1] : part }
    receiver = described_class::PacketIQ.new(rate: 48_000)
    frames = []
    air.each_slice(11) { |chunk| receiver.feed_dibits(chunk) { |frame| frames << frame } }
    expect(frames.length).to eq(3)
    expect(frames.map { |f| f[:last_block] }).to eq([false, false, true])
    expect(frames.map { |f| f[:block_index] }).to eq([0, 1, 2])
    expect(frames).to all(include(crc_ok: true, talkgroup: 0x2345))
  end

  it 'replays an independent op25 three-block binary fixture' do
    bytes = File.binread(File.expand_path('../../../../fixtures/sdr/p25/tsdu3.bin', __dir__))
    dibits = bytes.bytes.flat_map { |byte| [6, 4, 2, 0].map { |shift| (byte >> shift) & 3 } }
    frames = []
    receiver = described_class::PacketIQ.new(rate: 48_000)
    dibits.each_slice(19) { |chunk| receiver.feed_dibits(chunk) { |frame| frames << frame } }
    expect(frames.map { |frame| frame[:raw_hex] }).to eq(%w[000000100123456789AB02E1 000000100123456789AB02E1 800000100123456789ABE6D5])
  end

  it 'decodes an independent op25 unconfirmed PDU with header and packet CRCs' do
    bytes = File.binread(File.expand_path('../../../../fixtures/sdr/p25/updu.bin', __dir__))
    dibits = bytes.bytes.flat_map { |byte| [6, 4, 2, 0].map { |shift| (byte >> shift) & 3 } }
    frames = []
    receiver = described_class::PacketIQ.new(rate: 48_000, mode: :pdu)
    dibits.each_slice(17) { |chunk| receiver.feed_dibits(chunk) { |frame| frames << frame } }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(event: 'pdu', duid: 12, format: 0x15, sap: 4, llid: 1,
                                    blocks: 2, pad_octets: 7, payload_hex: '0102030405060708090A0B0C0D',
                                    packet_crc_ok: true, header_crc_ok: true, encrypted: false)
    receiver = described_class::PacketIQ.new(rate: 48_000, mode: :pdu)
    frames = []
    receiver.feed_dibits(dibits.first(200)) { |frame| frames << frame }
    expect(frames).to be_empty
  end

  it 'decodes a complete status-interleaved TSBK rather than emitting an unchecked NID' do
    receiver = described_class::PacketIQ.new(rate: 48_000)
    frames = []
    bits = tsbk_dibits
    bits.each_slice(7) { |chunk| receiver.feed_dibits(chunk) { |frame| frames << frame } }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(decoded: true, crc_ok: true, nac: '293', duid: 7,
                                    opcode: 0, manufacturer_id: 0, payload_hex: '00100123456789AB')
  end

  it 'decodes C4FM IQ through the public streaming entry point before EOF' do
    require 'timeout'
    reader, writer = IO.pipe
    queue = Queue.new
    phase = 0.0
    fixture = File.binread(File.expand_path('../../../../fixtures/sdr/p25/updu.bin', __dir__))
    dibits = fixture.bytes.flat_map { |byte| [6, 4, 2, 0].map { |shift| (byte >> shift) & 3 } }
    samples = (([0, 1, 2, 3] * 8) + dibits + ([0, 1] * 10)).flat_map do |d|
      hz = [600, 1800, -600, -1800][d]
      Array.new(10) do
        phase += 2 * Math::PI * hz / 48_000
        [(Math.cos(phase) * 120).round, (Math.sin(phase) * 120).round]
      end.flatten
    end.pack('c*')
    worker = Thread.new do
      described_class.decode(freq_obj: { freq: 851_000_000 }, source: reader, iq_format: :cs8, mode: :pdu,
                             sample_rate: 48_000, interactive: false, output: StringIO.new,
                             log_file: false, on_frame: ->(f) { queue << f })
    end
    samples.bytes.each_slice(131) { |b| writer.write(b.pack('C*')) }
    expect(Timeout.timeout(3) { queue.pop }).to include(event: 'pdu', decoded: true, packet_crc_ok: true,
                                                        payload_hex: '0102030405060708090A0B0C0D')
    expect(writer).not_to be_closed
    writer.close
    expect(Timeout.timeout(3) { worker.value }[:reason]).to eq(:eof)
  ensure
    writer&.close unless writer&.closed?
    worker&.kill
    worker&.join
    reader&.close unless reader&.closed?
  end

  it 'corrects a trellis error but rejects bad NID, damaged block, noise and truncation' do
    packet = tsbk_dibits
    receiver = described_class::PacketIQ.new(rate: 48_000)
    frames = []
    corrupt = packet.dup
    corrupt[28] ^= 1
    receiver.feed_dibits(corrupt) { |f| frames << f }
    broken = packet.dup
    (65..105).each { |i| broken[i] ^= 3 }
    receiver.feed_dibits(broken) { |f| frames << f }
    receiver.feed_dibits(Random.new(25).bytes(600).bytes.map { |v| v & 3 }) { |f| frames << f }
    receiver.feed_dibits(packet.first(110)) { |f| frames << f }
    expect(frames).to be_empty
    receiver.feed_dibits(packet.drop(110)) { |f| frames << f }
    expect(frames.length).to eq(1)
    corrected = packet.dup
    corrected[65] ^= 1
    receiver.feed_dibits(corrected) { |f| frames << f }
    expect(frames.last).to include(fec_corrected_bits: 1, crc_ok: true)
    expect(frames.length).to eq(2)
  end

  it 'parses standard group grants but never interprets protected payload as grant fields' do
    receiver = described_class::PacketIQ.new(rate: 48_000)
    frames = []
    receiver.feed_dibits(tsbk_dibits) { |f| frames << f }
    expect(frames.first).to include(channel_id: 1, channel_number: 1, talkgroup: 0x2345, source_id: 0x6789AB)
    receiver.feed_dibits(tsbk_dibits(protected: true)) { |f| frames << f }
    expect(frames.last).to include(encrypted: true, payload_hex: nil, ciphertext_hex: '00100123456789AB')
    expect(frames.last).not_to have_key(:talkgroup)
  end

  it 'rejects unsupported modulation and voice requests before opening sources' do
    expect { described_class.decode(source: StringIO.new, interactive: false, log_file: false, freq_obj: { freq: 851_000_000 }, mode: :voice) }.to raise_error(ArgumentError, /tsbk/)
    expect { described_class.decode(source: StringIO.new, interactive: false, log_file: false, freq_obj: { freq: 851_000_000 }, phase: 2) }.to raise_error(ArgumentError, /Phase 1/)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::P25
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::P25
    expect(help_response).to respond_to :help
  end
end
