# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::Bluetooth do
  it 'exposes an explicitly separate detector entry point' do
    expect(described_class).to respond_to(:detect)
  end

  # Bluetooth Core 6.2, Vol 6 Part C, 4.2.1 (bits in transmission order).
  # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-62/out/en/low-energy-controller/sample-data.html
  let(:advertising_bits) do
    %w[01010101 01101011 01111101 10010001 01110001
       00101001 00110011 01000111 10100001 10111111 10111110 11000010
       01110010 01011000 11100101 00110101 11110111 11110011 10100101].join.chars.map(&:to_i)
  end

  let(:connected_bits) do
    %w[10101010 11010100 10011000 00010000 01010101
       01100011 11011001 01001010 10001100 11011011 01111101 10111001
       10110010 00101111 10011000].join.chars.map(&:to_i)
  end

  it 'decodes connected SIG codewords from synthetic GFSK IQ through the public runner' do
    phase = 0.0
    iq = (([0, 1] * 12) + connected_bits + ([0, 1] * 20)).flat_map do |bit|
      Array.new(8) do
        phase += bit == 1 ? Math::PI / 16 : -Math::PI / 16
        [(Math.cos(phase) * 100).round, (Math.sin(phase) * 100).round]
      end.flatten
    end.pack('c*')
    frames = []
    result = described_class.decode(freq_obj: { freq: 2_438_000_000 }, source: StringIO.new(iq),
                                    iq_format: :cs8, sample_rate: 8_000_000, channel: 16,
                                    access_address: 0xAA08192B, crc_init: 0xC4C181, encrypted: false,
                                    chunk_bytes: 137, interactive: false, output: StringIO.new, log_file: false,
                                    on_frame: ->(frame) { frames << frame })
    expect(result[:reason]).to eq(:eof)
    expect(frames.length).to eq(1)
    expect(frames.first).to include(payload_hex: '0102030405', pdu_type: 'LL_DATA', crc_ok: true)
  end

  it 'decodes the SIG connected data vector with caller supplied connection context' do
    bits = %w[10101010 11010100 10011000 00010000 01010101
              01100011 11011001 01001010 10001100 11011011 01111101 10111001
              10110010 00101111 10011000].join.chars.map(&:to_i)
    demod = described_class::DemodIQ.new(rate: 8_000_000, channel: 16,
                                         access_address: 0xAA08192B, crc_init: 0xC4C181, encrypted: false)
    frames = []
    bits.each_slice(11) { |chunk| demod.feed_bits(chunk) { |f| frames << f } }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(pdu_type: 'LL_DATA', llid: 2, nesn: 1, sn: 0, md: 1,
                                    payload_hex: '0102030405', crc_ok: true, encrypted: false)
  end

  it 'decodes the SIG AUX_ADV_IND header and payload on a secondary channel' do
    bits = %w[01010101 01101011 01111101 10010001 01110001
              00011100 01111110 01111011 11101111 00100101 00000010 10101001
              01111001 10010100 00100000 11101100 11000110 01101001 11101101
              11011101 01010011 00101000 01011100 01001001 00111110 11010100].join.chars.map(&:to_i)
    frames = []
    demod = described_class::DemodIQ.new(rate: 8_000_000, channel: 7, extended: true)
    # SIG 6.2 section 4.2.2 prints CRC D8 23 AE, which does not match
    # its PDU. Reject that verbatim vector. Independently calculated MSB
    # polynomial 0x65B yields on-air A6 8B C4; whitened tail EC D4 41.
    demod.feed_bits(bits) { |f| frames << f }
    expect(frames).to be_empty
    bits[-24, 24] = %w[00110111 00101011 10000010].join.chars.map(&:to_i)
    bits.each_slice(13) { |chunk| demod.feed_bits(chunk) { |f| frames << f } }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(pdu_type: 'AUX_ADV_IND', adv_addr: 'A9:AA:AB:AC:AD:AE',
                                    advertising_sid: 14, advertising_did: 0xABC, tx_power: -42,
                                    adv_mode: 1, advertising_data_hex: '0507090B0D', crc_ok: true)
    broken = bits.dup
    broken[-1] ^= 1
    demod.feed_bits(broken) { |f| frames << f }
    expect(frames.length).to eq(1)
  end

  it 'forwards connected context and refuses to infer encryption from RF payload bytes' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq) do |opts|
      frames = []
      bits = %w[10101010 11010100 10011000 00010000 01010101
                01100011 11011001 01001010 10001100 11011011 01111101 10111001
                10110010 00101111 10011000].join.chars.map(&:to_i)
      opts[:demod].feed_bits(bits) { |f| frames << f }
      expect(frames.first).to include(encrypted: true, payload_hex: nil, ciphertext_hex: '0102030405')
    end
    described_class.decode(freq_obj: { freq: 2_438_000_000 }, source: StringIO.new,
                           channel: 16, access_address: 0xAA08192B, crc_init: 0xC4C181, encrypted: true)
    expect { described_class::DemodIQ.new(rate: 8_000_000, channel: 16, access_address: 0xAA08192B) }.to raise_error(ArgumentError, /crc_init/)
  end

  it 'decodes the independent SIG LL_CHANNEL_MAP_IND including CTE header' do
    bits = %w[01010101 01000010 00111100 11101000 01010101
              01110010 10011100 00101001 10010010 10110010 00010001 11100000
              00111000 11100010 00010011 00010111 10010111 00111110 11100011
              11111111 11111111 11111111 11111111 11111111].join.chars.map(&:to_i)
    frames = []
    demod = described_class::DemodIQ.new(rate: 8_000_000, channel: 29,
                                         access_address: 0xAA173C42, crc_init: 0xCD3F6C, encrypted: false)
    bits.each_slice(13) { |chunk| demod.feed_bits(chunk) { |f| frames << f } }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(pdu_type: 'LL_CONTROL', control_opcode: 1, channel_map_hex: 'DBFFFFFF01',
                                    instant: 0x4321, cte_info: 0x85, header_length: 3, crc_ok: true)
  end

  it 'matches the Bluetooth SIG CRC vector rather than a self-generated checksum' do
    expect(described_class.ble_crc24(bytes: [0x42, 9, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xC1, 1, 2, 3])).to eq(0xEBB4AD)
  end

  it 'decodes the independent whitened SIG vector over actual streaming IQ before EOF' do
    require 'timeout'
    reader, writer = IO.pipe
    observed = Queue.new
    phase = 0.0
    iq = (([0, 1] * 12) + advertising_bits + ([0, 1] * 20)).flat_map do |bit|
      Array.new(8) do
        phase += bit == 1 ? Math::PI / 16 : -Math::PI / 16
        [(Math.cos(phase) * 100).round, (Math.sin(phase) * 100).round]
      end.flatten
    end.pack('c*')
    worker = Thread.new do
      described_class.decode(freq_obj: { freq: 2_426_000_000 }, source: reader,
                             iq_format: :cs8, sample_rate: 8_000_000, channel: 38,
                             interactive: false, output: StringIO.new, log_file: false,
                             on_frame: ->(frame) { observed << frame })
    end
    iq.bytes.each_slice(137) { |part| writer.write(part.pack('C*')) }
    frame = Timeout.timeout(3) { observed.pop }
    expect(writer).not_to be_closed
    expect(frame).to include(decoded: true, crc_ok: true, pdu_type: 'ADV_NONCONN_IND',
                             adv_addr: 'C1:A2:A3:A4:A5:A6', advertising_data_hex: '010203')
    writer.close
    expect(Timeout.timeout(3) { worker.value }[:reason]).to eq(:eof)
  ensure
    writer&.close unless writer&.closed?
    worker&.kill
    worker&.join
    reader&.close unless reader&.closed?
  end

  it 'keeps GFSK symbol decisions stable across single-sample IQ chunks' do
    rate = 4_000_000
    phase = 0.0
    bits = Array.new(300) { |i| (i / 3).even? ? 1 : 0 }
    iq = bits.flat_map do |bit|
      Array.new(4) do
        phase += bit == 1 ? 0.3 : -0.3
        [Math.cos(phase), Math.sin(phase)]
      end.flatten
    end
    results = [iq.length, 2].map do |size|
      slicer = described_class::SymbolStream.new(rate: rate, baud: 1_000_000)
      iq.each_slice(size).flat_map { |chunk| slicer.feed_iq(chunk) }
    end
    expect(results.first.length).to be > 250
    expect(results.last).to eq(results.first)
  end

  it 'retains a partial advertising PDU until its body arrives' do
    dsp = PWN::SDR::Decoder::DSP
    payload = [0, 20] + (1..20).to_a
    crc = described_class.ble_crc24(bytes: payload)
    reg = 37 | 0x40
    bytes = (payload + [crc & 255, (crc >> 8) & 255, (crc >> 16) & 255]).map do |byte|
      8.times do |i|
        bit = reg & 1
        byte ^= bit << i
        reg = (reg >> 1) ^ (bit == 1 ? 0x44 : 0)
      end
      byte
    end
    bits = Array.new(32) { |i| (described_class::BLE_ADV_AA >> i) & 1 } + bytes.flat_map { |b| Array.new(8) { |i| (b >> i) & 1 } }
    # Isolate framing from the GFSK slicer with offline bit fixtures.
    slicer = instance_double(PWN::SDR::Decoder::Bluetooth::SymbolStream)
    allow(PWN::SDR::Decoder::Bluetooth::SymbolStream).to receive(:new).and_return(slicer)
    allow(slicer).to receive(:feed_iq) { |chunk| chunk }
    demod = described_class::DemodIQ.new(rate: 4_000_000)
    frames = []
    demod.feed_iq(bits[0, 120]) { |f| frames << f }
    expect(frames).to be_empty
    demod.feed_iq(bits[120..]) { |f| frames << f }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(length: 20, crc_ok: true)
  end

  it 'rejects corruption and truncation without suppressing repeated valid packets' do
    demod = described_class::DemodIQ.new(rate: 8_000_000, channel: 38)
    frames = []
    bad = advertising_bits.dup
    bad[-5] ^= 1
    demod.feed_bits(bad) { |frame| frames << frame }
    expect(frames).to be_empty
    demod.feed_bits(advertising_bits[0, 80]) { |frame| frames << frame }
    expect(frames).to be_empty
    demod.feed_bits(advertising_bits[80..]) { |frame| frames << frame }
    demod.feed_bits(advertising_bits) { |frame| frames << frame }
    expect(frames.length).to eq(2)
    noise = Random.new(124).bytes(1024).unpack('B*').join.chars.map(&:to_i)
    demod.feed_bits(noise) { |frame| frames << frame }
    expect(frames.length).to eq(2)
  end

  it 'rejects invalid connected channel/context before opening RF sources' do
    expect(PWN::SDR::Decoder::Base).not_to receive(:run_iq)
    expect do
      described_class.decode(freq_obj: { freq: 2_402_000_000 }, access_address: 0xAA08192B,
                             crc_init: 0xC4C181, encrypted: false, channel: 37)
    end.to raise_error(ArgumentError, /connected channel/)
  end

  it 'rejects unsupported PHY and BR/EDR before opening a source' do
    expect { described_class::DemodIQ.new(rate: 4_000_000, ble: false) }.to raise_error(ArgumentError, %r{BR/EDR})
    expect { described_class.decode(freq_obj: { freq: 2_402_000_000 }, phy: :coded) }.to raise_error(ArgumentError, /1M/)
    expect { described_class::DemodIQ.new(rate: 4_000_000, channel: 2) }.to raise_error(ArgumentError, /37/)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::Bluetooth
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::Bluetooth
    expect(help_response).to respond_to :help
  end
end
