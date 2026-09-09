# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::DECT do
  it 'descrambles the ETSI register sequence and validates protected subfields' do
    # EN 300 175-3 figure 6.14: Q1/Q4 feedback, inverted Q4 output.
    q = [0, 0, 0, 1, 1]
    invert = 1
    sequence = Array.new(320) do
      bit = q[4] ^ invert
      invert ^= 1 if q.all?(1)
      q = [q[1] ^ q[4]] + q[0, 4]
      bit
    end
    # Zero data has R-CRC 0001 (section 6.2.5.2).
    plain = (([0] * 79) + [1]) * 4
    body = plain.zip(sequence).map { |a, b| a ^ b }
    result = described_class.parse_b_field(bits: body, frame_number: 0, encrypted: false, b_format: :multisubfield)
    expect(result).to include(payload_hex: '00' * 32, b_crc_ok: true, payload_state: 'clear')
    body[0] ^= 1
    expect(described_class.parse_b_field(bits: body, frame_number: 0, encrypted: false, b_format: :multisubfield)).to be_nil
  end

  it 'streams descrambled P32 protected payload from IQ before EOF' do
    require 'timeout'
    # Independent bit-register reference, EN 300 175-3 figure 6.14, frame 0.
    body = ['3bcd215d8865bd44ef3585762196f513bcd215d9865bd44ef3485762196e513bcd215d8865bd44ee'].pack('H*').unpack1('B*').chars.map(&:to_i)
    selected = (0...80).map { |n| body[n + (48 * (1 + (n / 16)))] }
    xcrc = selected.each_slice(4).map { |b| b.join.to_i(2) }.reduce(:^)
    header = [0x64, 1, 2, 3, 4, 5]
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: header, poly: 0x0589, init: 0) ^ 1
    bits = ['AAAAE98A'].pack('H*').unpack1('B*').chars.map(&:to_i)
    bits += (header + [crc >> 8, crc & 255]).pack('C*').unpack1('B*').chars.map(&:to_i)
    bits += body + xcrc.to_s(2).rjust(4, '0').chars.map(&:to_i)
    damaged = bits.dup
    damaged[96] ^= 1 # not selected by X-CRC: only protected B-subfield CRC rejects it
    bits = damaged + ([0, 1] * 12) + bits
    phase = 0.0
    iq = (([0, 1] * 16) + bits + ([0, 1] * 12)).flat_map do |bit|
      Array.new(4) do
        phase += bit == 1 ? 0.4 : -0.4
        [(Math.cos(phase) * 120).round, (Math.sin(phase) * 120).round]
      end.flatten
    end.pack('c*')
    reader, writer = IO.pipe
    frames = Queue.new
    worker = Thread.new do
      described_class.decode(freq_obj: { freq: 1_897_344_000 }, packet: :p32, sample_rate: 4_608_000,
                             frame_number: 0, b_format: :multisubfield, encrypted: false,
                             source: reader, iq_format: :cs8, interactive: false, output: StringIO.new,
                             log_file: false, on_frame: ->(f) { frames << f })
    end
    iq.bytes.each_slice(73) { |b| writer.write(b.pack('C*')) }
    expect(Timeout.timeout(3) { frames.pop }).to include(payload_hex: '00' * 32, b_crc_ok: true)
    expect(writer).not_to be_closed
    writer.close
    expect(Timeout.timeout(3) { worker.value }[:reason]).to eq(:eof)
  ensure
    writer&.close unless writer&.closed?
    worker&.kill
    worker&.join
    reader&.close unless reader&.closed?
  end

  it 'exposes an explicitly separate detector entry point' do
    expect(described_class).to respond_to(:detect)
  end

  it 'keeps polarity streams separate when an A-field spans chunks' do
    dsp = PWN::SDR::Decoder::DSP
    header = [0x40, 1, 2, 3, 4, 5]
    crc = dsp.crc16(bytes: header, poly: described_class::RCRC_POLY, init: 0) ^ 1
    bits = [described_class::SYNC_FP].pack('N').bytes.flat_map { |b| b.to_s(2).rjust(8, '0').chars.map(&:to_i) }
    bits += (header + [crc >> 8, crc & 255]).flat_map { |b| b.to_s(2).rjust(8, '0').chars.map(&:to_i) }
    slicer = instance_double(PWN::SDR::Decoder::Bluetooth::SymbolStream)
    allow(PWN::SDR::Decoder::Bluetooth::SymbolStream).to receive(:new).and_return(slicer)
    allow(slicer).to receive(:feed_iq) { |chunk| chunk }
    # Old path exposes the polarity carry corruption independently too.
    allow(dsp).to receive(:gfsk_slice) { |opts| opts[:invert] ? opts[:iq].map { |b| b ^ 1 } : opts[:iq] }
    demod = described_class::DemodIQ.new(rate: 2_304_000)
    frames = []
    bits.each_slice(40) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
    expect(frames.select { |f| f[:crc_ok] }.map { |f| f[:rfpi] }).to include('0102030405')
  end

  it 'requires a complete P32 B-field and validates the selected-bit X CRC' do
    dsp = PWN::SDR::Decoder::DSP
    header = [0x60, 1, 2, 3, 4, 5]
    crc = dsp.crc16(bytes: header, poly: 0x0589, init: 0) ^ 1
    a = (header + [crc >> 8, crc & 255]).pack('C*').unpack1('B*').chars.map(&:to_i)
    sync = [described_class::SYNC_FP].pack('N').unpack1('B*').chars.map(&:to_i)
    # All-zero scrambled B-field has zero X CRC, directly from x^4+1.
    bits = sync + a + Array.new(324, 0)
    demod = described_class::DemodIQ.new(rate: 4_608_000, packet: :p32, encrypted: true)
    frames = []
    bits.each_slice(23) { |part| demod.feed_bits(part) { |frame| frames << frame } }
    expect(frames.length).to eq(1)
    expect(frames.first).to include(event: 'p32', decoded: true, crc_ok: true, xcrc_ok: true,
                                    encrypted: true, payload_hex: nil, payload_state: 'scrambled-encrypted',
                                    scrambled_payload_hex: '00' * 40)
    damaged = bits.dup
    damaged[-1] ^= 1
    demod.feed_bits(damaged) { |frame| frames << frame }
    expect(frames.length).to eq(1)
  end

  it 'decodes P00 control packets from real streaming IQ before EOF' do
    require 'timeout'
    header = [0x6E, 1, 2, 3, 4, 5]
    crc = PWN::SDR::Decoder::DSP.crc16(bytes: header, poly: 0x0589, init: 0) ^ 1
    bits = [described_class::SYNC_FP].pack('N').unpack1('B*').chars.map(&:to_i)
    bits += (header + [crc >> 8, crc & 255]).pack('C*').unpack1('B*').chars.map(&:to_i)
    phase = 0.0
    iq = (([0, 1] * 16) + bits + ([0, 1] * 12)).flat_map do |bit|
      Array.new(4) do
        phase += bit == 1 ? 0.4 : -0.4
        [(Math.cos(phase) * 120).round, (Math.sin(phase) * 120).round]
      end.flatten
    end.pack('c*')
    reader, writer = IO.pipe
    frames = Queue.new
    worker = Thread.new do
      described_class.decode(freq_obj: { freq: 1_897_344_000 }, packet: :p00, sample_rate: 4_608_000,
                             source: reader, iq_format: :cs8, interactive: false, output: StringIO.new,
                             log_file: false, on_frame: ->(f) { frames << f })
    end
    iq.bytes.each_slice(73) { |b| writer.write(b.pack('C*')) }
    expect(Timeout.timeout(3) { frames.pop }).to include(event: 'p00', decoded: true, crc_ok: true, rfpi: '0102030405')
    writer.close
    expect(Timeout.timeout(3) { worker.value }[:reason]).to eq(:eof)
  ensure
    writer&.close unless writer&.closed?
    worker&.kill
    worker&.join
    reader&.close unless reader&.closed?
  end

  it 'rejects acquisition-only and unimplemented slot formats in decode' do
    expect { described_class.decode(source: StringIO.new, interactive: false, log_file: false, freq_obj: { freq: 1_897_344_000 }, packet: :a_field) }.to raise_error(ArgumentError, /p00/)
    expect { described_class.decode(source: StringIO.new, interactive: false, log_file: false, freq_obj: { freq: 1_897_344_000 }, packet: :p80) }.to raise_error(ArgumentError, /p00/)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::DECT
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::DECT
    expect(help_response).to respond_to :help
  end
end
