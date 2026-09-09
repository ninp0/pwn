# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'
require 'stringio'
require 'timeout'

describe PWN::SDR::Decoder::ADSB do
  it 'decodes surface movement and reference-resolved CPR through chunked IQ' do
    # pyModeS v2.21.1 tests/test_adsb.py: published payload and expected position.
    # Upstream supplied zero parity: regenerate CRC only, not the payload.
    bits = '8FC8200A3AB8F5F893096B000000'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    bits[88, 24] = described_class.crc24(bits: bits[0, 88] + Array.new(24, 0)).to_s(2).rjust(24, '0').chars.map(&:to_i)
    frame = described_class.decode_modes(bits: bits)
    expect(frame).to include(on_ground: true, ground_speed_kt: 19, cpr_format: 1)
    expect(frame[:track_deg]).to be_within(0.1).of(42.2)
    expect(frame).not_to have_key(:altitude_ft)
    frames = []
    demod = described_class::DemodIQ.new(reference: [-43.5, 172.5])
    iq = (described_class::PREAMBLE + bits.flat_map { |b| b == 1 ? [1.0, 0.0] : [0.0, 1.0] }).flat_map { |v| [v, 0.0] }
    iq.each_slice(17) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
    expect(frames.last[:lat]).to be_within(0.00001).of(-43.48564)
    expect(frames.last[:lon]).to be_within(0.00001).of(172.53942)
    expect(described_class.decode_modes(bits: bits)).not_to have_key(:lat)
    bits[40] ^= 1
    expect(described_class.decode_modes(bits: bits)).to be_nil
  end

  it 'does not invent surface speed or track from unavailable and reserved fields' do
    { 0 => nil, 1 => 0, 2 => 0.125, 8 => 0.875, 9 => 1,
      12 => 1.75, 13 => 2, 38 => 14.5, 39 => 15, 93 => 69,
      94 => 70, 108 => 98, 109 => 100, 123 => 170, 124 => nil,
      125 => nil, 127 => nil }.each do |movement, expected|
      bits = '8FC8200A3AB8F5F893096B000000'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
      bits[37, 7] = movement.to_s(2).rjust(7, '0').chars.map(&:to_i)
      bits[44] = 0
      bits[88, 24] = described_class.crc24(bits: bits[0, 88] + Array.new(24, 0)).to_s(2).rjust(24, '0').chars.map(&:to_i)
      frame = described_class.decode_modes(bits: bits)
      expect(frame[:ground_speed_kt]).to eq(expected)
      expect(frame).not_to have_key(:track_deg)
      expect(frame[:ground_speed_min_kt]).to eq(movement == 124 ? 175.0 : nil)
      [nil, [], [91, 0], [0, 181], [Float::NAN, 0]].each do |reference|
        expect(described_class.surface_position(frame: frame, reference: reference)).to be_nil
      end
    end
  end

  it 'forwards the surface reference into the actual IQ demodulator' do
    reference = [-43.5, 172.5]
    expect(described_class::DemodIQ).to receive(:new).with(rate: 2_000_000, reference: reference).and_call_original
    allow(PWN::SDR::Decoder::Base).to receive(:run_iq)
    described_class.decode(freq_obj: { freq: 1_090_000_000 }, reference: reference, file: '/offline/surface.cs16')
  end

  it 'decodes Q-zero Gillham altitude against the independent pyModeS v2.21.1 reference' do
    # py_common.altitude: insert absent M bit at index six of this 12-bit field.
    { 0x20 => nil, 0x80 => -1200, 0x100 => nil, 0x200 => -1000,
      0x400 => nil, 0x800 => -800, 0xA01 => 62_400, 0xA05 => 63_100,
      0xA09 => 61_100, 0xA0D => 64_400, 0xC08 => 29_200 }.each do |value, feet|
      bits = value.to_s(2).rjust(12, '0').chars.map(&:to_i)
      expect(described_class.modes_altitude(bits12: bits)).to eq(feet)
    end
    expect(described_class.modes_altitude(bits12: Array.new(12, 2))).to be_nil
  end

  it 'does not interpret a GNSS-height field as Q-bit barometric altitude' do
    bits = '8D40621D58C382D690C8AC2863A7'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    bits[32, 5] = [1, 0, 1, 0, 0]
    bits[88, 24] = described_class.crc24(bits: bits[0, 88] + Array.new(24, 0)).to_s(2).rjust(24, '0').chars.map(&:to_i)
    expect(described_class.decode_modes(bits: bits)).not_to have_key(:altitude_ft)
    expect(described_class.decode_modes(bits: bits)).to include(gnss_height_m: 3128)
  end

  it 'extracts airborne CPR and resolves the published even/odd position pair' do
    # The 1090 MHz Riddle, airborne-position worked example (even most recent).
    even, odd = %w[8D40621D58C382D690C8AC2863A7 8D40621D58C386435CC412692AD6].map do |hex|
      described_class.decode_modes(bits: hex.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) })
    end
    expect(even).to include(cpr_format: 0, cpr_lat: 93_000, cpr_lon: 51_372)
    position = described_class.airborne_position(even: even, odd: odd, even_time: 10, odd_time: 5)
    expect(position[:lat]).to be_within(0.00001).of(52.257202)
    expect(position[:lon]).to be_within(0.00001).of(3.919373)
    expect(described_class.airborne_position(even: even, odd: odd, even_time: 20, odd_time: 5)).to be_nil
    expect(described_class.airborne_position(even: even, odd: odd.merge(icao24: 'FFFFFF'), even_time: 10, odd_time: 5)).to be_nil
  end

  it 'decodes published ground and air velocity vectors with source and altitude difference' do
    # https://github.com/junzis/the-1090mhz-riddle/blob/master/content/ads-b/5-airborne-velocity.tex
    ground, air = %w[8D485020994409940838175B284F 8DA05F219B06B6AF189400CBC33F].map do |hex|
      described_class.decode_modes(bits: hex.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) })
    end
    expect(ground).to include(velocity_subtype: 1, east_velocity_kt: -8, north_velocity_kt: -159,
                              vertical_rate_fpm: -832, vertical_rate_source: 'GNSS', gnss_baro_difference_ft: 550)
    expect(ground[:ground_speed_kt]).to be_within(0.01).of(159.20)
    expect(ground[:track_deg]).to be_within(0.01).of(182.88)
    expect(air).to include(airspeed_kt: 375, airspeed_type: 'TAS', vertical_rate_fpm: -2304, vertical_rate_source: 'barometric')
    expect(air[:heading_deg]).to be_within(0.01).of(243.98)
    expect(air).not_to have_key(:gnss_baro_difference_ft)
    expect(air).not_to have_key(:ground_speed_kt)
  end

  it 'adds global CPR positions to streaming IQ frames rather than only exposing a helper' do
    frames = []
    demod = described_class::DemodIQ.new
    %w[8D40621D58C386435CC412692AD6 8D40621D58C382D690C8AC2863A7].each do |hex|
      bits = hex.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
      iq = (described_class::PREAMBLE + bits.flat_map { |b| b == 1 ? [1.0, 0.0] : [0.0, 1.0] }).flat_map { |v| [v, 0.0] }
      iq.each_slice(17) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
    end
    expect(frames.first).not_to have_key(:lat)
    expect(frames.last[:lat]).to be_within(0.00001).of(52.257202)
    expect(frames.last[:lon]).to be_within(0.00001).of(3.919373)
  end

  it 'does not claim arbitrary text is decoded UAT data' do
    expect(described_class.parse_line(line: 'noise')).to be_nil
  end

  it 'never silently falls back to energy detection from decode' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(hash_including(fallback: :raise))
    described_class.decode(freq_obj: {}, file: '/offline/fixture.cs16', fallback: :detector)
  end

  it 'emits the known Mode S vector while the source pipe remains open and rejects noise' do
    bits = '8D40621D58C382D690C8AC2863A7'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    iq = (described_class::PREAMBLE + bits.flat_map { |b| b == 1 ? [1, 0] : [0, 1] }).flat_map { |v| [(v * 20_000).to_i, 0] }
    reader, writer = IO.pipe
    frames = Queue.new
    worker = Thread.new do
      described_class.decode(freq_obj: { freq: 1_090_000_000 }, source: reader, sample_rate: 2_000_000,
                             iq_format: :cs16, interactive: false, output: StringIO.new, log_file: false,
                             on_frame: ->(frame) { frames << frame })
    end
    Timeout.timeout(3) do
      writer.write(iq.pack('s<*'))
      expect(frames.pop[:raw_hex]).to eq('8D40621D58C382D690C8AC2863A7')
      expect(writer).not_to be_closed
      writer.close
      worker.value
    end
    random = Random.new(21)
    demod = described_class::DemodIQ.new
    bad_frames = []
    demod.feed_iq(Array.new(4000) { random.rand(-1.0..1.0) }) { |f| bad_frames << f }
    expect(bad_frames).to be_empty
  ensure
    writer&.close unless writer&.closed?
    worker&.kill
    worker&.join
    reader&.close unless reader&.closed?
  end

  it 'rejects unsupported UAT and rates instead of decoding with the 2 Msps Mode S slicer' do
    allow(PWN::SDR::Decoder::Base).to receive(:run_iq)
    expect { described_class.decode(freq_obj: { freq: '978.000.000' }) }.to raise_error(ArgumentError, /UAT/)
    expect { described_class::DemodIQ.new(rate: 2_400_000) }.to raise_error(ArgumentError, /2_000_000/)
  end

  it 'validates public Mode S frames and preserves I/Q pairs across odd chunks' do
    bits = '8D40621D58C382D690C8AC2863A7'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    expect(described_class.decode_modes(bits: bits)).to include(icao24: '40621D', altitude_ft: 38_000)
    bad = bits.dup
    bad[40] ^= 1
    expect(described_class.decode_modes(bits: bad)).to be_nil
    expect(described_class.decode_modes(bits: bits[0...-1])).to be_nil
    iq = (described_class::PREAMBLE + bits.flat_map { |bit| bit == 1 ? [1.0, 0.0] : [0.0, 1.0] }).flat_map { |x| [x, 0.0] }
    frames = []
    demod = described_class::DemodIQ.new
    iq.each_slice(17) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
    expect(frames.map { |f| f[:icao24] }).to eq(['40621D'])
  end

  it 'exposes detection separately without claiming a decoded payload' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_detector) do |opts|
      detail = opts[:describe].call({})
      expect(detail).to include(event: 'detection', capability: 'energy-detection', decoded: false)
      expect(detail.keys & %i[text message payload type_payload]).to be_empty
      expect(opts[:interactive]).to eq(false)
      :detected
    end
    expect(described_class.detect(freq_obj: {}, interactive: false)).to eq(:detected)
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'emits a CRC-valid frame ending exactly at a chunk boundary' do
    bits = '8D40621D58C382D690C8AC2863A7'.chars.flat_map { |c| c.to_i(16).digits(2).fill(0, c.to_i(16).digits(2).length...4).reverse }
    iq = (described_class::PREAMBLE + bits.flat_map { |bit| bit == 1 ? [1.0, 0.0] : [0.0, 1.0] }).flat_map { |x| [x, 0.0] }
    frames = []
    demod = described_class::DemodIQ.new
    iq.each_slice(26) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
    expect(frames.map { |f| f[:raw_hex] }).to eq(['8D40621D58C382D690C8AC2863A7'])
  end

  it 'emits changed payloads from the same aircraft during one stream' do
    first = '8D40621D58C382D690C8AC2863A7'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    second = first[0, 88]
    second[40] ^= 1
    crc = described_class.crc24(bits: second + Array.new(24, 0))
    second += crc.to_s(2).rjust(24, '0').chars.map(&:to_i)
    frames = []
    demod = described_class::DemodIQ.new
    [first, second].each do |bits|
      iq = (described_class::PREAMBLE + bits.flat_map { |b| b == 1 ? [1.0, 0.0] : [0.0, 1.0] }).flat_map { |x| [x, 0.0] }
      demod.feed_iq(iq) { |f| frames << f }
    end
    expect(frames.length).to eq(2)
    expect(frames.map { |f| f[:raw_hex] }.uniq.length).to eq(2)
  end

  %i[ADSB Flex Morse Pager POCSAG RTTY].each do |name|
    it "terminates #{name}'s actual offline pipeline without reporting silence as frames" do
      frames = []
      output = StringIO.new
      Tempfile.create(['decoder-silence', '.cs16']) do |file|
        file.binmode
        file.write("\0" * 512)
        file.flush
        expect(PWN::SDR::GQRX).not_to receive(:listen_udp)
        Timeout.timeout(3) do
          PWN::SDR::Decoder.const_get(name).decode(
            freq_obj: { freq: '1090 MHz' }, file: file.path,
            on_frame: proc { |f| frames << f }, output: output, interactive: false,
            duration: 1, queue_size: 2, log_file: false, chunk_bytes: 17
          )
        end
      end
      expect(frames).to be_empty
      expect(output.string).to be_empty
    end
  end

  %i[Flex Morse Pager POCSAG RTTY].each do |name|
    [false, true].each do |iq|
      it "configures #{name}'s audio clock for the selected #{iq ? 'IQ' : 'audio'} input rate" do
        mod = PWN::SDR::Decoder.const_get(name)
        opts = { freq_obj: { freq: '145 MHz' }, rate: 8000, sample_rate: 96_000 }
        opts[:file] = '/offline/fixture.cs16' if iq
        expect(mod::Demod).to receive(:new).with(rate: iq ? 96_000 : 8000).and_call_original
        allow(PWN::SDR::Decoder::Base).to receive(iq ? :run_iq : :run_native)
        mod.decode(opts)
      end
    end
  end

  # Registry aliases are exercised too; APT/Tempest have separate owners.
  PWN::SDR::Decoder::REGISTRY.select { |_, name| %i[ADSB Flex Morse Pager POCSAG RTTY].include?(name) }.each do |key, name|
    [false, true].each do |iq|
      it "forwards realtime controls through #{key} (IQ=#{iq}) without overriding protocol configuration" do
        mod = PWN::SDR::Decoder.const_get(name)
        controls = {
          on_frame: proc {}, output: false, interactive: false, duration: 0.1,
          stop: proc { false }, queue_size: 7, log_file: false
        }
        opts = controls.merge(freq_obj: { freq: '1090 MHz' }, protocol: 'WRONG', demod: :wrong)
        opts[:file] = '/offline/fixture.cu8' if iq
        runner = !iq && %i[Flex Morse Pager POCSAG RTTY].include?(name) ? :run_native : :run_iq
        expect(PWN::SDR::Decoder::Base).to receive(runner) do |actual|
          expect(actual).to include(controls)
          expect(actual[:protocol]).not_to eq('WRONG')
          expect(actual[:demod]).not_to eq(:wrong)
        end
        mod.decode(opts)
      end
    end
  end
end
