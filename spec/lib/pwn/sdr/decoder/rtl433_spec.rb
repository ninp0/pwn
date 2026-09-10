# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::RTL433 do
  it 'reports an actionable missing native executable without emitting frames' do
    Dir.mktmpdir('pwn-missing-backend-') do |dir|
      executable = File.join(dir, 'rtl_433')
      frames = []
      output = StringIO.new
      expect do
        described_class.decode(mode: :native, file: 'spec/fixtures/sdr/rtl433/toyota.cu8',
                               executable: executable, output: output, on_frame: ->(frame) { frames << frame })
      end.to raise_error(IOError, /rtl_433.*not found.*install.*executable:/i)
      expect(frames).to be_empty
      expect(output.string).to be_empty
    end
  end

  it 'cancels an already stopped native replay before spawning' do
    expect(Open3).not_to receive(:popen3)
    expect do
      described_class.decode(mode: :native, file: 'spec/fixtures/sdr/rtl433/toyota.cu8', stop: -> { true })
    end.to raise_error(IOError, /cancelled/)
  end

  it 'decodes six real over-air Acurite packets with payloads matching the upstream reference' do
    demod = described_class::AcuriteIQ.new(rate: 250_000)
    frames = []
    File.open('spec/fixtures/sdr/rtl433/acurite_th_609_001.cu8', 'rb') do |file|
      while (raw = file.read(4096))
        iq = PWN::SDR::Decoder::DSP.unpack_cu8(data: raw)
        demod.feed_iq(iq) { |frame| frames << frame }
      end
    end
    reference = File.readlines('spec/fixtures/sdr/rtl433/acurite_th_609_001.json').map { |line| JSON.parse(line, symbolize_names: true).except(:time, :mic) }
    expect(frames.map { |frame| frame.slice(*reference.first.keys) }).to eq(reference)
    expect(frames.length).to eq(6)
    expect(frames).to all(include(model: 'Acurite-609TXC', id: 202, battery_ok: 1,
                                  temperature_C: 26.2, humidity: 76, status: 2, decoded: true,
                                  integrity: 'additive-checksum'))
  end

  it 'routes the real RF fixture through the public decoder and rejects unsupported models' do
    frames = []
    result = described_class.decode(freq_obj: {}, file: 'spec/fixtures/sdr/rtl433/acurite_th_609_001.cu8',
                                    interactive: false, output: StringIO.new, log_file: false,
                                    on_frame: ->(frame) { frames << frame })
    expect(result[:frames]).to eq(6)
    expect(frames).to all(include(decoded: true, id: 202))
    expect { described_class.decode(mode: :all) }.to raise_error(ArgumentError, /mode/)
  end

  it 'replays OOK and FSK native catalogue decoders against published captures', :rtl433_integration do
    %w[acurite_th_609_001 wh31 toyota].each do |name|
      frames = []
      result = described_class.decode(mode: :native, file: "spec/fixtures/sdr/rtl433/#{name}.cu8",
                                      sample_rate: 250_000, output: StringIO.new, log_file: false,
                                      on_frame: ->(frame) { frames << frame })
      reference = File.readlines("spec/fixtures/sdr/rtl433/#{name}.json").map { |line| JSON.parse(line, symbolize_names: true).except(:time) }
      expect(frames.map { |frame| frame.slice(*reference.first.keys) }).to eq(reference)
      expect(result[:frames]).to eq(reference.length)
      expect(frames).to all(include(protocol: 'RTL433', backend: 'rtl_433', decoded: true))
      expect(frames.map { |frame| frame[:device_protocol] }).to all(be_a(Integer))
    end
  end

  it 'requires explicit native files and validates formats and protocol selection without the native client' do
    allow(PWN::SDR::Decoder::Base).to receive(:run_iq).and_raise('unexpected automatic RF')
    expect { described_class.decode(mode: :native) }.to raise_error(ArgumentError, /explicit file/)
    path = 'spec/fixtures/sdr/rtl433/toyota.cu8'
    expect { described_class.decode(mode: :native, file: path, format: :bogus) }.to raise_error(ArgumentError, /format/)
    expect { described_class.decode(mode: :native, file: path, source: :rtl_sdr) }.to raise_error(ArgumentError, /live source/)
    expect { described_class.decode(mode: :native, file: path, protocols: [0]) }.to raise_error(ArgumentError, /protocol/)
    expect { described_class.decode(mode: :native, file: path, stop: -> { true }) }.to raise_error(IOError, /cancelled/)
  end

  it 'supports native protocol selection', :rtl433_integration do
    path = 'spec/fixtures/sdr/rtl433/toyota.cu8'
    expect(described_class.decode(mode: :native, file: path, protocols: [11], output: StringIO.new)[:frames]).to eq(0)
    expect(described_class.decode(mode: :native, file: path, protocols: [88], output: StringIO.new)[:frames]).to eq(1)
  end

  # Synthetic OOK modulation; the bytes are the payload decoded from the real capture.
  def acurite_iq(hex)
    bits = [hex].pack('H*').unpack1('B*').chars
    levels = [0.01] * 1000
    bits.each { |bit| levels.concat(([0.9] * 125) + ([0.01] * (bit == '0' ? 250 : 500))) }
    levels.concat(([0.9] * 125) + ([0.01] * 1000))
    levels.flat_map { |level| [level, 0.0] }
  end

  it 'rejects corrupt checksums, truncated PPM frames and seeded low-level noise' do
    valid = acurite_iq('ca21064c3d')
    positive = []
    described_class::AcuriteIQ.new(rate: 250_000).feed_iq(valid) { |f| positive << f }
    expect(positive.length).to eq(1)
    random = Random.new(433)
    cases = [acurite_iq('ca21064c3c'), valid.first(valid.length / 2 / 2 * 2),
             Array.new(20_000) { random.rand * 0.1 }]
    cases.each do |iq|
      frames = []
      demod = described_class::AcuriteIQ.new(rate: 250_000)
      iq.each_slice(142) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
      demod.flush { |f| frames << f }
      expect(frames).to be_empty
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::RTL433
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::RTL433
    expect(help_response).to respond_to :help
  end
end
