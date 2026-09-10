# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::RFID do
  it 'reports an actionable missing native executable without emitting frames' do
    Dir.mktmpdir('pwn-missing-backend-') do |dir|
      executable = File.join(dir, 'proxmark3')
      frames = []
      output = StringIO.new
      expect do
        described_class.decode(mode: :fdxb_pm3, file: 'spec/fixtures/sdr/rfid/fdxb_animal.pm3',
                               executable: executable, output: output, on_frame: ->(frame) { frames << frame })
      end.to raise_error(IOError, /proxmark3.*not found.*install.*executable:/i)
      expect(frames).to be_empty
      expect(output.string).to be_empty
    end
  end

  it 'cancels an already stopped native replay before spawning' do
    expect(Process).not_to receive(:spawn)
    expect do
      described_class.decode(mode: :fdxb_pm3, file: 'spec/fixtures/sdr/rfid/fdxb_animal.pm3', stop: -> { true })
    end.to raise_error(IOError, /cancelled/)
  end

  it 'decodes independent ISO11784/11785 FDX-B amplitude captures with the native offline client', :proxmark3_integration do
    %w[animal extended].each do |variant|
      frames = []
      result = described_class.decode(mode: :fdxb_pm3, file: "spec/fixtures/sdr/rfid/fdxb_#{variant}.pm3",
                                      output: StringIO.new, on_frame: ->(frame) { frames << frame })
      expect(result[:frames]).to eq(1)
      expect(frames.first).to include(protocol: 'RFID', mode: :fdxb_pm3, source: 'amplitude',
                                      backend: 'proxmark3', decoded: true, country_code: 999,
                                      national_id: 112_233, integrity: 'crc16', uid: '999-000000112233')
      expect(frames.first[:animal]).to eq(variant == 'animal')
      expect(frames.first[:data_block]).to eq(variant == 'extended')
    end
  end

  it 'rejects automatic RF and supports cancellation without the native client' do
    allow(PWN::SDR::Decoder::Base).to receive(:run_iq).and_raise('unexpected automatic RF')
    expect { described_class.decode(mode: :fdxb_pm3) }.to raise_error(ArgumentError, /explicit/)
    path = 'spec/fixtures/sdr/rfid/fdxb_animal.pm3'
    expect { described_class.decode(mode: :fdxb_pm3, file: path, source: :rtl_sdr) }.to raise_error(ArgumentError, /live/)
    expect { described_class.decode(mode: :fdxb_pm3, file: path, stop: -> { true }) }.to raise_error(IOError, /cancelled/)
  end

  it 'emits no identity for an incomplete native amplitude trace', :proxmark3_integration do
    path = 'spec/fixtures/sdr/rfid/fdxb_animal.pm3'
    Tempfile.create(['fdxb-short-', '.pm3']) do |file|
      file.write(File.readlines(path).first(100).join)
      file.flush
      frames = []
      expect do
        described_class.decode(mode: :fdxb_pm3, file: file.path, output: StringIO.new,
                               on_frame: ->(frame) { frames << frame })
      end.to raise_error(IOError, /decoder failed/)
      expect(frames).to be_empty
    end
  end

  # Literal bits transcribed from Priority 1 Design's published card example:
  # https://www.priority1design.com.au/em4100_protocol.html (version 06, UID 001259E3).
  # The waveform below is synthetic modulation, NOT an independent RF capture.
  let(:card_bits) { '1111111110000001100000000000000011001010101010010111010011001000' }

  def em_iq(bits)
    bits.chars.flat_map do |bit|
      levels = bit == '1' ? [0.2, 0.8] : [0.8, 0.2]
      levels.flat_map { |level| [level, 0.0] * 16 }
    end
  end

  it 'recovers the externally published EM4100 card across arbitrary IQ chunks before flush' do
    demod = described_class::EM4100IQ.new(rate: 62_500)
    frames = []
    em_iq(card_bits * 2).each_slice(74) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
    expect(frames).not_to be_empty
    expect(frames.first).to include(uid: '06001259E3', version: 6, identifier: '001259E3',
                                    decoded: true, integrity: 'row-and-column-even-parity')
  end

  [16, 32, 64].each do |clocks|
    it "decodes RF/#{clocks} with inverted envelope polarity and arbitrary initial timing" do
      frames = []
      iq = ([0.8, 0.0] * 3) + em_iq(card_bits * 2).each_slice(2).map { |i, q| [1.0 - i, q] }.flatten
      demod = described_class::EM4100IQ.new(rate: 62_500 * 64 / clocks, clocks_per_bit: clocks)
      iq.each_slice(62) { |chunk| demod.feed_iq(chunk) { |f| frames << f } }
      expect(frames.map { |frame| frame[:uid] }.uniq).to eq(['06001259E3'])
    end
  end

  it 'routes the public IQ decode API to EM4100 instead of a detector' do
    raw = em_iq(card_bits).map { |sample| ((sample * 127.5) + 127.5).round }.pack('C*')
    frames = []
    result = described_class.decode(freq_obj: {}, source: StringIO.new(raw), sample_rate: 62_500,
                                    interactive: false, log_file: false, output: StringIO.new,
                                    on_frame: ->(frame) { frames << frame })
    expect(result[:frames]).to eq(1)
    expect(frames.first[:uid]).to eq('06001259E3')
  end

  it 'rejects unsupported RFID modes before opening any source' do
    expect { described_class.decode(mode: :epc_gen2) }.to raise_error(ArgumentError, /mode/)
  end

  it 'does not decode row parity, column parity, stop errors, truncated frames or noise' do
    [9, 13, 59, 63].each do |index|
      corrupt = card_bits.dup
      corrupt[index] = corrupt[index] == '0' ? '1' : '0'
      frames = []
      described_class::EM4100IQ.new(rate: 62_500).feed_iq(em_iq(corrupt * 2)) { |f| frames << f }
      expect(frames).to be_empty
    end
    [em_iq(card_bits[0, 63]), Array.new(20_000, 0.01)].each do |iq|
      frames = []
      demod = described_class::EM4100IQ.new(rate: 62_500)
      demod.feed_iq(iq) { |f| frames << f }
      demod.flush { |f| frames << f }
      expect(frames).to be_empty
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::RFID
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::RFID
    expect(help_response).to respond_to :help
  end
end
