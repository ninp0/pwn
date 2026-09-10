# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::Liquid do
  it 'should display information for authors' do
    expect(PWN::FFI::Liquid).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::Liquid).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::Liquid).to respond_to :available?
  end

  it 'rejects native DSP calls when libliquid is unavailable' do
    allow(described_class).to receive(:available?).and_return(false)
    expect { described_class.resample(samples: [0.0], rate: 0.5) }.to raise_error(RuntimeError, /libliquid not available/)
    expect { described_class.freq_demod(iq: [1.0, 0.0]) }.to raise_error(RuntimeError, /libliquid not available/)
  end

  it 'keeps DSP resampling functional when libliquid is unavailable' do
    allow(described_class).to receive(:available?).and_return(false)
    allow(PWN::SDR::Decoder::DSP).to receive(:native).and_return(true)
    expect(described_class).not_to receive(:resample)
    result = PWN::SDR::Decoder::DSP.resample(samples: [0.0, 1.0, 2.0, 3.0], src_rate: 4, dst_rate: 2)
    expect(result).to eq([0.0, 2.0])
  end

  before(:each, :liquid_integration) do
    expect(described_class.available?).to be(true),
                                          'PWN_TEST_LIQUID=1 requires liquid-dsp: install libliquid and make it visible to the dynamic loader. ' \
                                          "Load error: #{described_class.load_error}"
  end

  it 'should resample at half rate with libliquid', :liquid_integration do
    samples = Array.new(64) { |i| Math.sin(2 * Math::PI * i / 16.0) }
    out = PWN::FFI::Liquid.resample(samples: samples, rate: 0.5)
    expect(out.length).to be_between(24, 40)
  end

  it 'should FM-demod a complex tone with libliquid', :liquid_integration do
    iq = []
    phase = 0.0
    dphi = 2 * Math::PI * 0.05
    64.times do
      iq << Math.cos(phase)
      iq << Math.sin(phase)
      phase += dphi
    end
    audio = PWN::FFI::Liquid.freq_demod(iq: iq, kf: 0.5)
    expect(audio.length).to eq(64)
    # after settle, demod of constant dphi ≈ 0.1 (2*dphi when kf=0.5 → dphi/kf)
    expect(audio[10]).to be_within(0.05).of(0.1)
  end
end
