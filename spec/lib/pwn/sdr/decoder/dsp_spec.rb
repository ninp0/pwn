# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::DSP do
  it 'should display information for authors' do
    expect(PWN::SDR::Decoder::DSP).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::SDR::Decoder::DSP).to respond_to :help
  end

  it 'should expose a native toggle' do
    expect(PWN::SDR::Decoder::DSP).to respond_to :native
    expect(PWN::SDR::Decoder::DSP).to respond_to :native=
  end

  it 'should unpack s16le to unit-range floats (ruby path)' do
    was = PWN::SDR::Decoder::DSP.native
    PWN::SDR::Decoder::DSP.native = false
    raw = [0, 16_384, -16_384, 32_767].pack('s<*')
    out = PWN::SDR::Decoder::DSP.unpack_s16le(data: raw)
    expect(out[0]).to be_within(1e-6).of(0.0)
    expect(out[1]).to be_within(1e-3).of(0.5)
    expect(out[2]).to be_within(1e-3).of(-0.5)
    expect(out[3]).to be_within(1e-3).of(1.0)
  ensure
    PWN::SDR::Decoder::DSP.native = was
  end

  it 'should unpack s16le via Volk', :volk_integration do
    was = PWN::SDR::Decoder::DSP.native
    expect(PWN::FFI.available?(mod: :Volk)).to be(true), 'Install libvolk and make it visible to the dynamic loader (PWN_TEST_VOLK=1).'
    PWN::SDR::Decoder::DSP.native = true
    raw = [0, 16_384, -16_384, 32_767].pack('s<*')
    native_out = PWN::FFI::Volk.unpack_s16le(data: raw)
    expect(PWN::FFI::Volk).to receive(:unpack_s16le).with(data: raw).and_call_original
    out = PWN::SDR::Decoder::DSP.unpack_s16le(data: raw)
    expect(out).to eq(native_out)
    expect(out[1]).to be_within(1e-3).of(0.5)
  ensure
    PWN::SDR::Decoder::DSP.native = was
  end

  it 'falls back to Ruby unpacking with native enabled but Volk absent' do
    was = described_class.native
    described_class.native = true
    allow(PWN::FFI).to receive(:available?).with(mod: :Volk).and_return(false)
    expect(PWN::FFI::Volk).not_to receive(:unpack_s16le)
    raw = [0, 16_384, -16_384, 32_767].pack('s<*')
    expect(described_class.unpack_s16le(data: raw)).to eq([0.0, 0.5, -0.5, 32_767 / 32_768.0])
  ensure
    described_class.native = was
  end

  it 'falls back to Ruby resampling with native enabled but Liquid absent' do
    was = described_class.native
    samples = Array.new(200) { |i| Math.sin(2 * Math::PI * i / 40.0) }
    described_class.native = false
    ruby_out = described_class.resample(samples: samples, src_rate: 48_000, dst_rate: 24_000)
    expect(ruby_out.length).to eq(100)

    allow(PWN::FFI).to receive(:available?).with(mod: :Liquid).and_return(false)
    expect(PWN::FFI::Liquid).not_to receive(:resample)
    described_class.native = true
    expect(described_class.resample(samples: samples, src_rate: 48_000, dst_rate: 24_000)).to eq(ruby_out)
  ensure
    described_class.native = was
  end

  it 'resamples using Liquid to a comparable length', :liquid_integration do
    was = described_class.native
    expect(PWN::FFI.available?(mod: :Liquid)).to be(true), 'Install libliquid and make it visible to the dynamic loader (PWN_TEST_LIQUID=1).'
    samples = Array.new(200) { |i| Math.sin(2 * Math::PI * i / 40.0) }
    described_class.native = true
    native_out = PWN::FFI::Liquid.resample(samples: samples, rate: 0.5)
    expect(PWN::FFI::Liquid).to receive(:resample).with(samples: samples, rate: 0.5).and_call_original
    liq_out = described_class.resample(samples: samples, src_rate: 48_000, dst_rate: 24_000)
    expect(liq_out).to eq(native_out)
    # Multi-stage resampler length can differ due to delay.
    expect(liq_out.length).to be_between(90, 120)
  ensure
    described_class.native = was
  end
end
