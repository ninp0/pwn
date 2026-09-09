# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ffi/dsp_native'

describe PWN::SDR::Decoder::DSP do
  if PWN::FFI::DSPNative.available? || ENV['PWN_TEST_DSP_NATIVE'] == '1'
    it 'executes native packed kernels with Ruby parity when explicitly built' do
      %i[cu8 cs16le f64].each do |format|
        raw = format == :f64 ? Array.new(514) { |i| Math.sin(i * 0.13) }.pack('d*') : Random.new(83).bytes(1028)
        %i[unpack mag fm].each do |operation|
          opts = { data: raw, format: format, operation: operation, kf: 0.37 }
          ruby = described_class.process_iq(opts.merge(native: false))
          native = described_class.process_iq(opts.merge(native: true))
          expect(native[:backend]).to eq(:native)
          expect(native[:samples].length).to eq(ruby[:samples].length)
          native[:samples].zip(ruby[:samples]).each { |a, b| expect(a).to be_within(1e-12).of(b) }
          state = {}
          chunked = raw.bytes.each_slice(19).flat_map do |bytes|
            described_class.process_iq(opts.merge(data: bytes.pack('C*'), native: true, state: state))[:samples]
          end
          expect(chunked).to eq(native[:samples])
        end
      end
    end
  end

  it 'preserves double precision in public magnitude and packed unpack APIs' do
    was = described_class.native
    iq = Array.new(514) { |i| Math.sin(i * 0.19) }
    described_class.native = false
    expected = described_class.mag_sq(iq: iq)
    raw = Random.new(92).bytes(1028)
    cu8 = described_class.unpack_cu8(data: raw)
    cs16 = described_class.unpack_cs16le(data: raw)
    described_class.native = true
    expect(described_class.mag_sq(iq: iq)).to eq(expected)
    expect(described_class.unpack_cu8(data: raw)).to eq(cu8)
    expect(described_class.unpack_cs16le(data: raw)).to eq(cs16)
  ensure
    described_class.native = was
  end

  it 'returns every requested FFT bin and agrees across Ruby and native transforms' do
    was = described_class.native
    iq = [1.0, 0.0] + Array.new(2046, 0.0)
    described_class.native = false
    ruby = described_class.cfft_mag(iq: iq, n: 1024, shift: false)
    expect(ruby.length).to eq(1024)
    expect(ruby).to eq(Array.new(1024, 1.0))
    [8, 64, 1024].each do |n|
      input = Array.new(n * 2) { |i| Math.sin(i * 0.123) }
      described_class.native = false
      expected = described_class.cfft_mag(iq: input, n: n)
      described_class.native = true
      actual = described_class.cfft_mag(iq: input, n: n)
      tolerance = PWN::FFI::DSPNative.available? ? 1e-8 : 1e-4
      actual.zip(expected).each { |a, b| expect(a).to be_within(tolerance).of(b) }
    end
  ensure
    described_class.native = was
  end

  it 'keeps the public FM scale, length and chunk state identical across backends' do
    iq = Array.new(1000) { |i| Math.sin(i * 0.13) }
    was = described_class.native
    described_class.native = false
    expected = described_class.fm_demod_iq(iq: iq, kf: 0.37)
    described_class.native = true
    actual = described_class.fm_demod_iq(iq: iq, kf: 0.37)
    expect(actual.length).to eq(expected.length)
    actual.zip(expected).each { |a, b| expect(a).to be_within(1e-12).of(b) }
    state = {}
    parts = iq.each_slice(14).flat_map { |chunk| described_class.fm_demod_iq(iq: chunk, kf: 0.37, state: state) }
    expect(parts).to eq(actual)
  ensure
    described_class.native = was
  end

  it 'degrades explicitly without a helper and preserves state after a native failure' do
    opts = { data: Random.new(5).bytes(33), format: :cs16le, operation: :fm, state: { previous: [0.25, -0.5], remainder: "\x01".b } }
    expected_state = Marshal.load(Marshal.dump(opts[:state]))
    expected = described_class.process_iq(opts.merge(native: false, state: expected_state))
    allow(PWN::FFI::DSPNative).to receive(:available?).and_return(false)
    missing_state = Marshal.load(Marshal.dump(opts[:state]))
    expect(described_class.process_iq(opts.merge(native: true, state: missing_state))).to eq(expected)
    expect(missing_state).to eq(expected_state)
    allow(PWN::FFI::DSPNative).to receive(:available?).and_return(true)
    allow(PWN::FFI::DSPNative).to receive(:process_iq).and_raise('native error')
    expect(described_class.process_iq(opts.merge(native: true))).to eq(expected)
    expect(opts[:state]).to eq(expected_state)
  end

  it 'processes packed IQ with explicit Ruby degradation and byte-boundary FM state' do
    raw = Random.new(71).bytes(1027)
    whole = described_class.process_iq(data: raw, format: :cu8, operation: :fm, native: false)
    state = {}
    chunks = raw.bytes.each_slice(17).flat_map do |bytes|
      described_class.process_iq(data: bytes.pack('C*'), format: :cu8, operation: :fm, native: false, state: state)[:samples]
    end
    expect(chunks).to eq(whole[:samples])
    expect(state[:remainder]).to eq(raw.byteslice(-1, 1))
    expect(whole[:backend]).to eq(:ruby)
  end
end
