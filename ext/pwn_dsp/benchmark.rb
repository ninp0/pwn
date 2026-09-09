# frozen_string_literal: true

# Run: bundle exec ruby -Ilib ext/pwn_dsp/benchmark.rb
require 'pwn'
require 'pwn/ffi/dsp_native'
require 'json'

dsp = PWN::SDR::Decoder::DSP
raw = Random.new(71).bytes(2 * 1_048_576)
dsp.native = false
iq = dsp.unpack_cu8(data: raw)
rows = []
[false, true].each do |native|
  dsp.native = native
  kernels = {
    unpack_array: [1_048_576, -> { dsp.unpack_cu8(data: raw) }],
    magnitude_array: [1_048_576, -> { dsp.mag_sq(iq: iq) }],
    fm_array: [1_048_576, -> { dsp.fm_demod_iq(iq: iq) }],
    fft512: [512 * 128, -> { 128.times { dsp.cfft_mag(iq: iq.first(1024), n: 512) } }]
  }
  kernels[:fft4096] = [4096 * 32, -> { 32.times { dsp.cfft_mag(iq: iq.first(8192), n: 4096) } }]
  %i[unpack mag fm].each do |op|
    kernels["packed_#{op}"] = [1_048_576, -> { dsp.process_iq(data: raw, operation: op, native: native) }]
  end
  kernels.each do |name, (count, kernel)|
    kernel.call
    times = Array.new(5) do
      start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      kernel.call
      Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
    end
    median = times.sort[2]
    rows << { native: native, kernel: name, samples: count, seconds: times, median_ms: median * 1000,
              msps: count / median / 1_000_000, keeps_up_kernel_only: [2_400_000, 10_000_000, 20_000_000].to_h { |rate| [rate, count / median >= rate] } }
  end
end
puts JSON.pretty_generate(ruby: RUBY_DESCRIPTION, platform: RUBY_PLATFORM, backends: PWN::FFI.backends,
                          note: 'Kernel wall time includes FFI copies and Ruby output allocation, not acquisition or protocol decoding. FFT512 batches 128 transforms; FFT4096 batches 32. Ruby fallback now preserves full requested size.', results: rows)
