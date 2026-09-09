# frozen_string_literal: true

# Offline full Base runner: packed file input, conversion/FM, SCH search,
# Viterbi/CRC, JSONL output and synchronous callbacks. No hardware.
require 'pwn'
require 'json'
require 'stringio'
require 'tempfile'

root = File.expand_path('../..', __dir__)
gsm = PWN::SDR::Decoder::GSM
fixture = File.binread(File.join(root, 'spec/fixtures/sdr/gsm/sch.cs16'))
rate = 1_083_333
repeats = Integer(ENV.fetch('GSM_BENCH_REPEATS', '20'))
# One independently modulated burst per ~10 TDMA frames, plus noise elsewhere.
random = Random.new(61)
noise = Array.new((50_000 - (fixture.bytesize / 4)) * 2) { random.rand(-500..500) }.pack('s<*')
raw = (fixture + noise) * repeats
results = []
Tempfile.create(['pwn-gsm-benchmark', '.cs16']) do |file|
  file.binmode
  file.write(raw)
  file.flush
  [false, true].each do |native|
    backend = gsm::SCHDemodIQ.new(rate: rate, native: native).backend
    abort 'Build ext/pwn_gsm/build.rb before benchmarking native' if native && backend != :native
    frames = []
    output = StringIO.new
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = gsm.decode(source: :file, file: file.path, iq_format: :cs16,
                        sample_rate: rate, chunk_bytes: 16_384, native: native,
                        interactive: false, log_file: false, output: output,
                        on_frame: ->(frame) { frames << frame })
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    abort 'Incorrect benchmark decode' unless result[:reason] == :eof && frames.length == repeats && frames.all? { |frame| frame[:payload_hex] == '03030100' }
    samples = raw.bytesize / 4
    results << { backend: backend, samples: samples, seconds: elapsed,
                 samples_per_second: samples / elapsed, realtime: samples / elapsed >= rate,
                 verified_frames: frames.length, chunk_bytes: 16_384,
                 dsp_native: PWN::SDR::Decoder::DSP.native && PWN::FFI.available?(mod: :DSPNative),
                 ruby_version: RUBY_VERSION }
  end
end
puts JSON.pretty_generate(results)
