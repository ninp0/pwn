# frozen_string_literal: true

# Offline replay only; no RF acquisition. Run with bundle exec ruby.
require 'pwn'
require 'json'
require 'stringio'
require 'digest'

path = File.expand_path('../../spec/fixtures/sdr/lte/signal.1.92M.dat', __dir__)
iq = File.binread(path, 76_800).unpack('e*')
raw = iq.map { |value| (value * 16_000).round }.pack('s<*')
iterations = Integer(ENV.fetch('ITERATIONS', '100'))
raise ArgumentError, 'ITERATIONS must be positive' unless iterations.positive?

results = { fixture_sha256: Digest::SHA256.file(path).hexdigest,
            scope: 'offline repeated upstream 5ms capture; not a continuous on-air stream',
            iterations: iterations }
%i[demod shared_runner].each do |mode|
  counts = []
  times = Array.new(iterations) do
    count = 0
    emit = lambda do |frame|
      raise 'unexpected MIB' unless frame[:payload_hex] == '681c00' && frame[:pci] == 150 && frame[:checksum_verified]

      count += 1
    end
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    if mode == :demod
      demod = PWN::SDR::Decoder::LTE::AcquiredPBCHIQ.new
      demod.feed_iq(iq, &emit)
      demod.flush(&emit)
    else
      result = PWN::SDR::Decoder::LTE.decode(mode: :pbch_iq, source: StringIO.new(raw),
                                             iq_format: :cs16, chunk_bytes: 997,
                                             interactive: false, output: StringIO.new,
                                             log_file: false, on_frame: emit)
      raise 'runner did not reach EOF' unless result[:reason] == :eof
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
    raise "expected one MIB, got #{count}" unless count == 1

    counts << count
    elapsed
  end
  seconds = times.sum
  results[mode] = { first_seconds: times.first, total_seconds: seconds, decoded_mibs: counts.sum,
                    complex_samples_per_second: iterations * 9600 / seconds,
                    realtime_ratio: iterations * 0.005 / seconds }
end
json = JSON.pretty_generate(results)
File.write(File.join(__dir__, 'benchmark-results.json'), "#{json}\n")
puts json
