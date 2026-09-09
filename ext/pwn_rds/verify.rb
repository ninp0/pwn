# frozen_string_literal: true

# Explicit optional native-backend verification; never opens an RF device.
require 'pwn'
require 'stringio'
require 'timeout'
require 'json'

backend = ENV.fetch('REDSEA', 'redsea')
fixture = File.expand_path('../../spec/fixtures/sdr/rds/mpx-testfile-yksi.flac', __dir__)
frames = []
started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
result = Timeout.timeout(10) do
  PWN::SDR::Decoder::RDS.decode(freq_obj: {}, backend: :redsea, executable: backend,
                                file: fixture, interactive: false, log_file: false,
                                output: StringIO.new, on_frame: ->(frame) { frames << frame })
end
elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
raise "Wrong stream result: #{result.inspect}" unless result[:reason] == :eof
raise "Wrong decoded groups: #{frames.inspect}" unless frames.length == 1 && frames[0].values_at(:rds_pi, :group, :checksum_verified) == ['6201', '14A', true]
raise 'Missing independently expected group fields' unless frames[0][:backend_fields]['prog_type'] == 'Serious classical'

puts JSON.pretty_generate(fixture_duration_seconds: 0.7, wall_seconds: elapsed,
                          groups: frames.length, result: frames.first)
