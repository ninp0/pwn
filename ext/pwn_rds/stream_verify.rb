# frozen_string_literal: true

# Real MPX replay, with a live pipe held open; no RF hardware.
require 'pwn'
require 'open3'
require 'timeout'
require 'stringio'

backend = ENV.fetch('REDSEA', 'redsea')
fixture = File.expand_path('../../spec/fixtures/sdr/rds/mpx-testfile-yksi.flac', __dir__)
pcm, status = Open3.capture2('sox', fixture, '-t', 's16', '-L', '-')
raise 'sox failed' unless status.success?

reader, writer = IO.pipe
queue = Queue.new
worker = Thread.new do
  PWN::SDR::Decoder::RDS.decode(freq_obj: {}, backend: :redsea, executable: backend,
                                source: reader, sample_rate: 192_000, interactive: false,
                                output: StringIO.new, log_file: false, on_frame: ->(frame) { queue << frame })
end
begin
  pcm.bytes.each_slice(137) { |bytes| writer.write(bytes.pack('C*')) }
  frame = Timeout.timeout(5) { queue.pop }
  raise 'Wrong raw PCM group' unless frame[:raw_group_hex] == '620101DF0A145349' && frame[:rds_pi] == '6201'
  raise 'EOF occurred before frame' if writer.closed?

  writer.close
  raise 'No EOF result' unless Timeout.timeout(5) { worker.value }[:reason] == :eof

  puts 'PASS: raw s16le MPX -> 57 kHz demod -> intact 0A group before pipe EOF'
ensure
  writer.close unless writer.closed?
  worker.kill if worker.alive?
  worker.join
  reader.close unless reader.closed?
end

reader, writer = IO.pipe
begin
  worker = Thread.new do
    PWN::SDR::Decoder::RDS.decode(freq_obj: {}, backend: :redsea, executable: backend,
                                  source: reader, sample_rate: 192_000, interactive: false,
                                  output: StringIO.new, log_file: false, duration: 0.1)
  end
  raise 'Deadline not honored' unless Timeout.timeout(3) { worker.value }[:reason] == :duration
  raise 'Source leaked' unless reader.closed?

  puts 'PASS: deadline cancels blocked native backend and closes source'
ensure
  writer.close unless writer.closed?
  worker.kill if worker.alive?
  worker.join
end
