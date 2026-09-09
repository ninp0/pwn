# frozen_string_literal: true

require 'json'
require 'open3'

module PWN
  module SDR
    module Decoder
      # Protocol frames via .decode; energy observations only via .detect.
      module RTL433
        # Streaming I/Q energy/burst demod for Base.run_iq.
        class DetectorIQ
          def initialize(rate:, protocol:, modulation:, extra: {})
            @rate = rate.to_f
            @protocol = protocol
            @modulation = modulation
            @extra = extra
            @floor = nil
            @in_burst = false
            @burst_t0 = nil
            @magnitudes = []
            @sample_count = 0
            @peak = -200.0
            @burst_n = 0
            @threshold = (extra[:threshold] || 8.0).to_f
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            @magnitudes.concat(PWN::SDR::Decoder::DSP.mag_sq(iq: samples))
            m2 = @magnitudes
            hop = [(@rate / 1000.0).round, 1].max
            i = 0
            while i + hop <= m2.length
              win = m2[i, hop]
              break if win.nil? || win.empty?

              ms = win.sum / win.length
              lvl = ms.positive? ? (10.0 * Math.log10(ms)) : -120.0
              @floor = @floor.nil? ? lvl : ((@floor * 0.98) + (lvl * 0.02))
              delta = lvl - @floor
              if delta >= @threshold
                unless @in_burst
                  @in_burst = true
                  @burst_t0 = @sample_count
                  @peak = lvl
                end
                @peak = lvl if lvl > @peak
              elsif @in_burst
                emit_burst(&)
              end
              i += hop
              @sample_count += hop
            end
            @magnitudes.shift(i)
          end

          def flush(&)
            @sample_count += @magnitudes.length
            @magnitudes.clear
            emit_burst(truncated: true, &) if @in_burst
          end

          private

          def emit_burst(truncated: false)
            @in_burst = false
            @burst_n += 1
            dur_ms = ((@sample_count - @burst_t0) * 1000.0 / @rate).round
            msg = {
              protocol: @protocol, event: 'burst', source: 'iq',
              capability: 'detector-only', decoded: false,
              burst_no: @burst_n, peak_dbfs: @peak.round(1),
              floor_dbfs: @floor.round(1), delta_db: (@peak - @floor).round(1),
              duration_ms: dur_ms, modulation: @modulation,
              sample_rate: @rate.to_i
            }.merge(@extra.except(:threshold))
            # protocol-specific enrichment
            msg.merge!(self.class.enrich(msg)) if self.class.respond_to?(:enrich)
            msg[:summary] = format(
              '%<p>s IQ-burst #%<n>d peak=%<pk>+.1f dBFS Δ=%<d>.1f dB dur=%<ms>d ms',
              p: @protocol, n: @burst_n, pk: @peak, d: @peak - @floor, ms: dur_ms
            )
            msg[:truncated] = true if truncated
            yield msg if block_given?
          end
        end

        # Native Acurite 609TXC OOK/PPM only. Protocol timing and checksum:
        # https://github.com/merbanan/rtl_433/blob/master/src/devices/acurite.c
        # This is NOT a binding to rtl_433 or support for its entire device catalogue.
        class AcuriteIQ
          def initialize(rate:, threshold: 0.5)
            @rate = Float(rate)
            raise ArgumentError, 'Acurite requires sample_rate >= 20000' unless @rate.finite? && @rate >= 20_000

            @threshold = Float(threshold)**2
            @smooth = 0.0
            @alpha = 1.0 / [(@rate * 0.000032).round, 1].max
            @level = false
            @run = 0
            @bits = []
            @pulse_valid = false
          end

          def feed_iq(samples, rate: nil)
            raise ArgumentError, 'sample rate changed midstream' if rate && (rate.to_f - @rate).abs.positive?
            raise ArgumentError, 'interleaved IQ pairs required' unless samples.length.even?

            samples.each_slice(2) do |i, q|
              @smooth += @alpha * (((i * i) + (q * q)) - @smooth)
              level = @smooth >= @threshold * (@level ? 0.8 : 1.2)
              if level != @level
                duration = @run / @rate
                if @level
                  @pulse_valid = duration.between?(0.00015, 0.001)
                  @bits.clear unless @pulse_valid
                elsif @pulse_valid && duration.between?(0.00065, 0.0025)
                  @bits << (duration < 0.0015 ? 0 : 1)
                  @bits.clear if @bits.length > 40
                else
                  @bits.clear
                end
                @level = level
                @run = 0
              end
              @run += 1
              next if @level || @run != (@rate * 0.003).ceil

              frame = RTL433.parse_frame(bits: @bits)
              yield frame if frame && block_given?
              @bits.clear
              @pulse_valid = false
            end
          end

          def flush
            @bits.clear
          end
        end

        public_class_method def self.parse_frame(opts = {})
          bits = opts[:bits]
          return nil unless bits.is_a?(Array) && bits.length == 40 && bits.all? { |b| [0, 1].include?(b) }

          bytes = bits.each_slice(8).map { |byte| byte.join.to_i(2) }
          checksum = bytes.first(4).sum
          return nil if checksum.zero? || (checksum & 0xff) != bytes[4] || bytes[3] > 100

          temperature = ((bytes[1] & 15) << 8) | bytes[2]
          temperature -= 4096 if temperature >= 2048
          { protocol: 'RTL433', mode: :acurite_609txc, source: 'iq', decoded: true,
            model: 'Acurite-609TXC', id: bytes[0], status: bytes[1] >> 4,
            battery_ok: bytes[1].nobits?(0x80) ? 1 : 0, temperature_C: temperature / 10.0,
            humidity: bytes[3], integrity: 'additive-checksum', payload_hex: bytes.pack('C*').unpack1('H*'),
            summary: "Acurite-609TXC id=#{bytes[0]} temperature=#{temperature / 10.0}C humidity=#{bytes[3]}%" }
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTL433.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        SUPPORTED_MODES = %i[acurite_609txc native].freeze
        DemodIQ = AcuriteIQ

        # Never silently downgrade decode to energy detection.
        public_class_method def self.decode(opts = {})
          mode = opts.fetch(:mode, :acurite_609txc).to_s.to_sym
          raise ArgumentError, "unsupported RTL433 mode #{mode}; supported: #{SUPPORTED_MODES.join(', ')}" unless SUPPORTED_MODES.include?(mode)

          return native_replay(opts) if mode == :native

          freq_obj = opts[:freq_obj] || {}
          rate = opts[:sample_rate] || freq_obj[:iq_rate] || 250_000
          demod = AcuriteIQ.new(rate: rate, threshold: opts.fetch(:threshold, 0.5))
          PWN::SDR::Decoder::Base.run_iq(opts.merge(freq_obj: freq_obj, protocol: 'RTL433',
                                                    sample_rate: rate, demod: demod, fallback: :raise))
        end

        # File-only native catalogue replay: never selects an RF device or reads user config.
        # https://github.com/merbanan/rtl_433
        private_class_method def self.native_replay(opts = {})
          path = File.expand_path(opts.fetch(:file) { raise ArgumentError, 'native replay requires an explicit file' }.to_s)
          raise ArgumentError, 'native replay requires a regular file' unless File.file?(path)
          raise ArgumentError, 'native replay does not accept a live source' if opts[:source] && opts[:source] != :file

          format = opts.fetch(:format, :cu8).to_s
          width = { 'cu8' => 2, 'cs16' => 4, 'cf32' => 8 }[format]
          raise ArgumentError, 'native format must be cu8, cs16 or cf32' unless width
          raise ArgumentError, 'incomplete IQ sample' unless (File.size(path) % width).zero?

          rate = Integer(opts.fetch(:sample_rate, 250_000))
          duration = Float(opts.fetch(:duration, 30))
          raise ArgumentError, 'positive sample_rate and finite duration required' unless rate.positive? && duration.finite? && duration.positive?

          command = [opts.fetch(:executable, 'rtl_433').to_s, '-c', '0', '-s', rate.to_s,
                     '-r', "#{format}:#{path}", '-F', 'json', '-M', 'protocol']
          if opts[:protocols]
            ids = Array(opts[:protocols]).map { |id| Integer(id) }
            raise ArgumentError, 'protocols must contain positive native protocol IDs' if ids.empty? || ids.any? { |id| id <= 0 }

            command.push('-R', '0')
            ids.each { |id| command.push('-R', id.to_s) }
          end
          count = 0
          output = opts.fetch(:output, $stdout)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + duration
          Open3.popen3(*command) do |input, stdout, stderr, worker|
            input.close
            buffers = { stdout => +'', stderr => +'' }
            errors = +''
            begin
              until buffers.empty?
                raise IOError, 'rtl_433 replay cancelled' if opts[:stop]&.call
                raise IOError, 'rtl_433 replay deadline exceeded' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

                ready = IO.select(buffers.keys, nil, nil, 0.05)
                next unless ready

                ready.first.each do |io|
                  chunk = io.read_nonblock(16_384, exception: false)
                  next if chunk == :wait_readable

                  if chunk.nil?
                    raise IOError, 'truncated rtl_433 JSON line' if io == stdout && !buffers[io].empty?

                    buffers.delete(io)
                    next
                  end
                  if io == stderr
                    errors = (errors + chunk)[-16_384..] || (errors + chunk)
                    next
                  end
                  buffers[io] << chunk
                  raise IOError, 'oversized rtl_433 JSON line' if buffers[io].bytesize > 1_048_576

                  while (line = buffers[io].slice!(/.*\n/))
                    data = JSON.parse(line, symbolize_names: true)
                    next unless data.is_a?(Hash) && data[:model]

                    device_protocol = data.delete(:protocol)
                    frame = parse_line(line: JSON.generate(data)).merge(protocol: 'RTL433', device_protocol: device_protocol,
                                                                        backend: 'rtl_433', source: 'iq', mode: :native,
                                                                        decoded: true, integrity: data[:mic] || 'not-reported')
                    encoded = JSON.generate(frame)
                    output&.puts(encoded)
                    File.open(opts[:log_file], 'a') { |log| log.puts(encoded) } if opts[:log_file]
                    opts[:on_frame]&.call(frame)
                    count += 1
                  end
                end
              end
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              raise IOError, 'rtl_433 replay deadline exceeded' unless remaining.positive? && worker.join(remaining)
              raise IOError, "rtl_433 failed: #{errors}" unless worker.value.success?
            ensure
              if worker.alive?
                begin
                  Process.kill('KILL', worker.pid)
                rescue Errno::ESRCH
                  nil
                end
              end
              worker.join
            end
          end
          { protocol: 'RTL433', mode: :native, backend: 'rtl_433', frames: count, source: path }
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj]

          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 250_000).to_i
          proto = 'ISM-433'
          demod = DetectorIQ.new(
            rate: rate, protocol: proto, modulation: 'OOK/ASK/FSK',
            extra: { threshold: 10.0 }
          )
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: demod,
            threshold: 10.0,
            note: 'True-air I/Q path characterizes OOK/FSK bursts; offline rtl_433 JSON via .parse_line.',
            describe: proc { |b|
              { modulation: 'OOK/ASK/FSK', classification: (if b[:duration_ms] < 20
                                                              'keyfob/OOK-short'
                                                            else
                                                              (b[:duration_ms] < 120 ? 'sensor/OOK-packet' : 'FSK-continuous')
                                                            end) }
            }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          h = begin
            JSON.parse(line, symbolize_names: true)
          rescue StandardError
            { unparsed: line }
          end
          out = { protocol: 'RTL433' }.merge(h)
          bits = []
          bits << out[:model].to_s if out[:model]
          bits << "id=#{out[:id]}" if out[:id]
          bits << "ch=#{out[:channel]}" if out[:channel]
          bits << "code=#{out[:code]}" if out[:code]
          bits << "cmd=#{out[:cmd] || out[:button]}" if out[:cmd] || out[:button]
          bits << "temp=#{out[:temperature_C]}C" if out[:temperature_C]
          bits << "rssi=#{out[:rssi]}" if out[:rssi]
          out[:summary] = bits.empty? ? line[0, 120] : bits.join(' ')
          out
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Default :acurite_609txc is the Ruby OOK/PPM implementation.
            # mode: :native runs installed rtl_433 with its enabled device catalogue (OOK/FSK).
            # Native mode is finite FILE replay only: file required, no auto RF/config loading.
            # Native options: format: :cu8/:cs16/:cf32, protocols: [positive native IDs],
            # executable: 'rtl_433', duration: 30 seconds (deadline), stop: callable.
            # Output is per-device native JSON, device_protocol preserves native numeric ID.
            # Individual sensors/integrity depend on installed version; mic absent means not-reported.
            # sample_rate: 250000 default, >=20000; threshold: 0.5 normalized envelope amplitude.
            # Parses ID/status/battery/signed temperature/humidity and checks additive checksum.
            # The Ruby mode checksum is weak, not authentication; use native mode for FSK/other sensors.
            # decode never falls back to a detector; unsupported mode raises ArgumentError.
            # #{self}.detect uses the same source/lifecycle options for energy-only observations.
            # Validate a complete frame and return decoded fields or nil.
            #{self}.parse_frame(bits: 'required - Array of 40 binary digits in transmitted order')
            # Run decode and return its result
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq',
              on_frame: 'optional - callback receiving each emitted Hash',
              output: 'optional - writable IO (default stdout)',
              interactive: 'optional - false disables ENTER input',
              duration: 'optional - finite seconds to run',
              stop: 'optional - callable returning true to stop',
              queue_size: 'optional - bounded pending chunks (default 8)',
              log_file: 'optional - JSONL path or false to disable logging',
              sample_rate: 'optional - sample rate value consumed by #decode',
              source: 'optional - source value consumed by #decode',
              file: 'optional - filesystem path'
            )

            # Run parse line and return its result
            #{self}.parse_line(
              line: 'optional - line value consumed by #parse_line'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
