# frozen_string_literal: true

require 'tempfile'
require 'json'
require 'fileutils'

module PWN
  module SDR
    module Decoder
      # Protocol frames via .decode; energy observations only via .detect.
      module RFID
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

        # EM4100 Manchester RF/64, RF/32 and RF/16 at a configured carrier.
        # Frame layout and polarity: https://www.priority1design.com.au/em4100_protocol.html
        # Only ASK Manchester is supported; not PSK, biphase, ISO14443 or EPC Gen2.
        class EM4100IQ
          def initialize(rate:, carrier_hz: 125_000, clocks_per_bit: 64, threshold: 0.5)
            raise ArgumentError, 'EM4100 clocks_per_bit must be 16, 32 or 64' unless [16, 32, 64].include?(clocks_per_bit)

            @rate = Float(rate)
            @half = @rate * clocks_per_bit / (2.0 * Float(carrier_hz))
            raise ArgumentError, 'EM4100 requires at least four samples per half bit' unless @half.finite? && @half >= 4

            @threshold = Float(threshold)**2
            @level = nil
            @remaining = 0
            @symbols = []
          end

          def feed_iq(samples, rate: nil)
            raise ArgumentError, 'sample rate changed midstream' if rate && (rate.to_f - @rate).abs.positive?
            raise ArgumentError, 'interleaved IQ pairs required' unless samples.length.even?

            samples.each_slice(2) do |i, q|
              level = ((i * i) + (q * q)) >= @threshold ? 1 : 0
              if level != @level
                @level = level
                @remaining = @half / 2.0
              end
              @remaining -= 1
              next if @remaining.positive?

              @remaining += @half
              @symbols << level
              @symbols.shift if @symbols.length > 128
              next unless @symbols.length == 128
              next unless @symbols.each_slice(2).all? { |a, b| a != b }

              bits = @symbols.each_slice(2).map(&:last)
              [bits, bits.map { |bit| bit ^ 1 }].each do |candidate|
                frame = RFID.parse_frame(bits: candidate)
                yield frame if frame && block_given?
              end
            end
          end

          def flush
            @symbols.clear # Never pad a truncated frame into a tag.
          end
        end

        public_class_method def self.parse_frame(opts = {})
          bits = opts[:bits]
          return nil unless bits.is_a?(Array) && bits.length == 64 && bits.all? { |b| [0, 1].include?(b) }
          return nil unless bits.first(9) == [1] * 9 && bits.last.zero?

          rows = bits[9, 50].each_slice(5).to_a
          return nil unless rows.all? { |row| row.sum.even? }
          return nil unless 4.times.all? { |column| (rows.sum { |row| row[column] } + bits[59 + column]).even? }

          uid = rows.map { |row| row.first(4).join.to_i(2).to_s(16) }.join.upcase
          { protocol: 'RFID', mode: :em4100, source: 'iq', decoded: true,
            integrity: 'row-and-column-even-parity', uid: uid, version: uid[0, 2].to_i(16),
            identifier: uid[2, 8], summary: "EM4100 UID=#{uid}" }
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RFID.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        SUPPORTED_MODES = %i[em4100 fdxb_pm3].freeze
        DemodIQ = EM4100IQ

        # Never silently downgrade decode to energy detection.
        public_class_method def self.decode(opts = {})
          mode = opts.fetch(:mode, :em4100).to_s.to_sym
          raise ArgumentError, "unsupported RFID mode #{mode}; supported: #{SUPPORTED_MODES.join(', ')}" unless SUPPORTED_MODES.include?(mode)

          return fdxb_replay(opts) if mode == :fdxb_pm3

          freq_obj = opts[:freq_obj] || {}
          rate = opts[:sample_rate] || freq_obj[:iq_rate] || 250_000
          demod = EM4100IQ.new(rate: rate, carrier_hz: opts.fetch(:carrier_hz, 125_000),
                               clocks_per_bit: opts.fetch(:clocks_per_bit, 64), threshold: opts.fetch(:threshold, 0.5))
          PWN::SDR::Decoder::Base.run_iq(opts.merge(freq_obj: freq_obj, protocol: 'RFID',
                                                    sample_rate: rate, demod: demod, fallback: :raise))
        end

        # Native offline demodulation of PM3 signed amplitude traces, NOT raw SDR IQ.
        # https://github.com/RfidResearchGroup/proxmark3
        private_class_method def self.fdxb_replay(opts = {})
          path = opts.fetch(:file) { raise ArgumentError, 'FDX-B requires an explicit PM3 amplitude file' }.to_s
          raise ArgumentError, 'FDX-B requires a regular PM3 amplitude file' unless File.file?(path) && File.size(path) <= 4_000_000
          raise ArgumentError, 'FDX-B PM3 replay cannot accept live sources or IQ format/rate' if opts[:source] || opts[:format] || opts[:sample_rate]

          duration = Float(opts.fetch(:duration, 30))
          raise ArgumentError, 'finite positive duration required' unless duration.finite? && duration.positive?

          # Validate the text representation and copy to a command-safe generated path.
          data = File.read(path)
          raise ArgumentError, 'PM3 file must contain signed integer amplitude samples' unless data.lines.all? { |line| line.strip.match?(/\A-?\d+\z/) }

          Tempfile.create(['pwn-fdxb-', '.pm3']) do |trace|
            Tempfile.create('pwn-fdxb-output-') do |output|
              trace.write(data)
              trace.flush
              pid = Process.spawn(opts.fetch(:executable, 'proxmark3').to_s, '--incognito', '-c',
                                  "data load -f #{trace.path}; lf fdxb demod", in: File::NULL, out: output, err: output)
              deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + duration
              begin
                loop do
                  waited = Process.waitpid2(pid, Process::WNOHANG)
                  if waited
                    pid = nil
                    raise IOError, 'proxmark3 offline decoder failed' unless waited.last.success?

                    break
                  end
                  raise IOError, 'proxmark3 replay cancelled' if opts[:stop]&.call
                  raise IOError, 'proxmark3 replay deadline exceeded' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
                  raise IOError, 'oversized proxmark3 output' if output.size > 1_048_576

                  sleep 0.01
                end
              ensure
                if pid
                  begin
                    Process.kill('KILL', pid)
                    Process.waitpid(pid)
                  rescue Errno::ESRCH, Errno::ECHILD
                    nil
                  end
                end
              end
              output.rewind
              text = output.read(1_048_577)
              raise IOError, 'oversized proxmark3 output' if text.bytesize > 1_048_576
              raise IOError, 'proxmark3 did not load the amplitude trace' unless text.match?(/loaded [\d,]+ samples/)

              frames = []
              if text.match?(/CRC-16\.+\s+0x[0-9A-Fa-f]+ \( ok \)/)
                identity = text.match(/Animal ID\.+\s+(\d{3})-(\d{12})/)
                raise IOError, 'unrecognized proxmark3 FDX-B identity output' unless identity

                frame = { protocol: 'RFID', mode: :fdxb_pm3, source: 'amplitude', backend: 'proxmark3',
                          decoded: true, integrity: 'crc16', country_code: identity[1].to_i,
                          national_id: identity[2].to_i, uid: "#{identity[1]}-#{identity[2]}",
                          animal: text.match?(/Animal bit set\?\.+ True/),
                          data_block: text.match?(/Data block\?\.+ True/),
                          summary: "FDX-B ISO11784/11785 UID=#{identity[1]}-#{identity[2]}" }
                frames << frame
                encoded = JSON.generate(frame)
                opts.fetch(:output, $stdout)&.puts(encoded)
                File.open(opts[:log_file], 'a') { |log| log.puts(encoded) } if opts[:log_file]
                opts[:on_frame]&.call(frame)
              end
              { protocol: 'RFID', mode: :fdxb_pm3, backend: 'proxmark3', frames: frames.length }
            end
          end
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          band = if hz < 1_000_000 then 'LF'
                 elsif hz.between?(13_000_000, 14_000_000) then 'HF'
                 else 'UHF'
                 end

          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_000_000).to_i
          proto = "RFID-#{band}"
          demod = DetectorIQ.new(
            rate: rate, protocol: proto, modulation: 'ASK/load-mod',
            extra: { threshold: 6.0 }
          )
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: demod,
            threshold: 6.0,
            note: 'True-air I/Q path reports reader-carrier and tag-backscatter bursts by band.',
            describe: proc { |b| { band: b[:band], modulation: 'ASK/load-mod', classification: b[:classification] } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'RFID' }
          out[:uid]  = ::Regexp.last_match(1).delete(' ') if line =~ /UID[:=]?\s*((?:[0-9A-Fa-f]{2}\s*){4,10})/
          out[:epc]  = ::Regexp.last_match(1) if line =~ /EPC[:=]?\s*([0-9A-Fa-f]+)/
          out[:atqa] = ::Regexp.last_match(1) if line =~ /ATQA[:=]?\s*([0-9A-Fa-f ]+)/
          out[:sak]  = ::Regexp.last_match(1) if line =~ /SAK[:=]?\s*([0-9A-Fa-f]+)/
          out[:tag]  = ::Regexp.last_match(1) if line =~ /(EM4\w+|HID\w*|Mifare\w*|NTAG\w*|ISO\s?\d+)/i
          out[:summary] = "RFID #{out[:tag]} UID=#{out[:uid] || out[:epc]}".squeeze(' ')
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Default :em4100 is ASK Manchester, not PSK/biphase/HF/UHF.
            # :fdxb_pm3 uses installed proxmark3 offline demodulation of ISO11784/11785 FDX-B.
            # file: explicit .pm3 signed integer AMPLITUDE trace, not SDR IQ; no hardware access.
            # Valid CRC16 required. Returns national/country ID, animal and data-block flags.
            # executable: 'proxmark3'; duration: 30s deadline; stop: callable; output/on_frame/log_file.
            # PM3 mode is finite offline replay; no ISO14443/ISO15693/EPC Gen2 coverage.
            # carrier_hz: 125000 default; clocks_per_bit: 64 default, or 32/16.
            # threshold: 0.5 default, normalized envelope amplitude; tune to the received levels.
            # sample_rate must provide >=4 samples/half-bit; default 250000.
            # Recovers polarity/timing at transitions; validates all row/column parity and stop.
            # decode never falls back to a detector; unsupported mode raises ArgumentError.
            # #{self}.detect uses the same source/lifecycle options for energy-only observations.
            # Validate a complete frame and return decoded fields or nil.
            #{self}.parse_frame(bits: 'required - Array of 64 binary digits in transmitted order')
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
