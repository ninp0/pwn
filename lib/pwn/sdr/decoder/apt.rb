# frozen_string_literal: true

require 'tempfile'

module PWN
  module SDR
    module Decoder
      # Pure-Ruby NOAA APT (Automatic Picture Transmission) decoder for the
      # 137 MHz polar-orbiting weather satellites (NOAA-15/18/19).
      #
      # APT is a 2400 Hz AM subcarrier inside a ~34 kHz-wide FM downlink
      # carrying two 909-pixel image channels at 2 lines/second (2080
      # words/line). This module envelope-demodulates the 2400 Hz carrier
      # from audio, resamples to 4160 words/sec with continuous phase, and
      # aligns the initial line on a Sync-A correlation candidate. Fixed-rate
      # rows update a bounded rolling P5 PGM; there is no drift tracking or
      # satellite identification. Line contrast is normalized independently.
      # No `sox`, no `noaa-apt`.
      module APT
        WORDS_PER_LINE = 2080
        LINES_PER_SEC  = 2
        WORD_RATE      = WORDS_PER_LINE * LINES_PER_SEC # 4160 Hz
        # Sync-A: 7 cycles of 1040 Hz square = 1 1 0 0 repeated 7 times
        SYNC_A = (Array.new(4, 0) + ([1, 1, 0, 0] * 7) + Array.new(7, 0)).freeze

        # Streaming APT demodulator fed by Base.run_native.
        class Demod
          def initialize(rate: 48_000, out_path: nil, max_lines: 1024)
            @rate = rate.to_f
            raise ArgumentError, 'rate must be finite and positive' unless @rate.finite? && @rate.positive?
            raise ArgumentError, 'max_lines must be positive' unless max_lines.to_i.positive?

            @env_win = [(@rate / 2400.0).round, 1].max
            @envelope = Array.new(@env_win, 0.0)
            @env_index = 0
            @env_sum = 0.0
            @phase = 0.0
            @pgm_path = out_path || "/tmp/apt_#{Time.now.strftime('%Y%m%d_%H%M%S')}.pgm"
            @max_lines = max_lines.to_i
            @rows = []
            @word_buf = []
            @lines = 0
            @synced = false
          end

          def feed(samples, &emit)
            samples.each do |sample|
              value = sample.abs
              @env_sum += value - @envelope[@env_index]
              @envelope[@env_index] = value
              @env_index = (@env_index + 1) % @env_win
              @phase += WORD_RATE
              while @phase >= @rate
                @phase -= @rate
                @word_buf << (@env_sum / @env_win)
                extract_lines(&emit) if @word_buf.length >= WORDS_PER_LINE
              end
            end
          end

          def finish(&)
            extract_lines(&)
            @word_buf.clear
            { path: @pgm_path, width: WORDS_PER_LINE, height: @rows.length, lines: @lines }
          end

          private

          def extract_lines
            unless @synced
              return if @word_buf.length < WORDS_PER_LINE

              offset = sync_offset(@word_buf)
              unless offset
                @word_buf.shift(@word_buf.length - SYNC_A.length)
                return
              end
              @word_buf.shift(offset)
              @synced = true
            end
            while @word_buf.length >= WORDS_PER_LINE
              row = @word_buf.shift(WORDS_PER_LINE)
              lo, hi = row.minmax
              span = hi - lo
              span = 1.0 unless span.positive?
              @rows << row.map { |v| (((v - lo) / span) * 255).clamp(0, 255).round }.pack('C*')
              @rows.shift while @rows.length > @max_lines
              @lines += 1
              write_pgm
              next unless block_given?

              yield(
                protocol: 'NOAA-APT', event: 'line',
                lines: @lines, seconds: @lines.to_f / LINES_PER_SEC,
                width: WORDS_PER_LINE, height: @rows.length,
                first_line: @lines - @rows.length + 1,
                pgm: @pgm_path,
                summary: "APT line #{@lines} (#{@lines.to_f / LINES_PER_SEC}s) → #{@pgm_path}"
              )
            end
          end

          def sync_offset(row)
            best_off = nil
            best_cor = 0.8
            (0..(row.length - SYNC_A.length)).each do |o|
              window = row[o, SYNC_A.length]
              lo, hi = window.minmax
              next if hi - lo < 0.01

              mid = (hi + lo) / 2.0
              matches = SYNC_A.each_with_index.count { |s, i| (window[i] > mid ? 1 : 0) == s }
              cor = matches.to_f / SYNC_A.length
              if cor > best_cor
                best_cor = cor
                best_off = o
              end
            end
            best_off
          end

          def write_pgm
            Tempfile.create(['apt', '.pgm'], File.dirname(@pgm_path)) do |file|
              file.binmode
              file.write("P5\n#{WORDS_PER_LINE} #{@rows.length}\n255\n")
              @rows.each { |row| file.write(row) }
              file.close
              File.rename(file.path, @pgm_path)
            end
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::APT.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Energy detection only; does not identify or decode APT payloads.
        # Supported Method Parameters::
        # APT.detect(freq_obj: Hash, threshold: 8.0, on_frame: Proc)
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(
                              protocol: 'APT',
                              note: 'Energy detection only; no protocol payload decoding.',
                              describe: proc { |_burst| { event: 'detection', capability: 'energy-detection', decoded: false } }
                            ))
        end

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          want_iq = opts[:source] || opts[:file] || freq_obj[:iq_source] || freq_obj[:iq_file]
          rate = if want_iq
                   opts[:sample_rate] || freq_obj[:iq_rate] || 48_000
                 else
                   opts[:rate] || 48_000
                 end
          demod = Demod.new(rate: rate, out_path: opts[:out_path], max_lines: opts.fetch(:max_lines, 1024))
          common = opts.merge(freq_obj: freq_obj, protocol: 'NOAA-APT', demod: demod)
          if want_iq
            PWN::SDR::Decoder::Base.run_iq(common.merge(
                                             sample_rate: rate.to_i, fm_demod: true, fallback: :raise,
                                             note: 'NOAA APT: FM-demod I/Q then 2400 Hz AM envelope → rolling PGM.'
                                           ))
          else
            PWN::SDR::Decoder::Base.run_native(common.merge(rate: rate.to_i))
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Detect energy only (not protocol payloads); accepts Base runner controls.
            #{self}.detect(freq_obj: {}, threshold: 8.0, on_frame: nil)
            # Run decode and return its result
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq',
              source: 'optional - source value consumed by #decode',
              file: 'optional - filesystem path',
              out_path: 'optional - out path value consumed by #decode',
              sample_rate: 'optional - I/Q audio rate Hz (default 48000 or freq_obj[:iq_rate])',
              rate: 'optional - native audio rate Hz (default 48000)',
              max_lines: 'optional - rolling image height limit (default 1024)',
              on_frame: 'optional - callback receiving each line Hash after atomic PGM update',
              output: 'optional - IO for immediate JSONL events (default stdout)',
              interactive: 'optional - stop on ENTER (default true)',
              duration: 'optional - maximum stream seconds',
              stop: 'optional - callable cancellation predicate',
              queue_size: 'optional - bounded Base input queue size',
              log_file: 'optional - JSONL log path or false to disable'
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
