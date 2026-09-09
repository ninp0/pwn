# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby combined pager decoder for the mixed-protocol `pager_all`
      # band plan. Feeds every incoming 48 kHz audio chunk to BOTH the
      # native POCSAG and FLEX demodulators concurrently; whichever locks
      # emits messages. No `multimon-ng`, no `sox`.
      module Pager
        # Composite demodulator wrapping POCSAG::Demod + Flex::Demod.
        class Demod
          def initialize(rate: 48_000)
            @pocsag = PWN::SDR::Decoder::POCSAG::Demod.new(rate: rate)
            @flex   = PWN::SDR::Decoder::Flex::Demod.new(rate: rate)
          end

          def flush(&)
            @pocsag.flush(&)
            @flex.flush(&) if @flex.respond_to?(:flush)
          end

          def feed(samples, &)
            @pocsag.feed(samples.dup, &)
            @flex.feed(samples, &)
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Pager.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        # Energy detection only; does not identify or decode Pager payloads.
        # Supported Method Parameters::
        # Pager.detect(freq_obj: Hash, threshold: 8.0, on_frame: Proc)
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(
                              protocol: 'PAGER',
                              note: 'Energy detection only; no protocol payload decoding.',
                              describe: proc { |_burst| { event: 'detection', capability: 'energy-detection', decoded: false } }
                            ))
        end

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          # Prefer true-air I/Q (FM-demod → existing audio demod) when the
          # operator asks for a source/file or sets freq_obj[:iq_source].
          # Otherwise keep the GQRX 48 kHz UDP audio path (run_native).
          want_iq = opts[:source] || opts[:file] || freq_obj[:iq_source] || freq_obj[:iq_file]
          if want_iq
            PWN::SDR::Decoder::Base.run_iq(
              **opts,
              fallback: :raise,
              freq_obj: freq_obj,
              protocol: 'PAGER',
              demod: Demod.new(rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 240_000).to_i),
              sample_rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 240_000).to_i,
              source: opts[:source],
              file: opts[:file],
              fm_demod: true,
              note: 'PAGER true-air: FM-demod I/Q then native bit recovery; missing I/Q raises (use .detect for energy only).'
            )
          else
            PWN::SDR::Decoder::Base.run_native(
              **opts,
              freq_obj: freq_obj,
              protocol: 'PAGER',
              demod: Demod.new(rate: (opts[:rate] || 48_000).to_i)
            )
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
              on_frame: 'optional - callback receiving each emitted Hash',
              output: 'optional - writable IO (default stdout)',
              interactive: 'optional - false disables ENTER input',
              duration: 'optional - finite seconds to run',
              stop: 'optional - callable returning true to stop',
              queue_size: 'optional - bounded pending chunks (default 8)',
              log_file: 'optional - JSONL path or false to disable logging',
              source: 'optional - source value consumed by #decode',
              file: 'optional - filesystem path',
              sample_rate: 'optional - sample rate value consumed by #decode'
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
