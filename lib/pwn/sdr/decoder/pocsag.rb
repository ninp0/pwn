# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby POCSAG (CCIR Radiopaging Code No. 1) decoder.
      #
      # GQRX supplies NBFM-discriminator audio on its 48 kHz UDP tap; for a
      # 2-FSK pager channel that is already an NRZ baseband whose sign
      # encodes the bit. This module NRZ-slices at 512/1200/2400 baud,
      # locks onto the 32-bit Frame Sync Codeword (0x7CD215D8), then walks
      # each 8-frame batch of BCH(31,21)+parity codewords, extracting
      # address (RIC/capcode + function bits) and message codewords
      # (numeric BCD or 7-bit ASCII). No `multimon-ng`, no `sox`.
      module POCSAG
        FSC       = 0x7CD215D8
        IDLE_CW   = 0x7A89C197
        BAUDS     = [1200, 512, 2400].freeze
        BCD_TABLE = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', 'U', ' ', '-', ')', '('].freeze

        FUNCTION_DESC = {
          0 => 'Numeric (Tone/A)',
          1 => 'Tone only (B)',
          2 => 'Tone only (C)',
          3 => 'Alphanumeric (D)'
        }.freeze

        # Incremental framing retains partial codewords and messages across
        # transport chunks and batch sync words. A terminator emits immediately.
        class BitStream
          def initialize(baud:)
            @baud = baud
            @bits = []
            @word_index = nil
            @pending = nil
          end

          def feed(bits, &emit)
            @bits.concat(bits)
            loop do
              if @word_index.nil? || @word_index == 16
                idx = DSP.find_sync(bits: @bits, pattern: FSC, width: 32, max_err: 2)
                unless idx
                  @bits.shift([@bits.length - 31, 0].max)
                  break
                end
                @bits.shift(idx + 32)
                @word_index = 0
              end
              break if @bits.length < 32

              cw = DSP.bits_to_int(bits: @bits.shift(32))
              cw = POCSAG.correct_word(word: cw)
              unless cw
                @pending = nil
                @word_index += 1
                next
              end
              if cw == IDLE_CW
                emit_pending(&emit)
              elsif cw.nobits?(0x80000000)
                emit_pending(&emit)
                @pending = { ric: (((cw >> 13) & 0x3FFFF) << 3) | (@word_index / 2),
                             func: (cw >> 11) & 3, msg_words: [] }
              elsif @pending
                @pending[:msg_words] << ((cw >> 11) & 0xFFFFF)
              end
              @word_index += 1
            end
          end

          def flush(&)
            @pending = nil unless @bits.empty?
            return unless @pending

            emit_pending(&)
          end

          private

          def emit_pending
            return unless @pending

            yield POCSAG.assemble(pending: @pending, baud: @baud)
            @pending = nil
          end
        end

        # Stateful filters and clocks for each candidate baud; inverted bits
        # have independent framing history, not concatenated polarity trials.
        class Demod
          def initialize(rate: 48_000)
            @streams = BAUDS.map do |baud|
              [Bluetooth::SymbolStream.new(rate: rate, baud: baud),
               BitStream.new(baud: baud), BitStream.new(baud: baud)]
            end
          end

          def feed(samples, &emit)
            @streams.each do |slicer, normal, inverted|
              bits = slicer.feed(samples)
              normal.feed(bits, &emit)
              inverted.feed(bits.map { |b| b ^ 1 }, &emit)
            end
          end

          def flush(&emit)
            @streams.each do |_, normal, inverted|
              normal.flush(&emit)
              inverted.flush(&emit)
            end
          end
        end

        # Supported Method Parameters::
        # carry = PWN::SDR::Decoder::POCSAG.decode_bits(bits: [...], baud: 1200) { |msg| ... }
        # Returns the trailing (unconsumed) bits so the caller can prepend
        # them to the next chunk for streaming continuity.

        # Extended BCH syndrome includes the overall even parity bit.
        private_class_method def self.word_syndrome(opts = {})
          word = opts[:word]
          remainder = word >> 1
          30.downto(10) { |i| remainder ^= 0x769 << (i - 10) if remainder[i] == 1 }
          (remainder << 1) | (word.digits(2).sum & 1)
        end

        CORRECTION_MASKS = begin
          masks = { 0 => 0 }
          32.times do |i|
            masks[word_syndrome(word: 1 << i)] = 1 << i
            ((i + 1)...32).each do |j|
              mask = (1 << i) | (1 << j)
              masks[word_syndrome(word: mask)] = mask
            end
          end
          masks.freeze
        end

        # Correct up to two errors across BCH(31,21) and its parity bit.
        # Beyond the correction radius, rejection is not guaranteed (as with
        # any bounded-distance decoder); three-bit errors are detectable.
        public_class_method def self.correct_word(opts = {})
          word = opts[:word]
          return nil unless word.is_a?(Integer) && word.between?(0, 0xFFFFFFFF)

          mask = CORRECTION_MASKS[word_syndrome(word: word)]
          mask ? word ^ mask : nil
        end

        # Validate BCH(31,21) plus even parity without changing the word.
        public_class_method def self.valid_word?(opts = {})
          word = opts[:word]
          return false unless word.is_a?(Integer) && word.between?(0, 0xFFFFFFFF)
          return false unless word.digits(2).sum.even?

          remainder = word >> 1
          30.downto(10) { |i| remainder ^= 0x769 << (i - 10) if remainder[i] == 1 }
          remainder.zero?
        end

        public_class_method def self.decode_bits(opts = {})
          bits = opts[:bits] || []
          baud = opts[:baud]
          i = 0
          pending = nil
          flush = proc do
            yield assemble(pending: pending, baud: baud) if pending && block_given?
            pending = nil
          end
          loop do
            idx = PWN::SDR::Decoder::DSP.find_sync(bits: bits, pattern: FSC, width: 32, max_err: 2, from: i)
            break unless idx

            i = idx + 32
            # One batch = 8 frames × 2 codewords × 32 bits = 512 bits
            8.times do |frame|
              2.times do
                break if i + 32 > bits.length

                cw = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[i, 32])
                i += 32
                cw = correct_word(word: cw)
                unless cw
                  pending = nil
                  next
                end
                if cw == IDLE_CW
                  flush.call
                  next
                end
                next if cw == FSC

                if cw.nobits?(0x80000000)
                  flush.call
                  addr18 = (cw >> 13) & 0x3FFFF
                  func   = (cw >> 11) & 0x3
                  ric    = (addr18 << 3) | frame
                  pending = { ric: ric, func: func, msg_words: [] }
                elsif pending
                  pending[:msg_words] << ((cw >> 11) & 0xFFFFF)
                end
              end
            end
          end
          pending = nil if i < bits.length
          flush.call
          tail_from = [bits.length - 576, 0].max
          bits[tail_from..] || []
        end

        # Supported Method Parameters::
        # h = PWN::SDR::Decoder::POCSAG.assemble(pending: {ric:,func:,msg_words:}, baud: 1200)

        public_class_method def self.assemble(opts = {})
          pending = opts[:pending]
          baud    = opts[:baud]
          return {} unless pending

          words = pending[:msg_words] || []
          func  = pending[:func]
          type, text =
            if words.empty?
              ['Tone', nil]
            elsif func == 3
              ['Alpha', alpha_decode(words: words)]
            else
              ['Numeric', numeric_decode(words: words)]
            end
          out = {
            protocol: 'POCSAG',
            baud: baud,
            address: pending[:ric],
            capcode: pending[:ric].to_s.rjust(7, '0'),
            function: func,
            function_desc: FUNCTION_DESC[func] || 'Unknown',
            type: type,
            message: text
          }.compact
          summary = ["POCSAG#{baud}", "RIC=#{out[:capcode]}", "F#{func}(#{out[:function_desc]})"]
          summary << "#{type}: #{text}" if text
          out[:summary] = summary.join(' ')
          out
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::POCSAG.numeric_decode(words: [Integer, ...])

        public_class_method def self.numeric_decode(opts = {})
          words = opts[:words] || []
          out = +''
          words.each do |w|
            5.times do |d|
              nib = (w >> (16 - (d * 4))) & 0xF
              # POCSAG BCD nibbles are bit-reversed within each 4-bit group
              rev = ((nib & 1) << 3) | ((nib & 2) << 1) | ((nib & 4) >> 1) | ((nib & 8) >> 3)
              out << BCD_TABLE[rev]
            end
          end
          out.gsub(/ +$/, '')
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::POCSAG.alpha_decode(words: [Integer, ...])

        public_class_method def self.alpha_decode(opts = {})
          words = opts[:words] || []
          bitstream = []
          words.each do |w|
            19.downto(0) { |b| bitstream << ((w >> b) & 1) }
          end
          out = +''
          bitstream.each_slice(7) do |ch|
            break if ch.length < 7

            # 7-bit ASCII, LSB first within each character
            code = ch.each_with_index.sum { |b, i| b << i }
            next if code.zero? || code == 0x03 || code == 0x17

            out << (code.between?(0x20, 0x7E) ? code.chr : '.')
          end
          out.strip
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::POCSAG.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        # Energy detection only; does not identify or decode POCSAG payloads.
        # Supported Method Parameters::
        # POCSAG.detect(freq_obj: Hash, threshold: 8.0, on_frame: Proc)
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(
                              protocol: 'POCSAG',
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
              protocol: 'POCSAG',
              demod: Demod.new(rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 240_000).to_i),
              sample_rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 240_000).to_i,
              source: opts[:source],
              file: opts[:file],
              fm_demod: true,
              note: 'POCSAG true-air: FM-demod I/Q then native bit recovery; missing I/Q raises (use .detect for energy only).'
            )
          else
            PWN::SDR::Decoder::Base.run_native(
              **opts,
              freq_obj: freq_obj,
              protocol: 'POCSAG',
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
            # Correct up to two BCH/parity errors; nil if no codeword is within two flips.
            #{self}.correct_word(word: 'required - unsigned 32-bit POCSAG codeword including parity')
            # Detect energy only (not protocol payloads); accepts Base runner controls.
            #{self}.detect(freq_obj: {}, threshold: 8.0, on_frame: nil)
            # Verify BCH and parity without correcting errors.
            #{self}.valid_word?(word: 'required - unsigned 32-bit POCSAG codeword including parity')

            # Run decode bits and return its result
            #{self}.decode_bits(
              bits: 'optional - bits value consumed by #decode_bits (defaults to [])',
              baud: 'optional - baud value consumed by #decode_bits'
            )

            # Run assemble and return its result
            #{self}.assemble(
              pending: 'optional - pending value consumed by #assemble',
              baud: 'optional - baud value consumed by #assemble'
            )

            # Run numeric decode and return its result
            #{self}.numeric_decode(
              words: 'optional - words value consumed by #numeric_decode (defaults to [])'
            )

            # Run alpha decode and return its result
            #{self}.alpha_decode(
              words: 'optional - words value consumed by #alpha_decode (defaults to [])'
            )

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
