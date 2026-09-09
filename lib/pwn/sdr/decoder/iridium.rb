# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # IRA protocol decoding from pre-synchronized symbol IQ, plus separate
      # wideband energy observations (.detect). General raw-IQ acquisition and
      # non-IRA message families are not implemented. See the independent RF
      # vectors and BSD protocol-source notice in spec/fixtures/sdr/iridium/.
      module Iridium
        # Streaming I/Q energy/burst demod for Base.run_iq.
        class DemodIQ
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

        # IRA layout reference: muccc/iridium-toolkit bitsparser.py, BSD-2-Clause.
        # See spec/fixtures/sdr/iridium/README.md for source and RF provenance.
        # Accepts canonical differential/Gray bits INCLUDING the downlink UW;
        # extractor RAW records swap each dibit and must be normalized first.
        public_class_method def self.decode_ring_alert(opts = {})
          RingAlert.new.decode(opts[:bits])
        end

        # Deliberately scoped to the IRA family, not a generic RAW-bit decoder.
        class RingAlert
          ACCESS = '001100000011000011110011'
          POLYNOMIAL = 1207
          # Extended BCH(32,21): minimum distance six, bounded radius two.
          # Include the parity bit in the syndrome; never silently ignore it.
          ERROR_SYNDROMES = begin
            positions = (0...32).to_a
            masks = [0] + positions.map { |bit| 1 << bit } + positions.combination(2).map { |a, b| (1 << a) | (1 << b) }
            masks.to_h do |mask|
              value = mask >> 1
              value ^= POLYNOMIAL << (value.bit_length - POLYNOMIAL.bit_length) while value.bit_length >= POLYNOMIAL.bit_length
              [((value << 1) | (mask.to_s(2).count('1') & 1)), mask]
            end.freeze
          end

          def decode(bits)
            raise ArgumentError, 'Expected binary IRA bits with downlink access word' unless bits.is_a?(String) && bits.match?(/\A[01]+\z/) && bits.start_with?(ACCESS)
            raise ArgumentError, 'Truncated IRA header' if bits.length < 120

            @corrected = 0
            header = deinterleave(bits[24, 96], 3).map { |word| check_word(word) }.join
            pages = []
            offset = 120
            ended = false
            13.times do
              raise ArgumentError, 'Truncated IRA paging section' if bits.length < offset + 64

              page = deinterleave(bits[offset, 64], 2).map { |word| check_word(word) }.join
              offset += 64
              if page == '1' * 42
                ended = true
                break
              end
              raise ArgumentError, 'Invalid IRA paging reserved bits' unless page[32, 2] == '00' && page[39, 3] == '000'

              pages << { tmsi: page[0, 32].to_i(2), msc_id: page[34, 5].to_i(2) }
              break if pages.length == 12
            end
            raise ArgumentError, 'Missing IRA paging terminator' unless ended || pages.length == 12

            x, y, z = [13, 25, 37].map do |start|
              value = header[start, 12].to_i(2)
              value >= 2048 ? value - 4096 : value
            end
            {
              protocol: 'IRIDIUM', frame_type: 'IRA', decoded: true,
              integrity: 'BCH(31,21)+parity', corrected_bits: @corrected,
              sat: header[0, 7].to_i(2), beam: header[7, 6].to_i(2),
              xyz: [x, y, z], latitude: Math.atan2(z, Math.sqrt((x * x) + (y * y))) * 180 / Math::PI,
              longitude: Math.atan2(y, x) * 180 / Math::PI,
              radius_km: Math.sqrt((x * x) + (y * y) + (z * z)) * 4,
              interval: header[49, 7].to_i(2), broadcast_slot: header[56] == '0' ? 1 : 4,
              eip: header[57].to_i, downlink_subband: header[58, 5].to_i(2), pages: pages,
              summary: "IRIDIUM IRA sat=#{header[0, 7].to_i(2)} beam=#{header[7, 6].to_i(2)}"
            }
          end

          private

          def deinterleave(bits, count)
            symbols = bits.scan(/../).map(&:reverse).reverse
            Array.new(count) { |column| symbols.each_slice(count).map { |row| row[column] }.join }
          end

          def remainder(word)
            value = word
            value ^= POLYNOMIAL << (value.bit_length - POLYNOMIAL.bit_length) while value.bit_length >= POLYNOMIAL.bit_length
            value
          end

          def check_word(bits)
            word = bits.to_i(2)
            syndrome = (remainder(word >> 1) << 1) | (word.to_s(2).count('1') & 1)
            mask = ERROR_SYNDROMES[syndrome]
            raise ArgumentError, 'Uncorrectable IRA BCH/parity word' unless mask

            @corrected += mask.to_s(2).count('1')
            (word ^ mask).to_s(2).rjust(32, '0')[0, 21]
          end
        end

        # Input is already channelized, carrier/timing synchronized, one complex
        # sample per symbol at 25 ksym/s. This is NOT a wideband IQ receiver.
        class RingAlertSymbolsIQ
          GRAY = %w[00 01 11 10].freeze

          def initialize
            @previous = 0
            @bits = +''
          end

          def feed_iq(samples, rate: nil)
            raise ArgumentError, 'IRA symbol IQ requires 25000 samples/s' if rate && rate.to_i != 25_000

            samples.each_slice(2) do |i, q|
              quadrant = ((Math.atan2(q, i) / (Math::PI / 2)) - 0.5).round % 4
              @bits << GRAY[(quadrant - @previous) % 4]
              @previous = quadrant
              start = @bits.index(RingAlert::ACCESS)
              unless start
                @bits = @bits[-24, 24] if @bits.length > 24
                next
              end
              @bits = @bits[start..]
              next if @bits.length < 184 || ((@bits.length - 120) % 64).positive?

              begin
                frame = RingAlert.new.decode(@bits)
              rescue ArgumentError => e
                @bits = @bits[2..] unless e.message == 'Truncated IRA paging section' && @bits.length < 888
                next
              end
              @bits.clear
              yield frame.merge(source: 'symbol-iq', capability: 'IRA-synchronized-symbols', sample_rate: 25_000)
            end
          end

          def flush
            @bits.clear
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Iridium.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          raise NotImplementedError, 'Wideband IQ protocol decoding is not implemented; only mode: :ira_symbols_iq (synchronized IRA symbols) is supported. Use .detect for energy observations.' unless opts[:mode] == :ira_symbols_iq

          rate = opts[:sample_rate] || 25_000
          raise ArgumentError, 'IRA symbol IQ requires 25000 samples/s' unless rate == 25_000

          explicit_source = opts[:source].respond_to?(:read) || (opts[:file] && [nil, :file].include?(opts[:source]))
          raise ArgumentError, 'Explicit file or readable symbol IQ source required; RF acquisition is not supported' unless explicit_source

          PWN::SDR::Decoder::Base.run_iq(
            **opts, freq_obj: opts[:freq_obj] || {}, protocol: 'IRIDIUM',
                    sample_rate: rate, demod: RingAlertSymbolsIQ.new,
                    note: 'IRA only: pre-synchronized complex symbols; no wideband acquisition or RS message families.'
          )
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj] || {}

          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_000_000).to_i
          proto = 'IRIDIUM'
          demod = DemodIQ.new(
            rate: rate, protocol: proto, modulation: 'DE-QPSK',
            extra: { threshold: 7.0 }
          )
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: demod,
            threshold: 7.0,
            note: '25 kbit/s DE-QPSK — true-air I/Q path reports burst timing/energy.',
            describe: proc { |_b| { modulation: 'DE-QPSK', symbol_rate: 25_000 } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'IRIDIUM' }
          out[:frame_type] = ::Regexp.last_match(1) if line =~ /^([A-Z]{3}):/
          out[:sat]        = ::Regexp.last_match(1) if line =~ /sat:(\d+)/
          out[:beam]       = ::Regexp.last_match(1) if line =~ /beam:(\d+)/
          out[:pos]        = ::Regexp.last_match(1) if line =~ /pos=\(([^)]+)\)/
          out[:ra_id]      = ::Regexp.last_match(1) if line =~ /ric:(\d+)/
          out[:summary]    = "IRIDIUM #{out[:frame_type]} sat=#{out[:sat]} beam=#{out[:beam]}"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Decode IRA only from already channelized, carrier/timing-synchronized
            # symbol IQ. Not raw wideband IQ; no LCW, RS, voice or messaging support.
            #{self}.decode(
              mode: 'required - :ira_symbols_iq; default :iq raises NotImplementedError',
              source: 'required - :file or readable IO; never automatically acquires RF',
              file: 'optional - path required for file source',
              sample_rate: 'optional - exactly 25000 complex symbol samples/s',
              freq_obj: 'optional - metadata Hash; no radio control',
              iq_format: 'optional - :cs16 recommended for the supplied fixtures',
              on_frame: 'optional - decoded IRA Hash callback',
              interactive: 'optional - false for file replay',
              log_file: 'optional - path or false'
            )
            # Decode a canonical downlink IRA bit frame, with BCH/parity checks.
            #{self}.decode_ring_alert(
              bits: 'required - binary String including access word; canonical RWA order'
            )
            # Run detection only (not protocol decoding).
            #{self}.detect(
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
