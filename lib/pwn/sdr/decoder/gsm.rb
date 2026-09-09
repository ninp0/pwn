# frozen_string_literal: true

require 'ffi'
require 'rbconfig'

module PWN
  module SDR
    module Decoder
      # GSM SCH IQ/channel-bit decoding (.decode) and FCCH observations (.detect).
      # Channelized GMSK IQ is synchronized and differentially demodulated before
      # convolutional/CRC10 verification and BSIC/frame-number extraction.
      # Multipath equalization, BCCH/CCCH and traffic decoding are unsupported.
      module GSM
        SYMBOL_RATE = 3_250_000.0 / 12
        FCCH_TONE   = SYMBOL_RATE / 4.0 # 67.708 kHz above carrier
        FCCH_BITS   = 148
        # SCH extended training sequence (64 bits, TS 45.002 Table 5.2.5)
        SCH_ETSC = [
          1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0,
          0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1,
          0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1
        ].freeze

        # Streaming FCCH detector for Base.run_iq (not a channel decoder).
        class DemodIQ
          def initialize(rate:)
            @rate  = rate.to_f
            @spb   = @rate / SYMBOL_RATE
            @audio = []
            @audio_offset = 0
            @fcch_n = 0
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            @spb  = @rate / SYMBOL_RATE
            @fm_state ||= {}
            fm = PWN::SDR::Decoder::DSP.fm_demod_iq(iq: samples, state: @fm_state)
            @audio.concat(fm)
            scan(&) if block_given?
            max = (@rate * 0.25).to_i
            return unless @audio.length > max

            @audio_offset += @audio.length - max
            @audio.shift(@audio.length - max)
          end

          private

          def scan
            win = (FCCH_BITS * @spb).round
            return if @audio.length < win * 4

            # slide half-burst hop, look for min-variance window (pure tone)
            hop  = win / 4
            best = nil
            i = 0
            while i < @audio.length - win
              seg  = @audio[i, win]
              mean = seg.sum / seg.length
              var  = seg.sum { |v| (v - mean)**2 } / seg.length
              best = { i: i, mean: mean, var: var } if best.nil? || var < best[:var]
              i += hop
            end
            return unless best

            # FCCH criterion: variance ≪ overall variance AND mean > 0.
            g_mean = @audio.sum / @audio.length
            g_var  = @audio.sum { |v| (v - g_mean)**2 } / @audio.length
            return unless g_var.positive? && (best[:var] / g_var) < 0.15 && best[:mean].positive?

            position = @audio_offset + best[:i]
            return if @last_fcch_at == position

            @last_fcch_at = position
            @fcch_n += 1
            # discriminator output ≈ 2π·Δf/fs → Δf = mean · fs / (2π)
            f_est = best[:mean] * @rate / (2 * Math::PI)
            f_off = (f_est - FCCH_TONE).round
            yield(
              protocol: 'GSM', event: 'fcch', modulation: 'GMSK',
              capability: 'synchronization-only', decoded: false,
              symbol_rate: SYMBOL_RATE.to_i, fcch_no: @fcch_n,
              tone_hz: f_est.round, freq_offset_hz: f_off,
              variance_ratio: (best[:var] / g_var).round(4),
              summary: "GSM FCCH lock ##{@fcch_n} tone=#{f_est.round}Hz Δf=#{f_off}Hz"
            )

            # FCCH is only a timing/frequency observation. SCH decoding is
            # exposed separately for demodulated, burst-framed symbols.
          end
        end

        # Noncoherent SCH receiver for channelized GMSK, BT=0.3. Searches
        # sample timing against differentially precoded ETSC and estimates CFO
        # from its two discriminator levels. No multipath equalizer or BCCH/TCH.
        class SCHDemodIQ
          attr_reader :backend

          def initialize(rate:, native: true)
            @rate = Float(rate)
            raise ArgumentError, 'SCH IQ needs at least four samples per symbol' unless @rate.finite? && @rate >= 1_083_333

            @spb = @rate / SYMBOL_RATE
            @audio = []
            @state = {}
            @cursor = 0
            @offset = 0
            @training = SCH_ETSC.each_cons(2).map { |a, b| a == b ? 1 : -1 }
            @backend = :ruby
            load_native if native
          end

          def feed_iq(samples, rate: nil)
            raise ArgumentError, 'SCH sample rate cannot change during a stream' if rate && (rate.to_f - @rate).abs > 0.5

            @audio.concat(DSP.fm_demod_iq(iq: samples, state: @state))
            span = (148 * @spb).ceil
            packed = @audio.pack('d*') if @scanner && @audio.length > span
            while @cursor + span < @audio.length
              if packed
                @cursor = @scanner.pwn_gsm_search(packed, @audio.length, @cursor, @spb, @training_packed)
                break unless @cursor + span < @audio.length
              end
              frame = candidate(@cursor)
              if frame
                yield frame if block_given?
                @cursor += span
              else
                @cursor += 1
              end
            end
            @audio.shift(@cursor)
            @offset += @cursor
            @cursor = 0
          end

          private

          def load_native
            # An optional search accelerator, never a runtime compiler/download.
            path = File.expand_path("../../../../ext/pwn_gsm/libpwn_gsm.#{RbConfig::CONFIG.fetch('DLEXT')}", __dir__)
            @scanner = Module.new do
              extend ::FFI::Library

              ffi_lib path
              attach_function :pwn_gsm_search, %i[pointer size_t size_t double pointer], :size_t
            end
            @training_packed = @training.pack('l*')
            @backend = :native
          rescue LoadError
            @scanner = nil
          end

          def candidate(start)
            # Training starts at bit 42; bit 43 is the first known difference.
            values = Array.new(63) { |n| @audio[(start + ((43 + n) * @spb)).round] }
            positive = []
            negative = []
            values.each_with_index { |v, n| (@training[n].positive? ? positive : negative) << v }
            high = positive.sum / positive.length
            low = negative.sum / negative.length
            amplitude = (high - low) / 2.0
            nominal = Math::PI / (2 * @spb)
            return unless amplitude.between?(nominal * 0.35, nominal * 1.5)

            bias = (high + low) / 2.0
            errors = values.each_with_index.count { |v, n| (v > bias ? 1 : -1) != @training[n] }
            return if errors > 2

            differences = Array.new(148) { |n| @audio[(start + (n * @spb)).round] > bias ? 0 : 1 }
            bits = Array.new(148)
            bits[42] = SCH_ETSC.first
            42.downto(1) { |n| bits[n - 1] = bits[n] ^ differences[n] }
            # Reset differential state at the other known training boundary;
            # a training error must not invert the second coded half-burst.
            bits[105] = SCH_ETSC.last
            106.upto(147) { |n| bits[n] = bits[n - 1] ^ differences[n] }
            return unless bits.first(3) == [0, 0, 0] && bits.last(3) == [0, 0, 0]

            frame = GSM.decode_sch(bits: bits[3, 39] + bits[106, 39])
            frame&.merge(input: 'iq', modulation: 'GMSK', sample_index: @offset + start,
                         freq_offset_hz: (bias * @rate / (2 * Math::PI)).round,
                         training_errors: errors)
          end
        end

        # Supported Method Parameters::
        # bits = PWN::SDR::Decoder::GSM.viterbi_decode(
        #   bits: 'required - Array<0|1> soft/hard coded bits (rate-1/2)',
        #   k: 5, g0: 0o23, g1: 0o33
        # )
        # Minimal hard-decision K=5 rate-½ Viterbi (GSM 05.03 CC(2,1,5)).

        public_class_method def self.viterbi_decode(opts = {})
          bits = opts[:bits]
          k    = (opts[:k] || 5).to_i
          g0   = (opts[:g0] || 0o23).to_i
          g1   = (opts[:g1] || 0o33).to_i
          nstates = 1 << (k - 1)
          npairs  = bits.length / 2
          pm = Array.new(nstates, 1 << 30)
          pm[0] = 0
          bp = Array.new(npairs) { Array.new(nstates, 0) }
          npairs.times do |t|
            r0 = bits[t * 2]
            r1 = bits[(t * 2) + 1]
            npm = Array.new(nstates, 1 << 30)
            nstates.times do |s|
              [0, 1].each do |u|
                reg = (u << (k - 1)) | s
                o0 = parity(parity: reg & g0)
                o1 = parity(parity: reg & g1)
                m  = pm[s] + (o0 == r0 ? 0 : 1) + (o1 == r1 ? 0 : 1)
                ns = reg >> 1
                if m < npm[ns]
                  npm[ns] = m
                  bp[t][ns] = (s << 1) | u
                end
              end
            end
            pm = npm
          end
          # traceback from best final state
          s = opts[:terminated] ? 0 : pm.each_with_index.min_by(&:first).last
          out = Array.new(npairs)
          (npairs - 1).downto(0) do |t|
            v = bp[t][s]
            out[t] = v & 1
            s = v >> 1
          end
          out
        end

        # TS 45.003 SCH: 25 information + 10 inverted CRC + 4 tail bits,
        # convolutionally encoded to 78 bits. No IQ demodulation is implied.
        # Reference: libosmocore src/coding/gsm0503_parity.c (poly 0x175).
        public_class_method def self.decode_sch(opts = {})
          bits = opts[:bits]
          raise ArgumentError, 'SCH requires exactly 78 binary coded bits' unless bits.is_a?(Array) && bits.length == 78 && bits.all? { |b| b.is_a?(Integer) && [0, 1].include?(b) }

          info = viterbi_decode(bits: bits, terminated: true)
          return nil unless info[35, 4] == [0, 0, 0, 0]

          crc = 0
          info.first(25).each do |bit|
            feedback = ((crc >> 9) & 1) ^ bit
            crc = (crc << 1) & 0x3ff
            crc ^= 0x175 if feedback == 1
          end
          received = info[25, 10].reduce(0) { |a, b| (a << 1) | b }
          return nil unless received == (crc ^ 0x3ff)

          field = ->(positions) { positions.reduce(0) { |a, i| (a << 1) | info[i] } }
          ncc = field.call([7, 6, 5])
          bcc = field.call([4, 3, 2])
          t1 = field.call([1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 23])
          t2 = field.call([22, 21, 20, 19, 18])
          t3p = field.call([17, 16, 24])
          return nil unless t2 < 26 && t3p < 5

          t3 = (10 * t3p) + 1
          payload = info.first(25).each_slice(8).map { |byte| byte.each_with_index.sum { |b, i| b << i } }.pack('C*')
          {
            protocol: 'GSM', event: 'sch', capability: 'sch-channel-decode', decoded: true,
            checksum_verified: true, integrity: { algorithm: 'SCH-CRC10', valid: true },
            payload_hex: payload.unpack1('H*'), payload_bits: 25,
            bsic: (ncc << 3) | bcc, ncc: ncc, bcc: bcc, t1: t1, t2: t2, t3p: t3p,
            frame_number: (1326 * t1) + (51 * ((t3 - t2) % 26)) + t3,
            summary: "GSM SCH CRC verified NCC=#{ncc} BCC=#{bcc}"
          }
        end

        public_class_method def self.parity(opts = {})
          parity = opts[:parity].to_i
          p = 0
          while parity.positive?
            p ^= 1
            parity &= parity - 1
          end
          p
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GSM.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          mode = opts[:mode] || :iq
          raise NotImplementedError, "Unsupported GSM mode #{mode}; SCH IQ and :sch_bits only, not traffic/BCCH/CCCH" unless %i[iq sch_iq sch_bits].include?(mode)

          unless mode == :sch_bits
            freq_obj = opts[:freq_obj] || {}
            source = opts[:source] || freq_obj[:iq_source]
            file = opts[:file] || freq_obj[:iq_file]
            source ||= :file if file
            raise ArgumentError, 'SCH requires an explicit IQ source; no automatic hardware acquisition' if source.nil? || source.to_s == 'auto'

            rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 1_083_333).to_i
            return Base.run_iq(opts.merge(freq_obj: freq_obj, source: source, file: file,
                                          sample_rate: rate, protocol: 'GSM', fallback: :raise,
                                          demod: SCHDemodIQ.new(rate: rate, native: opts.fetch(:native, true))))
          end

          chunks = opts[:bit_chunks]
          raise ArgumentError, ':sch_bits requires enumerable bit_chunks (already demodulated binary SCH bursts)' unless chunks.respond_to?(:each)

          buffer = []
          frames = []
          chunks.each do |chunk|
            raise ArgumentError, 'bit_chunks must contain arrays of binary bits' unless chunk.is_a?(Array) && chunk.all? { |b| b.is_a?(Integer) && [0, 1].include?(b) }

            buffer.concat(chunk)
            while buffer.length >= 148
              frame = nil
              frame = decode_sch(bits: buffer[3, 39] + buffer[106, 39]) if buffer[0, 3] == [0, 0, 0] && buffer[42, 64] == SCH_ETSC && buffer[145, 3] == [0, 0, 0]
              buffer.shift(frame ? 148 : 1)
              next unless frame

              frames << frame
              opts[:on_frame]&.call(frame)
            end
          end
          frames
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj] || {}
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 1_083_333).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: 'GSM',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: '270.833 kbit/s GMSK — FCCH tone/frequency observations only; no SCH or traffic decoding.',
            describe: proc { |b| { modulation: 'GMSK', tdma_frames: (b[:duration_ms] / 4.615).round } }
          )
        end

        TSHARK_FIELDS = %w[
          frame.time gsmtap.arfcn gsmtap.chan_type gsm_a.imsi gsm_a.tmsi
          e212.mcc e212.mnc gsm_a.lac gsm_a.bssmap.cell_ci gsm_a.dtap.msg_rr_type
        ].freeze

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          f = line.split('|', -1)
          out = {
            protocol: 'GSM', frame_time: f[0], arfcn: f[1], chan_type: f[2],
            imsi: f[3], tmsi: f[4], mcc: f[5], mnc: f[6], lac: f[7],
            cell_id: f[8], rr_msg_type: f[9]
          }.reject { |_, v| v.to_s.empty? }
          if out[:imsi].to_s.length.between?(14, 16)
            out[:imsi_mcc]  = out[:imsi][0, 3]
            out[:imsi_mnc]  = out[:imsi][3, 3]
            out[:imsi_msin] = out[:imsi][6..]
          end
          bits = []
          bits << "ARFCN=#{out[:arfcn]}" if out[:arfcn]
          bits << "MCC/MNC=#{out[:mcc]}/#{out[:mnc]}" if out[:mcc]
          bits << "LAC=#{out[:lac]} CI=#{out[:cell_id]}" if out[:lac]
          bits << "IMSI=#{out[:imsi]}" if out[:imsi]
          out[:summary] = "GSM #{bits.join(' ')}".strip
          out
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Run viterbi decode and return its result
            #{self}.viterbi_decode(
              bits: 'required - Array<0|1> soft/hard coded bits (rate-1/2)',
              k: 'optional - 5, g0: 0o23, g1: 0o33',
              g0: 'optional - g0 value consumed by #viterbi_decode',
              g1: 'optional - g1 value consumed by #viterbi_decode',
              terminated: 'optional - force final trellis state zero (default false)'
            )

            # Run parity and return its result
            #{self}.parity(
              parity: 'optional - parity value consumed by #parity'
            )

            # Observe FCCH tones without decoding payloads:
            #{self}.detect(freq_obj: {}, source: :file, file: 'capture.cu8')
            # Decode SCH from channelized IQ or demodulated bits; verifies CRC10.
            # IQ needs >=1083333 samples/sec; no equalizer, BCCH/CCCH or traffic.
            #{self}.decode(
              mode: 'optional - :iq (default), :sch_iq, or :sch_bits',
              freq_obj: 'optional - capture settings Hash',
              source: 'required for IQ - explicit source IO/device/:file; never :auto',
              file: 'optional - IQ capture path',
              sample_rate: 'optional - IQ Hz, default 1083333',
              native: 'optional - use prebuilt SCH scanner when available (default true); false forces Ruby search',
              bit_chunks: 'optional - required in :sch_bits mode; Enumerable of binary Array chunks',
              on_frame: 'optional - synchronous callback before source EOF'
            )
            # Decode 78 convolutionally coded SCH bits and verify CRC10.
            #{self}.decode_sch(bits: 'required - exactly 78 binary bits; nil on integrity failure')

            # Capture observations only, never decoded payloads.
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
