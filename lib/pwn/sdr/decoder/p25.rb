# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # APCO Project 25 Phase-1 (C4FM) true-air decoder.
      #
      # I/Q → PWN::FFI::Liquid.freq_demod (or DSP.fm_demod_iq) → resample to
      # 48 kHz → 4-level slice at 4800 sym/s → dibits → hunt the 24-symbol
      # Frame Sync (0x5575F5FF77FF) → recover the 64-bit NID (12-bit NAC +
      # 4-bit DUID + BCH(63,16,23) parity). Emits {nac:, duid:, duid_name:}
      # from legacy acquisition (DemodIQ). The public .decode uses PacketIQ:
      # BCH-checked one-to-three-block TSDU, trellis/CRC and group grants.
      # Unconfirmed rate-1/2 packet data also supported; no voice or Phase 2.
      module P25
        # 24-symbol / 48-bit Frame Sync (dibit MSB-first)
        FS_DIBITS = [
          1, 1, 1, 1, 3, 1, 1, 3, 3, 3, 3, 1, 1, 3, 3, 3,
          3, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3
        ].freeze # → 0x5575F5FF77FF (see TIA-102.BAAA)
        FS_DIBITS_24 = [
          1, 1, 1, 1, 3, 1, 1, 3, 3, 3, 3, 1,
          3, 3, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3
        ].freeze
        # Correct 24-dibit Frame Sync per TIA-102 (+3 +3 +3 +3 −3 +3 …).
        # Derived from bit pattern 5575F5FF77FF, MSB-first, 2 bits/sym,
        # C4FM map: 01→+3, 00→+1, 10→−1, 11→−3 → dibits {1,0,2,3}.
        FRAME_SYNC = 0x5575F5FF77FF
        FS_BITS = Array.new(48) { |i| (FRAME_SYNC >> (47 - i)) & 1 }.freeze
        FS_SYMS = FS_BITS.each_slice(2).map { |a, b| (a << 1) | b }.freeze

        DUID_NAME = {
          0x0 => 'HDU', 0x3 => 'TDU', 0x5 => 'LDU1', 0x7 => 'TSBK',
          0xA => 'LDU2', 0xC => 'PDU', 0xF => 'TDULC'
        }.freeze

        # Streaming C4FM demod for Base.run_iq — I/Q → NAC/DUID frames.
        class DemodIQ
          AUDIO_RATE = 48_000

          def initialize(rate:)
            @rate = rate.to_f
            @dibits = []
            @seen_fs = 0
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            @fm_state ||= {}
            @audio ||= []
            @audio.concat(DSP.fm_demod_iq(iq: samples, state: @fm_state))
            # Fixed 10 ms analysis windows keep resampler and slicer resets
            # independent of USB/file/UDP chunk boundaries.
            window = [(@rate * 0.01).round, 1].max
            while @audio.length >= window
              audio = DSP.resample(samples: @audio.shift(window), src_rate: @rate, dst_rate: AUDIO_RATE)
              @dibits.concat(DSP.slice_4fsk(samples: audio, rate: AUDIO_RATE, baud: 4800))
              scan(&) if block_given?
            end
            @dibits.shift(@dibits.length - 4096) if @dibits.length > 8192
          end

          private

          def scan
            fs = P25::FS_SYMS
            i = 0
            while i <= @dibits.length - (24 + 32)
              # Allow up to 3 symbol errors on FS
              err = 0
              j = 0
              while j < 24
                err += 1 if @dibits[i + j] != fs[j]
                break if err > 3

                j += 1
              end
              if err <= 3
                nid_syms = @dibits[i + 24, 32] # 32 dibits = 64 bits
                nid_bits = nid_syms.flat_map { |d| [(d >> 1) & 1, d & 1] }
                nid = PWN::SDR::Decoder::DSP.bits_to_int(bits: nid_bits[0, 16])
                nac = (nid >> 4) & 0xFFF
                duid = nid & 0xF
                @seen_fs += 1
                yield(
                  protocol: 'P25', event: 'frame', modulation: 'C4FM',
                  capability: 'nid-only', decoded: false, checksum_verified: false,
                  fs_errors: err, nac: format('%03X', nac), duid: duid,
                  duid_name: P25::DUID_NAME[duid] || format('0x%X', duid),
                  nid_hex: format('%016X', PWN::SDR::Decoder::DSP.bits_to_int(bits: nid_bits)),
                  frame_no: @seen_fs,
                  summary: "P25 NAC=#{format('%03X', nac)} DUID=#{P25::DUID_NAME[duid] || duid} (fs_err=#{err})"
                )
                i += 24 + 32
              else
                i += 1
              end
            end
            @dibits.shift([i - 24, 0].max) if i > 24
          end
        end

        BCH_GENERATOR = 0xCD930BDD3B2B

        # TIA-102 one-to-three-block TSDU receiver. Protocol tables cross-checked against
        # https://github.com/boatbod/op25/blob/master/op25/gr-op25_repeater/lib/p25p1_fdma.cc
        # C4FM only; no CQPSK, voice, Phase 2 or confirmed 3/4-rate PDUs.
        class PacketIQ
          WORDS = [[2, 12, 1, 15], [14, 0, 13, 3], [9, 7, 10, 4], [5, 11, 6, 8]].freeze
          INTERLEAVE = ((0...12).flat_map { |row| [0, 52, 100, 148].flat_map { |base| Array.new(4) { |bit| base + (row * 4) + bit } } } + [48, 49, 50, 51]).freeze

          def initialize(rate:, mode: :tsbk)
            @mode = mode.to_sym
            @rate = rate.to_f
            @dibits = []
          end

          # Continuous discriminator and transition-aided clock for centered C4FM.
          # No frequency offset acquisition or CQPSK recovery is claimed.
          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            raise ArgumentError, 'C4FM requires an integer samples/symbol rate >= 48000' unless @rate >= 48_000 && (@rate % 4800).zero?

            spb = @rate / 4800
            @clock ||= spb / 2
            dibits = []
            samples.each_slice(2) do |re, im|
              next unless im

              if @previous_iq
                pr, pi = @previous_iq
                hz = Math.atan2((im * pr) - (re * pi), (re * pr) + (im * pi)) * @rate / (2 * Math::PI)
                @clock = spb / 2 if @previous_hz && (hz - @previous_hz).abs > 650
                @clock -= 1
                if @clock <= 0
                  dibits << (if hz >= 1200
                               1
                             else
                               (if hz >= 0
                                  0
                                else
                                  (hz > -1200 ? 2 : 3)
                                end)
                             end)
                  @clock += spb
                end
                @previous_hz = hz
              end
              @previous_iq = [re, im]
            end
            feed_dibits(dibits, &)
          end

          def feed_dibits(dibits, &)
            raise ArgumentError, 'dibits must be integers 0..3' unless dibits.all? { |d| (0..3).cover?(d) }

            @dibits.concat(dibits)
            while @dibits.length >= 57
              unless @dibits.first(24) == FS_SYMS
                @dibits.shift
                next
              end
              # Status symbol after every 35 data dibits, including sync/NID.
              data = @dibits.each_with_index.reject { |_, i| (i % 36) == 35 }.map(&:first)
              nid = data[24, 32].reduce(0) { |v, d| (v << 2) | d }
              info = checked_nid(nid)
              if info && (info & 15) == 12 && %i[pdu all].include?(@mode)
                result = PacketData.parse(data: data, info: info, decoder: method(:decode_block))
                break if result == :incomplete

                if result
                  packet, count = result
                  [packet].each(&)
                  @dibits.shift(count + (count / 35))
                else
                  @dibits.shift
                end
                next
              end
              unless info && (info & 15) == 7 && %i[tsbk all].include?(@mode)
                @dibits.shift
                next
              end
              packets = []
              incomplete = false
              3.times do |index|
                if data.length < 56 + ((index + 1) * 98)
                  incomplete = true
                  break
                end
                decoded_block = decode_block(data[56 + (index * 98), 98])
                break unless decoded_block

                bytes, errors = decoded_block
                break unless DSP.crc16(bytes: bytes.first(10), init: 0, xorout: 0xFFFF) == ((bytes[10] << 8) | bytes[11])

                protected = bytes[0].anybits?(0x40)
                payload = bytes[2, 8].pack('C*').unpack1('H*').upcase
                fields = {}
                if !protected && bytes[1].zero? && bytes[0].nobits?(63)
                  channel = (bytes[3] << 8) | bytes[4]
                  fields = { service_options: bytes[2], channel_id: channel >> 12,
                             channel_number: channel & 0xFFF, talkgroup: (bytes[5] << 8) | bytes[6],
                             source_id: (bytes[7] << 16) | (bytes[8] << 8) | bytes[9] }
                end
                packets << { protocol: 'P25', event: 'tsbk', capability: 'tsdu-tsbk',
                             decoded: true, checksum_verified: true, crc_ok: true,
                             nac: format('%03X', info >> 4), duid: 7, duid_name: 'TSBK',
                             opcode: bytes[0] & 63, manufacturer_id: bytes[1], last_block: bytes[0].anybits?(0x80), block_index: index,
                             protected: protected, encrypted: protected, fec_corrected_bits: errors,
                             payload_hex: protected ? nil : payload,
                             ciphertext_hex: protected ? payload : nil,
                             raw_hex: bytes.pack('C*').unpack1('H*').upcase }.merge(fields)
                break if packets.last[:last_block]
              end
              break if incomplete

              if packets.last && packets.last[:last_block]
                packets.each(&)
                count = 56 + (packets.length * 98)
                @dibits.shift(count + (count / 35))
              else
                @dibits.shift
              end
            end
          end

          private

          # Validate BCH(63,16,23) plus the DUID parity bit. No NID correction
          # is claimed: a corrupt NID is rejected, not trusted as a network ID.
          def checked_nid(nid)
            word = nid >> 1
            remainder = word
            62.downto(47) { |i| remainder ^= BCH_GENERATOR << (i - 47) if remainder[i] == 1 }
            return nil unless remainder.zero?

            info = nid >> 48
            parity = [5, 10].include?(info & 15) ? 1 : 0
            (nid & 1) == parity ? info : nil
          end

          # Four-state Viterbi, terminated at state 0; not a greedy symbol map.
          def decode_block(symbols)
            bits = symbols.flat_map { |d| [d >> 1, d & 1] }
            received = INTERLEAVE.map { |i| bits[i] }.each_slice(4).map { |b| b.reduce(0) { |v, x| (v << 1) | x } }
            paths = { 0 => [0, []] }
            received.each do |word|
              next_paths = {}
              4.times do |target|
                choices = paths.map do |state, (cost, path)|
                  [cost + (WORDS[state][target] ^ word).to_s(2).count('1'), path + [target]]
                end
                next_paths[target] = choices.min_by(&:first)
              end
              paths = next_paths
            end
            cost, path = paths[0]
            return nil if cost > 8

            bytes = path.first(48).each_slice(4).map { |v| v.reduce(0) { |a, d| (a << 2) | d } }
            [bytes, cost]
          end
        end

        # Unconfirmed rate-1/2 packet data units, separately bounded by BTF.
        class PacketData
          public_class_method def self.parse(opts = {})
            data = opts[:data]
            info = opts[:info]
            decoder = opts[:decoder]
            return :incomplete if data.length < 154

            decoded = decoder.call(data[56, 98])
            return nil unless decoded

            header, errors = decoded
            return nil unless DSP.crc16(bytes: header.first(10), init: 0, xorout: 0xFFFF) == ((header[10] << 8) | header[11])
            return nil unless (header[0] & 31) == 0x15 && header[0].nobits?(0xC0) && header[1].allbits?(0xC0) && header[6].anybits?(0x80)

            blocks = header[6] & 127
            pad = header[7] & 31
            offset = header[9] & 63
            return nil unless blocks.positive? && pad <= 11 && header[7].nobits?(0xE0) && header[8].zero? && header[9].nobits?(0xC0)

            count = 56 + ((blocks + 1) * 98)
            return :incomplete if data.length < count

            bytes = []
            blocks.times do |index|
              part = decoder.call(data[154 + (index * 98), 98])
              return nil unless part

              bytes.concat(part[0])
              errors += part[1]
            end
            crc = 0
            bytes[0...-4].each do |byte|
              7.downto(0) do |bit|
                feedback = ((crc >> 31) ^ (byte >> bit)) & 1
                crc = (crc << 1) & 0xFFFFFFFF
                crc ^= 0x04C11DB7 if feedback == 1
              end
            end
            received = bytes.last(4).reduce(0) { |value, byte| (value << 8) | byte }
            return nil unless (crc ^ 0xFFFFFFFF) == received

            length = bytes.length - pad - 4
            return nil if length.negative? || offset > length

            payload = bytes.first(length).pack('C*').unpack1('H*').upcase
            sap = header[1] & 63
            # Only SAP 0/4 are interpreted as clear user/packet data. Unknown
            # and encrypted services remain opaque; no key guessing.
            encrypted = if sap == 9
                          true
                        else
                          ([0, 4].include?(sap) ? false : nil)
                        end
            [{ protocol: 'P25', event: 'pdu', capability: 'unconfirmed-pdu', decoded: true,
               nac: format('%03X', info >> 4), duid: 12, duid_name: 'PDU', format: 0x15,
               sap: sap, manufacturer_id: header[2], outbound: header[0].anybits?(0x20),
               llid: (header[3] << 16) | (header[4] << 8) | header[5], blocks: blocks,
               pad_octets: pad, data_header_offset: offset, header_crc_ok: true, packet_crc_ok: true,
               checksum_verified: true, fec_corrected_bits: errors, encrypted: encrypted,
               payload_hex: encrypted == false ? payload : nil, ciphertext_hex: encrypted == true ? payload : nil,
               opaque_payload_hex: encrypted.nil? ? payload : nil }, count]
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::P25.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          raise ArgumentError, 'only :tsbk, :pdu (unconfirmed), or :all are supported' unless %i[tsbk pdu all].include?(opts.fetch(:mode, :tsbk).to_sym)
          raise ArgumentError, 'only Phase 1 C4FM is supported' unless opts.fetch(:phase, 1) == 1 && opts.fetch(:modulation, :c4fm).to_sym == :c4fm

          freq_obj = opts[:freq_obj]
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || (48_000 * 20)).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: 'P25',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: PacketIQ.new(rate: rate, mode: opts.fetch(:mode, :tsbk)),
            fallback: :raise,
            note: 'C4FM TSDU/unconfirmed PDU: BCH NID, status removal, Viterbi, CRC16 and packet CRC32.',
            describe: proc { |b| { modulation: 'C4FM', classification: b[:duration_ms] > 180 ? 'voice-LDU' : 'TSBK/control' } }
          )
        end

        # Energy observations only; never substituted for protocol decoding.
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(protocol: 'P25',
                                       note: 'Energy detector only; use .decode for supported protocol frames.'))
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'P25' }
          out[:nac]  = ::Regexp.last_match(1) if line =~ /NAC[:= ]+([0-9A-Fa-f]+)/
          out[:tg]   = ::Regexp.last_match(1) if line =~ /(?:TG|talkgroup)[:= ]+(\d+)/i
          out[:rid]  = ::Regexp.last_match(1) if line =~ /(?:RID|src|source)[:= ]+(\d+)/i
          out[:duid] = ::Regexp.last_match(1) if line =~ /DUID[:= ]+(\w+)/i
          out[:summary] = "P25 NAC=#{out[:nac]} TG=#{out[:tg]} RID=#{out[:rid]}"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Parse and integrity-check an unconfirmed packet data unit.
            #{self}::PacketData.parse(
              data: 'required - Array of synchronized dibits without status symbols',
              info: 'required - Integer containing verified NAC and DUID bits',
              decoder: 'required - callable accepting a trellis block and returning bytes and corrected-bit count'
            )

            # Supported: centered Phase-1 C4FM TSDU with 1..3 TSBKs (mode: :tsbk).
            # mode: :pdu decodes unconfirmed format 0x15, rate-1/2 PDUs; :all enables both.
            # Integer samples/symbol, rate >= 48000. Status symbols are removed;
            # BCH and parity are checked (no NID correction), trellis Viterbi and CRC verified.
            # Protected payload is ciphertext, never plaintext. No voice, CQPSK,
            # Phase 2, confirmed PDU/AMBT or frequency-offset acquisition. No decryption.
            #{self}.detect(freq_obj: 'required', on_frame: 'optional callback')

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
              mode: 'optional - :tsbk (default), :pdu (unconfirmed), :all',
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
