# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # DECT P00 control and P32 B-field descrambling, ETSI EN 300 175-3 sections 6.2/7.1.
      # https://www.etsi.org/deliver/etsi_EN/300100_300199/30017503/02.08.01_60/en_30017503v020801p.pdf
      #
      # 1.152 Mbit/s GFSK, 24-slot / 10 ms TDMA. Continuous Ruby FM/NRZ
      # symbol recovery → hunt 32-bit S-field
      # (16-bit preamble + 16-bit sync 0xE98A FP / 0x1675 PP) → A-field
      # (64 bits: 8-bit header + 40-bit tail + 16-bit R-CRC) → RFPI
      # extraction on Nt/Qt tails. Emits {rfpi:, role:, slot_est:, crc_ok:}.
      module DECT
        SYNC_FP = 0xAAAAE98A
        SYNC_PP = 0x55551675
        BAUD    = 1_152_000
        # R-CRC-16 poly x^16+x^10+x^8+x^7+x^3+1 = 0x0589, init 0x0000.
        RCRC_POLY = 0x0589
        A_TA = { 0 => 'Ct', 1 => 'Ct', 2 => 'Nt', 3 => 'Nt', 4 => 'Qt', 5 => 'combined', 6 => 'Mt', 7 => 'Pt' }.freeze

        # Streaming DECT GFSK demod for Base.run_iq — I/Q → RFPI/A-field.
        class DemodIQ
          def initialize(rate:, carrier: nil, packet: :a_field, encrypted: nil, **context)
            raise ArgumentError, 'supported packets are :p00 and :p32' unless %i[a_field p00 p32].include?(packet)

            @packet = packet
            @encrypted = encrypted
            @frame_number = context[:frame_number]
            @b_format = context.fetch(:b_format, :unprotected)
            @rate    = rate.to_f
            @carrier = carrier
            @polarity_bits = { false => [], true => [] }
            @skip = { false => 0, true => 0 }
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            @slicer ||= Bluetooth::SymbolStream.new(rate: @rate, baud: BAUD)
            feed_bits(@slicer.feed_iq(samples), &)
          end

          def feed_bits(bits, &)
            [false, true].each do |inv|
              scan(inv ? bits.map { |b| b ^ 1 } : bits, inv, &) if block_given?
            end
          end

          private

          def scan(bits, inv)
            @bits = @polarity_bits[inv]
            @bits.concat(bits)
            dropped = [@skip[inv], @bits.length].min
            @bits.shift(dropped)
            @skip[inv] -= dropped
            fp = Array.new(32) { |i| (SYNC_FP >> (31 - i)) & 1 }
            pp = Array.new(32) { |i| (SYNC_PP >> (31 - i)) & 1 }
            i = 0
            while i <= @bits.length - (32 + 64)
              role = nil
              role = 'FP' if err(@bits, i, fp) <= 3
              role ||= 'PP' if err(@bits, i, pp) <= 3
              if role
                a = @bits[i + 32, 64]
                hdr  = PWN::SDR::Decoder::DSP.bits_to_int(bits: a[0, 8])
                tail = a[8, 40]
                rcrc = PWN::SDR::Decoder::DSP.bits_to_int(bits: a[48, 16])
                bytes = PWN::SDR::Decoder::DSP.bytes_from_bits(bits: a[0, 48])
                calc  = PWN::SDR::Decoder::DSP.crc16(bytes: bytes, poly: RCRC_POLY, init: 0x0000)
                # DECT R-CRC XORs the final register with 0x0001
                crc_ok = ((calc ^ 0x0001) & 0xFFFF) == rcrc
                unless crc_ok
                  i += 1
                  next
                end
                ba = (hdr >> 1) & 7
                if @packet == :p00 && ba != 7
                  i += 1
                  next
                end
                frame_length = @packet == :p32 ? 420 : 96
                break if i + frame_length > @bits.length

                extra = {}
                if @packet == :p32
                  body = @bits[i + 96, 320]
                  selected = Array.new(80) { |n| body[n + (48 * (1 + (n / 16)))] }
                  xcrc = selected.each_slice(4).reduce(0) { |v, nibble| v ^ nibble.reduce(0) { |a, bit| (a << 1) | bit } }
                  received_xcrc = DSP.bits_to_int(bits: @bits[i + 416, 4])
                  unless xcrc == received_xcrc
                    i += 1
                    next
                  end
                  extra = { xcrc_ok: true, xcrc: xcrc, integrity_scope: 'A-field and selected 80 B-field bits only',
                            encrypted: @encrypted, payload_hex: nil,
                            payload_state: @encrypted ? 'scrambled-encrypted' : 'scrambled-encryption-unknown',
                            scrambled_payload_hex: DSP.bytes_from_bits(bits: body).pack('C*').unpack1('H*').upcase }
                  unless @frame_number.nil?
                    frame_number = @frame_number.respond_to?(:call) ? @frame_number.call : @frame_number
                    payload = DECT.parse_b_field(bits: body, frame_number: frame_number, encrypted: @encrypted, b_format: @b_format)
                    unless payload
                      i += frame_length
                      next
                    end
                    extra.merge!(payload)
                    extra[:capability] = 'p32-descrambled-b-field'
                    extra[:integrity_scope] = 'A-field, X-field and all B-subfields' if payload[:b_crc_ok]
                  end
                end
                ta = (hdr >> 5) & 0x7
                rfpi = A_TA[ta] == 'Nt' ? tail[0, 40] : nil
                rfpi_hex = rfpi ? format('%010X', PWN::SDR::Decoder::DSP.bits_to_int(bits: rfpi)) : nil
                yield({
                  protocol: 'DECT', event: @packet.to_s, role: role,
                  decoded: @packet != :a_field, checksum_verified: true,
                  capability: @packet == :p32 ? 'p32-framing-opaque-b-field' : 'a-field-control',
                  modulation: 'GFSK', header: format('%02X', hdr), ba: ba,
                  ta: ta, ta_name: A_TA[ta], rfpi: rfpi_hex,
                  tail_hex: format('%010X', DSP.bits_to_int(bits: tail)),
                  rcrc: format('%04X', rcrc), crc_ok: true,
                  carrier: @carrier, polarity_inverted: inv
                }.merge(extra))
                i += frame_length
              else
                i += 1
              end
            end
            @skip[inv] += [i - @bits.length, 0].max
            @bits.shift([i, @bits.length].min)
            @bits.shift(@bits.length - 8192) if @bits.length > 65_536
          end

          def err(bits, idx, pat)
            e = 0
            j = 0
            while j < pat.length
              e += 1 if bits[idx + j] != pat[j]
              return 99 if e > 3

              j += 1
            end
            e
          end
        end

        # EN 300 175-3 6.2.4 and 6.2.1.3: externally supplied frame/connection context.
        public_class_method def self.parse_b_field(opts = {})
          bits = opts[:bits]
          frame = opts[:frame_number]
          format = opts.fetch(:b_format, :unprotected)
          raise ArgumentError, 'B-field must contain 320 bits' unless bits.is_a?(Array) && bits.length == 320 && bits.all? { |b| [0, 1].include?(b) }
          raise ArgumentError, 'frame_number must be 0..15' unless frame.is_a?(Integer) && (0..15).cover?(frame)
          raise ArgumentError, 'unsupported B-field format' unless %i[unprotected multisubfield singlesubfield].include?(format)

          register = 24 | (frame & 7)
          invert = 1
          clear = bits.map do |bit|
            output = bit ^ (register >> 4) ^ invert
            invert ^= 1 if register == 31
            feedback = ((register >> 1) ^ (register >> 4)) & 1
            register = ((register << 1) & 31) | feedback
            output
          end
          hex = ->(data) { DSP.bytes_from_bits(bits: data).pack('C*').unpack1('H*').upcase }
          result = { frame_number: frame, b_format: format, payload_hex: nil, b_crc_ok: nil,
                     descrambled_payload_hex: hex.call(clear), payload_state: 'encryption-unknown' }
          if opts[:encrypted] != false
            return result.merge(payload_state: opts[:encrypted] ? 'encrypted' : 'encryption-unknown', ciphertext_hex: hex.call(clear))
          end

          subfields = if format == :unprotected
                        [clear]
                      else
                        clear.each_slice(format == :multisubfield ? 80 : 320).to_a
                      end
          if format != :unprotected
            return nil unless subfields.all? do |field|
              crc = DSP.crc16(bytes: DSP.bytes_from_bits(bits: field[0...-16]), poly: RCRC_POLY, init: 0) ^ 1
              crc == DSP.bits_to_int(bits: field[-16, 16])
            end

            subfields = subfields.map { |field| field[0...-16] }
          end
          result.merge(payload_state: 'clear', payload_hex: hex.call(subfields.flatten),
                       subfields: subfields.map { |field| { payload_hex: hex.call(field) } },
                       b_crc_ok: format == :unprotected ? nil : true)
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::DECT.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          raise ArgumentError, 'supported packets are :p00 and :p32' unless %i[p00 p32].include?(opts.fetch(:packet, :p00))

          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          # EU: carrier 0 = 1897.344 MHz, step 1.728 MHz down; US 1.9296 GHz.
          carrier = ((1_897_344_000 - hz) / 1_728_000.0).round
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_304_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: 'DECT',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, carrier: carrier, packet: opts.fetch(:packet, :p00), encrypted: opts[:encrypted],
                               frame_number: opts[:frame_number], b_format: opts.fetch(:b_format, :unprotected)),
            fallback: :raise,
            note: '1.152 Mbit/s GFSK — I/Q→gmskdem→S-field 0xE98A→A-field/RFPI/R-CRC.',
            describe: proc { |b| { modulation: 'GFSK', tdma_slots: (b[:duration_ms] / 0.417).round } }
          )
        end

        # Energy observations only; never substituted for protocol decoding.
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(protocol: 'DECT',
                                       note: 'Energy detector only; use .decode for supported protocol frames.'))
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'DECT' }
          out[:rfpi]    = ::Regexp.last_match(1).delete(' ') if line =~ /RFPI[:=]?\s*((?:[0-9A-Fa-f]{2}\s*){5})/
          out[:slot]    = ::Regexp.last_match(1) if line =~ /slot\s*(\d+)/i
          out[:carrier] = ::Regexp.last_match(1) if line =~ /carrier\s*(\d+)/i
          out[:rssi]    = ::Regexp.last_match(1) if line =~ /RSSI[:=]?\s*(-?\d+)/i
          out[:role]    = ::Regexp.last_match(1) if line =~ /\b(FP|PP)\b/
          out[:summary] = "DECT RFPI=#{out[:rfpi]} slot=#{out[:slot]} carrier=#{out[:carrier]}"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Supported: packet: :p00 control (default), or :p32 full-slot framing.
            # R-CRC protects A-field; X-CRC covers ONLY 80 selected scrambled B bits.
            # encrypted: true/false/nil supplies external connection context; nil is unknown.
            # P32 frame_number: 0..15 enables descrambling. A callable supplies each packet's frame.
            # A constant frame number applies to EVERY packet; no automatic multiframe tracking.
            # b_format: :unprotected, :multisubfield (4x64+16 CRC), :singlesubfield (304+16 CRC).
            # Format/encryption are caller-owned connection context, not inferred from BA alone.
            # No DSC decryption, encoded IPX/FEC, E/U channel demux, DLC reassembly or speech codec.
            # Descramble a P32 B-field and verify configured protected subfields.
            #{self}.parse_b_field(bits: 'required - 320 bits', frame_number: 'required - TDMA frame 0..15', encrypted: false, b_format: :multisubfield)
            # Role assumes the observed sync polarity; spectral inversion can swap FP/PP.
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
              source: 'optional - source value consumed by #decode',
              encrypted: 'optional - true or false for known connection encryption, nil if unknown',
              frame_number: 'optional - constant TDMA frame 0..15 or per-packet callable',
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
