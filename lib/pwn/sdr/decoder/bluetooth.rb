# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Bluetooth LE 1M single-channel advertising/connected PDU decoder.
      #
      # I/Q → continuous Ruby FM/NRZ fallback at
      # 1 Mbit/s → hunt LSB-first Access Address (adv = 0x8E89BED6) →
      # dewhiten (7-bit LFSR seeded ch|0x40) → PDU header (type/len) →
      # AdvA (6 bytes) → CRC-24 (poly 0x65B, init 0x555555). Emits per-PDU
      # {access_addr:, pdu_type:, adv_addr:, crc_ok:}. CRC failures are
      # rejected. Connected packets require explicit AA, CRCInit and encryption
      # state. CTE header is parsed; no direction finding, hopping, L2CAP
      # assembly, 2M/coded PHY or decryption.
      module Bluetooth
        BLE_ADV_AA   = 0x8E89BED6
        BLE_CRC_POLY = 0x65B
        BLE_CRC_INIT = 0x555555
        BLE_PDU_TYPE = {
          0 => 'ADV_IND', 1 => 'ADV_DIRECT_IND', 2 => 'ADV_NONCONN_IND',
          3 => 'SCAN_REQ', 4 => 'SCAN_RSP', 5 => 'CONNECT_IND',
          6 => 'ADV_SCAN_IND', 7 => 'ADV_EXT_IND'
        }.freeze
        BLE_ADV_CHANNELS = { 37 => 2_402_000_000, 38 => 2_426_000_000, 39 => 2_480_000_000 }.freeze
        # BR/EDR: 64-bit sync word derived from LAP; general-inquiry LAP=0x9E8B33.
        GIAC_LAP = 0x9E8B33

        # Continuous Ruby FM/NRZ fallback. Unlike a one-shot liquid gmskdem
        # call, filter history and symbol phase survive transport chunks.
        # Also used for DECT and ZigBee's existing FM/NRZ recovery path.
        class SymbolStream
          def initialize(rate:, baud:)
            @spb = rate.to_f / baud
            raise ArgumentError, 'sample rate must be at least twice the baud' if @spb < 2

            @phase = @spb / 2
            @previous_iq = nil
            @previous_input = 0.0
            @dc = 0.0
            @previous = 0.0
            @window = Array.new([(@spb / 4).round, 1].max, 0.0)
            @slot = 0
            @sum = 0.0
          end

          def feed_iq(samples)
            audio = []
            samples.each_slice(2) do |re, im|
              next unless im

              if @previous_iq
                pr, pi = @previous_iq
                audio << Math.atan2((im * pr) - (re * pi), (re * pr) + (im * pi))
              end
              @previous_iq = [re, im]
            end
            feed(audio)
          end

          def feed(samples)
            bits = []
            samples.each do |x|
              @dc = x - @previous_input + (0.995 * @dc)
              @previous_input = x
              @sum += @dc - @window[@slot]
              @window[@slot] = @dc
              @slot = (@slot + 1) % @window.length
              v = @sum / @window.length
              @phase = @spb / 2 if (@previous.negative? && v >= 0) || (@previous.positive? && v.negative?)
              @phase -= 1
              if @phase <= 0
                bits << (v.negative? ? 0 : 1)
                @phase += @spb
              end
              @previous = v
            end
            bits
          end
        end

        # Streaming BLE GFSK demod for Base.run_iq — I/Q → advertising PDUs.
        class DemodIQ
          BAUD = 1_000_000

          def initialize(rate:, channel: 37, ble: true, extended: false, **connection)
            access_address = connection.fetch(:access_address, BLE_ADV_AA)
            crc_init = connection[:crc_init]
            encrypted = connection[:encrypted]
            raise ArgumentError, 'BR/EDR is unsupported; only legacy BLE advertising is decoded' unless ble

            @connected = access_address != BLE_ADV_AA
            @extended = extended
            raise ArgumentError, 'advertising channel must be 37, 38 or 39' unless @connected || @extended || BLE_ADV_CHANNELS.key?(channel)
            raise ArgumentError, 'channel must be an integer 0..39' unless channel.is_a?(Integer) && (0..39).cover?(channel)
            raise ArgumentError, 'connected channel must be 0..36' if @connected && channel >= 37
            raise ArgumentError, 'connected decoding requires crc_init and explicit encrypted: true/false' if @connected && (crc_init.nil? || ![true, false].include?(encrypted))

            @access_address = Integer(access_address)
            @crc_init = crc_init || BLE_CRC_INIT
            raise ArgumentError, 'invalid access address or CRCInit width' unless (0..0xFFFFFFFF).cover?(@access_address) && @crc_init.is_a?(Integer) && (0..0xFFFFFF).cover?(@crc_init)

            @encrypted = encrypted || false
            @aa_bits = Array.new(32) { |i| (@access_address >> i) & 1 }
            @aa_inv = @aa_bits.map { |b| b ^ 1 }

            @rate    = rate.to_f
            @channel = channel
            @ble     = ble
            @bits    = []
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            # Try both polarities — GFSK sign depends on tuner spectral inversion.
            @slicer ||= Bluetooth::SymbolStream.new(rate: @rate, baud: BAUD)
            new_bits = @slicer.feed_iq(samples)
            feed_bits(new_bits, &)
          end

          def feed_bits(bits, &)
            raise ArgumentError, 'bits must contain only 0 or 1' unless bits.all? { |bit| [0, 1].include?(bit) }

            @bits.concat(bits)
            scan(&) if block_given?
          end

          private

          # 32-bit AA is transmitted LSB-first on the air.
          AA_BITS = Array.new(32) { |i| (BLE_ADV_AA >> i) & 1 }
          AA_INV  = AA_BITS.map { |b| b ^ 1 }.freeze

          def scan
            i = 0
            while i <= @bits.length - (32 + 16 + 24)
              inv = nil
              inv = false if match_at?(i, @aa_bits)
              inv = true  if inv.nil? && match_at?(i, @aa_inv)
              unless inv.nil?
                pdu = decode_pdu(@bits[(i + 32)..], inv)
                break if pdu == :incomplete

                if pdu
                  yield pdu
                  i += 32 + ((pdu.fetch(:header_length, 2) + pdu[:length].to_i + 3) * 8)
                  next
                end
              end
              i += 1
            end
            @bits.shift(i)
          end

          def match_at?(idx, pat, max_err: 2)
            pat.each_index.count { |j| @bits[idx + j] != pat[j] } <= max_err
          end

          # Core Vol 6 Part B 3.2: output bit 0 then advance x^7+x^4+1.
          def whiten(bytes)
            reg = @channel | 0x40
            bytes.map do |byte|
              value = byte
              8.times do |i|
                bit = reg & 1
                value ^= bit << i
                reg >>= 1
                reg ^= 0x44 if bit == 1
              end
              value
            end
          end

          def decode_pdu(stream, inv)
            stream = stream.map { |b| b ^ 1 } if inv
            hdr_b  = PWN::SDR::Decoder::DSP.bytes_from_bits(bits: stream[0, 16], lsb_first: true)
            hdr = whiten(hdr_b)
            return nil if hdr.length < 2

            ptype = hdr[0] & 0x0F
            len   = hdr[1] & 0xFF
            header_size = @connected && hdr[0].anybits?(0x20) ? 3 : 2
            return nil unless if @connected
                                hdr[0].anybits?(3) && hdr[0].nobits?(0xC0)
                              else
                                (ptype <= 6 || (@extended && ptype == 7)) && hdr[0].nobits?(0x10)
                              end
            return nil unless if @connected
                                (0..(@encrypted ? 255 : 251)).cover?(len)
                              elsif ptype == 7
                                (1..255).cover?(len)
                              elsif [1, 3].include?(ptype)
                                len == 12
                              else
                                (ptype == 5 ? len == 34 : (6..37).cover?(len))
                              end
            return :incomplete if (header_size + len + 3) * 8 > stream.length

            body_b = PWN::SDR::Decoder::DSP.bytes_from_bits(
              bits: stream[0, (header_size + len + 3) * 8], lsb_first: true
            )
            dewh = whiten(body_b)
            payload = dewh[header_size, len] || []
            crc_rx  = dewh[header_size + len, 3] || []
            crc_ok  = Bluetooth.ble_crc24(bytes: dewh[0, header_size + len], init: @crc_init) ==
                      (crc_rx[0].to_i | (crc_rx[1].to_i << 8) | (crc_rx[2].to_i << 16))
            return nil unless crc_ok

            if !@connected && ptype == 7
              fields = ExtendedHeader.parse(payload: payload)
              return nil unless fields

              return fields.merge(protocol: 'BLE', event: 'pdu', decoded: true, checksum_verified: true,
                                  encrypted: false, crc_ok: true, channel: @channel, length: len,
                                  pdu_type: @channel >= 37 ? 'ADV_EXT_IND' : 'AUX_ADV_IND',
                                  access_addr: format('%08X', @access_address), payload_hex: payload.pack('C*').unpack1('H*').upcase)
            end

            if @connected
              fields = LinkLayer.parse(header: dewh.first(header_size), payload: payload, encrypted: @encrypted)
              return nil unless fields

              return fields.merge(protocol: 'BLE', event: 'pdu', decoded: true, checksum_verified: true,
                                  channel: @channel, access_addr: format('%08X', @access_address),
                                  length: len, crc_ok: true)
            end

            adv_addr = payload.length >= 6 ? payload[0, 6].reverse.map { |b| format('%02X', b) }.join(':') : nil
            {
              protocol: 'BLE', event: 'pdu', decoded: crc_ok,
              checksum_verified: crc_ok, encrypted: false,
              advertising_data_hex: [0, 2, 4, 6].include?(ptype) ? payload.drop(6).pack('C*').unpack1('H*').upcase : nil,
              modulation: 'GFSK', channel: @channel,
              access_addr: format('%08X', BLE_ADV_AA),
              pdu_type: BLE_PDU_TYPE[ptype] || ptype,
              tx_add: (hdr[0] >> 6) & 1, rx_add: (hdr[0] >> 7) & 1,
              length: len, adv_addr: adv_addr, crc_ok: crc_ok,
              crc_rx: crc_rx.map { |b| format('%02X', b) }.join,
              payload_hex: payload.map { |b| format('%02X', b) }.join,
              summary: "BLE #{BLE_PDU_TYPE[ptype] || ptype} AdvA=#{adv_addr} len=#{len} ch=#{@channel} crc=#{crc_ok ? 'OK' : 'BAD'}"
            }
          end
        end

        # Connected header/CTE and selected control fields, after CRC verification.
        class LinkLayer
          public_class_method def self.parse(opts = {})
            header = opts[:header]
            payload = opts[:payload]
            encrypted = opts[:encrypted]
            byte = header[0]
            if header.length == 3
              cte = header[2]
              return nil unless (2..20).cover?(cte & 31) && cte.nobits?(0x20) && cte >> 6 != 3
            end
            hex = payload.pack('C*').unpack1('H*').upcase
            fields = { pdu_type: byte.allbits?(3) ? 'LL_CONTROL' : 'LL_DATA',
                       header_length: header.length, cte_info: header[2], llid: byte & 3,
                       nesn: (byte >> 2) & 1, sn: (byte >> 3) & 1, md: (byte >> 4) & 1,
                       encrypted: encrypted, payload_hex: encrypted ? nil : hex,
                       ciphertext_hex: encrypted ? hex : nil }
            if !encrypted && byte.allbits?(3)
              return nil if payload.empty?

              fields[:control_opcode] = payload[0]
              if payload[0] == 1
                return nil unless payload.length == 8 && payload[5].nobits?(0xE0) && payload[1, 5].sum { |v| v.to_s(2).count('1') } >= 2

                fields[:channel_map_hex] = payload[1, 5].pack('C*').unpack1('H*').upcase
                fields[:instant] = payload[6] | (payload[7] << 8)
              end
            end
            fields
          end
        end

        # Length-bounded extended advertising header parser.
        class ExtendedHeader
          # Core Vol 6 Part B 2.3.4: flagged fields in fixed order, bounded by
          # ExtHdrLen. Preserve ACAD/SyncInfo as bytes rather than invent fields.
          public_class_method def self.parse(opts = {})
            payload = opts[:payload]
            size = payload[0] & 63
            mode = payload[0] >> 6
            return nil if mode == 3 || size + 1 > payload.length

            out = { adv_mode: mode }
            if size.positive?
              flags = payload[1]
              return nil if flags.anybits?(0x80)

              cursor = 2
              { adv_addr: 6, target_addr: 6, cte_info: 1, adi: 2, aux_ptr: 3, sync_info: 18, tx_power: 1 }.each_with_index do |(name, width), bit|
                next if flags[bit].zero?
                return nil if cursor + width > size + 1

                data = payload[cursor, width]
                cursor += width
                case name
                when :adv_addr, :target_addr
                  out[name] = data.reverse.map { |b| format('%02X', b) }.join(':')
                when :adi
                  out[:advertising_did] = data[0] | ((data[1] & 15) << 8)
                  out[:advertising_sid] = data[1] >> 4
                when :tx_power
                  out[name] = data[0] >= 128 ? data[0] - 256 : data[0]
                else
                  out[:"#{name}_hex"] = data.pack('C*').unpack1('H*').upcase
                end
              end
              out[:acad_hex] = payload[cursor, size + 1 - cursor].pack('C*').unpack1('H*').upcase
            end
            out[:advertising_data_hex] = payload.drop(size + 1).pack('C*').unpack1('H*').upcase
            out
          end
        end

        # Supported Method Parameters::
        # crc = PWN::SDR::Decoder::Bluetooth.ble_crc24(bytes: Array<Integer>)
        # BLE CRC-24 (LSB-first LFSR, poly 0x65B, init 0x555555).

        public_class_method def self.ble_crc24(opts = {})
          bytes = opts[:bytes] || []
          # Reflect the specification's MSB-oriented CRCInit for a right-shift LFSR.
          reg = opts.fetch(:init, BLE_CRC_INIT).to_s(2).rjust(24, '0').reverse.to_i(2)
          bytes.each do |byte|
            8.times do |i|
              b = (byte >> i) & 1
              fb = (reg ^ b) & 1
              reg >>= 1
              reg ^= 0xDA6000 if fb == 1 # reflected x^24+x^10+x^9+x^6+x^4+x^3+x+1
              reg &= 0xFFFFFF
            end
          end
          # Register holds CRC LSB-first — return as-is (matched LSB-first on air)
          reg
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Bluetooth.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          raise ArgumentError, 'only BLE 1M PHY is supported' unless opts.fetch(:phy, :le1m).to_sym == :le1m

          ble = opts.fetch(:ble, freq_obj.fetch(:ble, true))
          # Nearest BLE advertising channel unless caller forces one.
          ch = opts[:channel] ||
               BLE_ADV_CHANNELS.min_by { |_, f| (f - hz).abs }&.first || 37
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 4_000_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            fallback: :raise,
            freq_obj: freq_obj,
            protocol: ble ? 'BLE' : 'BT-BR/EDR',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, channel: ch, ble: ble,
                               access_address: opts.fetch(:access_address, BLE_ADV_AA),
                               crc_init: opts[:crc_init], encrypted: opts[:encrypted], extended: opts.fetch(:extended, false)),
            note: 'LE 1M single-channel GFSK: AA, dewhitening, PDU fields and CRC-24.',
            describe: proc { |b| { modulation: 'GFSK', channel: ch, hop_slots: (b[:duration_ms] / 0.625).round } }
          )
        end

        # Energy observations only; never substituted for protocol decoding.
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(protocol: 'Bluetooth',
                                       note: 'Energy detector only; use .decode for supported protocol frames.'))
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'Bluetooth' }
          out[:lap]      = ::Regexp.last_match(1) if line =~ /LAP[=: ]([0-9a-fA-F]{6})/
          out[:uap]      = ::Regexp.last_match(1) if line =~ /UAP[=: ]([0-9a-fA-F]{2})/
          out[:bd_addr]  = ::Regexp.last_match(1) if line =~ /(?:AdvA|BD_ADDR)[=: ]([0-9a-fA-F:]{12,17})/
          out[:pdu_type] = ::Regexp.last_match(1) if line =~ /\b(ADV_\w+|SCAN_\w+|CONNECT_REQ)\b/
          out[:channel]  = ::Regexp.last_match(1) if line =~ /ch[=: ]?(\d{1,2})\b/i
          out[:rssi]     = ::Regexp.last_match(1) if line =~ /rssi[=: ]?(-?\d+)/i
          out[:summary]  = "BT #{out.values_at(:pdu_type, :bd_addr, :lap).compact.join(' ')}".strip
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Supported: BLE 1M legacy advertising; extended: true permits type 7
            # ADV_EXT_IND/AUX_ADV_IND on an explicitly selected channel 0..39.
            # Connected: access_address:, crc_init:, encrypted: true/false required.
            # Encrypted bytes remain ciphertext; no key-based decryption implemented.
            # CTEInfo and LL_CHANNEL_MAP_IND fields are parsed (no direction finding).
            # No BR/EDR, coded/2M PHY, hopping, AUX chain or L2CAP assembly.
            # Invalid lengths/CRC are rejected. Repeated valid packets are preserved.
            # phy: :le1m; ble: true. No silent energy fallback from .decode.
            #{self}.detect(freq_obj: 'required', on_frame: 'optional callback')

            # Run ble crc24 and return its result
            #{self}.ble_crc24(
              bytes: 'optional - bytes value consumed by #ble_crc24 (defaults to [])'
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
              channel: 'optional - channel value consumed by #decode',
              access_address: 'optional - Integer connection access address; default advertising AA',
              crc_init: 'optional - Integer 24-bit CRCInit; required for connected decoding',
              encrypted: 'optional - required for connected decoding: true yields ciphertext only; false yields plaintext',
              extended: 'optional - enable extended advertising PDUs, default false',
              sample_rate: 'optional - sample rate value consumed by #decode',
              source: 'optional - source value consumed by #decode',
              file: 'optional - filesystem path'
            )

            # Parse CRC-verified connected header and payload bytes.
            #{self}::LinkLayer.parse(
              header: 'required - Array of two or three header bytes',
              payload: 'required - Array of payload bytes',
              encrypted: 'required - Boolean indicating ciphertext rather than plaintext'
            )

            # Parse length-bounded extended advertising header bytes.
            #{self}::ExtendedHeader.parse(payload: 'required - Array of extended advertising payload bytes')

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
