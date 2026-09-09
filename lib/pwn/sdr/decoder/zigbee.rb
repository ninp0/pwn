# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # IEEE 802.15.4 O-QPSK (2.4 GHz ZigBee/Thread) true-air decoder.
      #
      # 2 Mchip/s half-sine O-QPSK ≡ MSK: continuous Ruby FM/NRZ recovery
      # produces differential frequency signs, not raw chips. Each symbol maps
      # to a 32-chip PN sequence (Table 73, IEEE 802.15.4-2011); soft-
      # correlate every 32 chips against the 16 sequences → symbols →
      # nibbles → bytes. Hunt SHR (4×0x00 preamble + SFD 0xA7) → PHR len
      # → MHR (FCF/seq/PAN/addr) → FCS (CRC-16-KERMIT). Emits per-frame
      # {pan_id:, src:, dst:, frame_type:, len:, fcs_ok:}.
      module ZigBee
        CHIP_RATE = 2_000_000
        # 16 × 32-chip PN sequences (symbol 0..15). Each row is one 32-bit
        # word; chips are MSB-first (c0 = bit31).
        PN32 = [
          0xD9C3522E, 0xED9C3522, 0x2ED9C352, 0x22ED9C35,
          0x522ED9C3, 0x3522ED9C, 0xC3522ED9, 0x9C3522ED,
          0x8C96077B, 0xB8C96077, 0x7B8C9607, 0x77B8C960,
          0x077B8C96, 0x6077B8C9, 0x96077B8C, 0xC96077B8
        ].freeze
        PN_CHIPS = PN32.map { |w| Array.new(32) { |i| (w >> (31 - i)) & 1 } }.freeze
        # Half-sine O-QPSK frequency signs are differential, not raw PN chips.
        # c0 depends on the preceding symbol and is excluded from correlation.
        MSK_CHIPS = PN_CHIPS.map do |chips|
          Array.new(32) { |i| (chips[i] ^ chips[(i - 1) % 32]) ^ (i.odd? ? 1 : 0) }
        end.freeze
        SFD = 0xA7
        FRAME_TYPE = { 0 => 'Beacon', 1 => 'Data', 2 => 'ACK', 3 => 'MAC-Cmd' }.freeze

        # Streaming O-QPSK/MSK chip demod for Base.run_iq — I/Q → 802.15.4 MPDU.
        class DemodIQ
          def initialize(rate:, channel: nil, network_keys: {}, link_key: nil, security_level: 5)
            @security_options = { network_keys: network_keys, link_key: link_key, security_level: security_level }
            @rate    = rate.to_f
            @channel = channel
            @chips   = []
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            @slicer ||= Bluetooth::SymbolStream.new(rate: @rate, baud: CHIP_RATE)
            @frequency_mode = true
            feed_chips(@slicer.feed_iq(samples), &)
          end

          def feed_chips(chips, &)
            @chips.concat(chips)
            scan(&) if block_given?
          end

          private

          def correlate_symbol(win)
            best = [0, -1]
            (@frequency_mode ? MSK_CHIPS : PN_CHIPS).each_with_index do |pn, sym|
              # Ignore chip0: its frequency sign depends on the preceding symbol.
              s = 0
              (1...32).each { |i| s += (win[i] == pn[i] ? 1 : -1) }
              best = [sym, s] if s > best[1]
            end
            best
          end

          def chips_to_bytes(chips)
            nsym = chips.length / 32
            syms = Array.new(nsym) { |i| correlate_symbol(chips[i * 32, 32]).first }
            # two nibbles → byte, LSB-nibble first (symbol 2n = low nibble)
            out = []
            syms.each_slice(2) { |lo, hi| out << ((hi.to_i << 4) | lo.to_i) if hi }
            out
          end

          def scan(&)
            # Sliding alignment requires all eight preamble symbols.
            i = 0
            while i <= @chips.length - (32 * 12)
              ok = true
              8.times do |p|
                sym, sc = correlate_symbol(@chips[i + (p * 32), 32])
                ok &&= sym.zero? && sc >= 20
                break unless ok
              end
              if ok
                # SFD (0xA7 = symbols 0x7, 0xA)
                s5, = correlate_symbol(@chips[i + (8 * 32), 32])
                s6, = correlate_symbol(@chips[i + (9 * 32), 32])
                if s5 == 0x7 && s6 == 0xA
                  length = chips_to_bytes(@chips[i + (32 * 10), 64]).first.to_i
                  unless (5..127).cover?(length)
                    i += 1
                    next
                  end
                  frame_length = (12 + (length * 2)) * 32
                  break if i + frame_length > @chips.length

                  yield_frame(i, &)
                  i += frame_length
                  next
                end
              end
              i += 1
            end
            @chips.shift(i)
          end

          def yield_frame(shr_i)
            phr_i = shr_i + (32 * 10)
            return if phr_i + (32 * 2) > @chips.length

            phr = chips_to_bytes(@chips[phr_i, 32 * 2]).first.to_i & 0x7F
            body_i = phr_i + (32 * 2)
            return if body_i + (phr * 32 * 2) > @chips.length

            bytes = chips_to_bytes(@chips[body_i, phr * 32 * 2])
            return if bytes.length < 3

            frame = ZigBee.parse_mpdu(@security_options.merge(bytes: bytes))
            yield frame.merge(channel: @channel, modulation: 'O-QPSK') if frame
          end
        end

        # IEEE 802.15.4-2006 MAC frames (versions 0/1), with nested ZigBee NWK/APS.
        # The FCS is transport integrity, never proof of CCM authentication.
        public_class_method def self.parse_mpdu(opts = {})
          bytes = opts[:bytes] || []
          return nil unless (5..127).cover?(bytes.length) && bytes.all? { |b| b.is_a?(Integer) && (0..255).cover?(b) }
          return nil unless DSP.crc16(bytes: bytes[0...-2], init: 0, refin: true, refout: true) == (bytes[-2] | (bytes[-1] << 8))

          fcf = bytes[0] | (bytes[1] << 8)
          version = (fcf >> 12) & 3
          dst_mode = (fcf >> 10) & 3
          src_mode = (fcf >> 14) & 3
          return nil if version > 1 || dst_mode == 1 || src_mode == 1 || fcf.anybits?(0x0380) || (fcf & 7) > 3

          compressed = fcf.anybits?(0x40)
          return nil if compressed && (dst_mode.zero? || src_mode.zero?)

          data = bytes[3...-2].dup
          take = lambda do |length|
            raise IndexError if data.length < length

            data.shift(length)
          end
          hex = ->(b) { b.pack('C*').unpack1('H*').upcase }
          pan = dst = src_pan = src = nil
          if dst_mode.positive?
            pan = hex.call(take.call(2).reverse)
            dst = hex.call(take.call(dst_mode == 3 ? 8 : 2).reverse)
          end
          if src_mode.positive?
            src_pan = compressed ? pan : hex.call(take.call(2).reverse)
            src = hex.call(take.call(src_mode == 3 ? 8 : 2).reverse)
          end
          security = fcf.anybits?(8)
          encrypted = false
          mic = []
          security_fields = {}
          if security
            return nil unless version == 1 # legacy 2003 security suites differ

            control = take.call(1).first
            return nil unless control.nobits?(0xE0)

            level = control & 7
            key_mode = (control >> 3) & 3
            counter = take.call(4).pack('C*').unpack1('V')
            key_id = take.call([0, 1, 5, 9][key_mode])
            mic_len = [0, 4, 8, 16, 0, 4, 8, 16][level]
            raise IndexError if data.length < mic_len

            mic = mic_len.zero? ? [] : data.pop(mic_len)
            encrypted = level >= 4
            security_fields = { security_level: level, frame_counter: counter,
                                key_id_mode: key_mode, key_id_hex: hex.call(key_id) }
          end
          frame = { protocol: 'ZigBee', layer: 'IEEE802.15.4-MAC', event: 'mpdu', decoded: true,
                    capability: '802.15.4-2003/2006-mac', fcs_ok: true, checksum_verified: true,
                    len: bytes.length, seq: bytes[2], fcf: format('%04X', fcf), frame_version: version,
                    frame_type: FRAME_TYPE[fcf & 7], pan_id: pan, src_pan_id: src_pan, src: src, dst: dst,
                    security_enabled: security, encrypted: encrypted, authentication_verified: false,
                    payload_hex: encrypted ? nil : hex.call(data), ciphertext_hex: encrypted ? hex.call(data) : nil,
                    mic_hex: hex.call(mic), raw_hex: hex.call(bytes) }.merge(security_fields)
          if !security && (fcf & 7) == 1
            frame[:nwk] = parse_nwk(opts.merge(bytes: data))
            if frame[:nwk]
              frame[:capability] = if frame[:nwk][:aps]
                                     'zigbee-nwk-aps'
                                   elsif frame[:nwk][:payload_hex].nil?
                                     'zigbee-nwk-secured'
                                   else
                                     'zigbee-nwk-command'
                                   end
            else
              frame[:nwk_status] = 'invalid-or-unsupported'
            end
          end
          frame
        rescue IndexError
          nil
        end

        # ZigBee PRO NWK version 2 and APS. Unsupported variants return nil.
        # Layout cross-check: https://github.com/secdev/scapy/blob/master/scapy/layers/zigbee.py
        class Octets
          attr_reader :offset

          def initialize(bytes)
            raise IndexError unless bytes.is_a?(Array) && bytes.all? { |b| b.is_a?(Integer) && (0..255).cover?(b) }

            @bytes = bytes
            @offset = 0
          end

          def take(count)
            raise IndexError if @offset + count > @bytes.length

            value = @bytes[@offset, count]
            @offset += count
            value
          end

          def number(count = 1)
            take(count).each_with_index.sum { |b, i| b << (8 * i) }
          end

          def address(count)
            take(count).reverse.pack('C*').unpack1('H*').upcase
          end

          def rest
            take(@bytes.length - @offset)
          end
        end

        # AES-CCM authenticated decryption; never release unauthenticated plaintext.
        public_class_method def self.decrypt_ccm(opts = {})
          require 'openssl'
          raise ArgumentError, 'key must be 16 binary octets' unless opts[:key].is_a?(String) && opts[:key].bytesize == 16

          cipher = OpenSSL::Cipher.new('aes-128-ccm')
          cipher.decrypt
          cipher.iv_len = opts[:nonce].bytesize
          cipher.auth_tag = opts[:mic]
          cipher.key = opts[:key]
          cipher.iv = opts[:nonce]
          cipher.ccm_data_len = opts[:ciphertext].bytesize
          cipher.auth_data = opts[:aad]
          cipher.update(opts[:ciphertext]) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          nil
        end

        # ZigBee auxiliary security, extended nonce, AES-CCM levels 5/6/7.
        # Level zero on the wire uses the configured network level (default 5).
        public_class_method def self.parse_security(opts = {})
          bytes = opts[:bytes]
          offset = opts[:offset]
          cursor = Octets.new(bytes[offset..])
          control = cursor.number
          return nil if control.anybits?(0xC0)

          level = control & 7
          level = opts.fetch(:security_level, 5) if level.zero?
          return nil unless [5, 6, 7].include?(level)

          effective_control = (control & 0xF8) | level
          counter_bytes = cursor.take(4)
          source = control.anybits?(0x20) ? cursor.take(8) : opts[:security_source]
          key_id = (control >> 3) & 3
          sequence = key_id == 1 ? cursor.number : nil
          key = key_id == 1 ? opts.fetch(:network_keys, {})[sequence] : (opts[:link_key] if key_id.zero?)
          header_size = offset + cursor.offset
          body = cursor.rest
          mic_length = { 5 => 4, 6 => 8, 7 => 16 }.fetch(level)
          return nil if body.length < mic_length

          mic = body.pop(mic_length)
          result = { security_level: level, key_id: key_id, key_sequence: sequence,
                     frame_counter: counter_bytes.pack('C*').unpack1('V'), authentication_verified: false,
                     ciphertext_hex: body.pack('C*').unpack1('H*').upcase,
                     mic_hex: mic.pack('C*').unpack1('H*').upcase, payload_hex: nil }
          return result unless key && source.is_a?(Array) && source.length == 8

          aad = bytes[0, header_size].dup
          aad[offset] = effective_control
          plain = decrypt_ccm(key: key, nonce: (source + counter_bytes + [effective_control]).pack('C*'),
                              aad: aad.pack('C*'), ciphertext: body.pack('C*'), mic: mic.pack('C*'))
          return nil unless plain

          result.merge(authentication_verified: true, payload_hex: plain.unpack1('H*').upcase)
        rescue IndexError
          nil
        end

        public_class_method def self.parse_nwk(opts = {})
          cursor = Octets.new(opts[:bytes])
          control = cursor.number(2)
          return nil unless ((control >> 2) & 15) == 2 && (control & 3) <= 1 && control.nobits?(0xE000)

          result = { frame_type: control & 3, protocol_version: 2, destination: cursor.address(2),
                     source: cursor.address(2), radius: cursor.number, sequence: cursor.number,
                     security_enabled: control.anybits?(0x200), authentication_verified: false }
          result[:extended_destination] = cursor.address(8) if control.anybits?(0x800)
          result[:extended_source] = cursor.address(8) if control.anybits?(0x1000)
          result[:multicast_control] = cursor.number if control.anybits?(0x100)
          if control.anybits?(0x400)
            count = cursor.number
            result[:relay_index] = cursor.number
            return nil if count.zero? || result[:relay_index] >= count

            result[:relays] = Array.new(count) { cursor.address(2) }
          end
          header_size = cursor.offset
          payload = cursor.rest
          if result[:security_enabled]
            security = parse_security(opts.merge(offset: header_size))
            return nil unless security

            result.merge!(security)
            return result unless security[:authentication_verified]

            payload = [security[:payload_hex]].pack('H*').bytes
          end
          result[:payload_hex] = payload.pack('C*').unpack1('H*').upcase
          if result[:frame_type].zero?
            result[:aps] = parse_aps(opts.merge(bytes: payload))
            return nil unless result[:aps]
          else
            return nil if payload.empty?

            result[:command_id] = payload.first
          end
          result
        rescue IndexError
          nil
        end

        public_class_method def self.parse_aps(opts = {})
          cursor = Octets.new(opts[:bytes])
          control = cursor.number
          type = control & 3
          delivery = (control >> 2) & 3
          return nil if type == 3 || delivery == 1 || control.anybits?(0x80)

          result = { frame_type: type, delivery_mode: delivery, security_enabled: control.anybits?(0x20),
                     authentication_verified: false, ack_requested: control.anybits?(0x40) }
          if type.zero? || (type == 2 && control.nobits?(0x10))
            if type.zero? && delivery == 3
              result[:group_address] = cursor.address(2)
            else
              result[:destination_endpoint] = cursor.number
            end
            result[:cluster_id] = cursor.address(2)
            result[:profile_id] = cursor.address(2)
            result[:source_endpoint] = cursor.number
          end
          result[:counter] = cursor.number
          if result[:security_enabled]
            security = parse_security(opts.merge(offset: cursor.offset))
            return security ? result.merge(security) : nil
          end
          payload = cursor.rest
          result.merge(payload_hex: payload.pack('C*').unpack1('H*').upcase)
        rescue IndexError
          nil
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ZigBee.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          raise ArgumentError, 'only 2.4 GHz O-QPSK is supported' unless opts.fetch(:phy, :oqpsk).to_sym == :oqpsk

          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          ch = ((hz - 2_405_000_000) / 5_000_000).round + 11
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 4_000_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            fallback: :raise,
            freq_obj: freq_obj,
            protocol: 'ZigBee',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, channel: ch, network_keys: opts.fetch(:network_keys, {}),
                               link_key: opts[:link_key], security_level: opts.fetch(:security_level, 5)),
            note: 'O-QPSK 2 Mcps ≡ MSK — I/Q→gmskdem→32-chip PN correlate→SHR/SFD→PHR/MHR/FCS.',
            describe: proc { |b| { modulation: 'O-QPSK', channel: ch, classification: b[:duration_ms] < 5 ? 'ACK' : 'MAC-frame' } }
          )
        end

        # Energy observations only; never substituted for protocol decoding.
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(protocol: 'ZigBee',
                                       note: 'Energy detector only; use .decode for supported protocol frames.'))
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'ZigBee' }
          out[:pan] = ::Regexp.last_match(1) if line =~ /PAN[:= ]+([0-9A-Fa-f]+)/i
          out[:src] = ::Regexp.last_match(1) if line =~ /src[:= ]+([0-9A-Fa-f:]+)/i
          out[:dst] = ::Regexp.last_match(1) if line =~ /dst[:= ]+([0-9A-Fa-f:]+)/i
          out[:cmd] = ::Regexp.last_match(1) if line =~ /\b(Beacon|Data|ACK|Cmd)\b/i
          out[:summary] = "ZigBee #{out[:cmd]} PAN=#{out[:pan]} #{out[:src]}→#{out[:dst]}"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Supported: 2.4 GHz O-QPSK (phy: :oqpsk), MAC frame versions 0/1.
            # Correct differential MSK templates, FCS, PAN/address and payload parsing.
            # MAC security v1 auxiliary header/MIC are parsed; encrypted payload stays opaque.
            # NWK v2 addresses/routes, APS unicast/broadcast/group data, command and ACK headers.
            # NWK/APS AES-CCM levels 5/6/7 supported; level 0 uses security_level: 5 by default.
            # network_keys: { sequence_number => 16-byte binary key }; link_key: binary APS data key.
            # Authentication is nested per layer; a MAC FCS is NOT NWK/APS authentication.
            # No MAC CCM, key transport/load derivation, replay policy, APS fragmentation/reassembly,
            # ZCL/ZDP semantic payload decoding, Inter-PAN, MAC version 2 or sub-GHz PHY.
            # Parse ZigBee network headers and supported APS payloads.
            #{self}.parse_nwk(bytes: 'required - NWK octets', network_keys: {}, link_key: nil)
            # Parse APS addressing and authenticated payloads with caller-supplied keys.
            #{self}.parse_aps(bytes: 'required - APS octets', link_key: 'optional - 16-byte binary key')
            # Parse an auxiliary security header and verify supported CCM protection.
            #{self}.parse_security(bytes: 'required - frame octets', offset: 'required - auxiliary header position',
                                  security_source: 'optional - eight source address octets, wire order',
                                  link_key: 'optional - 16-byte binary APS data key')
            # Authenticate and decrypt an AES-CCM message without releasing failed plaintext.
            #{self}.decrypt_ccm(key: 'required - binary key', nonce: 'required - binary nonce', aad: 'required - binary header',
                               ciphertext: 'required - binary ciphertext', mic: 'required - binary tag')
            # Normal spectral polarity and centered signals; no CFO acquisition.
            #{self}.parse_mpdu(bytes: 'required - Array of MPDU octets including FCS')
            # Detect signal energy without decoding protocol payloads.
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
              link_key: 'optional - 16-byte binary APS data key',
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
