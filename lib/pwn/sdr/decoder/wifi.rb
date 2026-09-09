# frozen_string_literal: true

require 'zlib'

module PWN
  module SDR
    module Decoder
      # Protocol frames via .decode; energy observations only via .detect.
      module WiFi
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

        # Ordered plaintext data fragments only; bounded capture-time state.
        # Protected MPDUs remain opaque; no ciphertext inference or key recovery.
        class MACReassembler
          def initialize
            @pending = {}
          end

          def feed(frame, sample_time:)
            @pending.delete_if { |_, state| sample_time - state[:time] > 1.0 }
            return frame unless frame[:type] == 2

            key = frame.values_at(:transmitter, :receiver, :source_address, :destination, :bssid,
                                  :sequence, :to_ds, :from_ds) + [frame.fetch(:qos_control, 0) & 15]
            if frame[:protected] || frame.fetch(:qos_control, 0).anybits?(0x80)
              @pending.delete(key)
              return frame
            end
            number = frame[:fragment]
            return frame if number.zero? && !frame[:more_fragments]

            payload = [frame[:payload_hex]].pack('H*')
            if payload.bytesize > 2304
              @pending.delete(key)
              return frame
            end
            if number.zero?
              @pending.shift if @pending.length >= 64
              @pending[key] = { time: sample_time, next: 1, payload: payload, previous: payload }
              return frame
            end
            state = @pending[key]
            return frame unless state
            return frame if frame[:retry] && number == state[:next] - 1 && payload == state[:previous]

            if number != state[:next] || state[:payload].bytesize + payload.bytesize > 2304
              @pending.delete(key)
              return frame
            end
            state[:payload] << payload
            state[:previous] = payload
            state[:next] += 1
            return frame if frame[:more_fragments]

            @pending.delete(key)
            body = state[:payload]
            result = frame.merge(reassembled: true, fragments: state[:next], msdu_hex: body.unpack1('H*'))
            result.merge!(ethertype: body[6, 2].unpack1('n'), network_payload_hex: body[8..].unpack1('H*')) if body.bytesize >= 8 && body.start_with?(['aaaa03000000'].pack('H*'))
            result
          end

          def clear
            @pending.clear
          end
        end

        # IEEE 802.11b 18.2/18.4 long-preamble DBPSK/Barker 1 Mbps only.
        # https://www.ieee802.org/11/Documents/DocumentArchives/1999_docs/90845b_p80211b-draft3.1.pdf
        # Integer 11 MHz chip-rate multiples; frequency-centred IQ. No OFDM/CCK,
        # DQPSK, short preamble, resampling, equalizer or clock-drift tracking.
        class DSSSIQ
          BARKER = [1, -1, 1, 1, -1, 1, 1, 1, -1, -1, -1].freeze
          SYNC = (([1] * 96) + [0xf3a0].pack('v').unpack1('b*').chars.map(&:to_i)).freeze

          def initialize(rate:)
            @rate = Integer(rate)
            raise ArgumentError, 'DSSS requires 11, 22 or 44 MHz IQ' unless [11_000_000, 22_000_000, 44_000_000].include?(@rate)

            @chips = BARKER.flat_map { |chip| [chip] * (@rate / 11_000_000) }
            @width = @chips.length
            @window = []
            @lanes = Array.new(@width) { {} }
            @count = 0
            @last_frame = -@width
            @reassembler = MACReassembler.new
          end

          def feed_iq(samples, rate: nil)
            raise ArgumentError, 'sample rate changed midstream' if rate && (rate.to_f - @rate).abs.positive?
            raise ArgumentError, 'interleaved IQ pairs required' unless samples.length.even?

            samples.each_slice(2) do |i, q|
              @count += 1
              @window << [i, q]
              @window.shift if @window.length > @width
              next unless @window.length == @width

              real = 0.0
              imag = 0.0
              power = 0.0
              @window.each_with_index do |(wi, wq), index|
                real += wi * @chips[index]
                imag += wq * @chips[index]
                power += (wi * wi) + (wq * wq)
              end
              lane = @lanes[@count % @width]
              if power < 1e-8 || ((real * real) + (imag * imag)) < 0.65 * power * @width
                lane.clear
                next
              end
              previous = lane[:previous]
              lane[:previous] = [real, imag]
              next unless previous

              scrambled = ((real * previous[0]) + (imag * previous[1])).negative? ? 1 : 0
              history = lane.fetch(:history, 0)
              bit = scrambled ^ ((history >> 3) & 1) ^ ((history >> 6) & 1)
              lane[:history] = ((history << 1) | scrambled) & 127
              frame = consume(lane, bit)
              next unless frame && @count - @last_frame >= @width

              @last_frame = @count
              frame = @reassembler.feed(frame, sample_time: @count.to_f / @rate)
              yield frame if block_given?
            end
          end

          def flush
            @window.clear
            @lanes.each(&:clear)
            @reassembler.clear
          end

          private

          def consume(lane, bit)
            bits = (lane[:bits] ||= [])
            bits << bit
            unless lane[:state]
              bits.shift if bits.length > SYNC.length
              if bits == SYNC
                lane[:state] = :header
                bits.clear
              end
              return nil
            end
            if lane[:state] == :header && bits.length == 48
              bytes = bits.pack('C*').bytes.each_slice(8).map { |byte| byte.each_with_index.sum { |b, n| b << n } }
              length = bytes[2] | (bytes[3] << 8)
              unless bytes[0] == 10 && bytes[1].nobits?(~4) && length >= 112 && (length % 8).zero? &&
                     WiFi.plcp_crc(bytes: bytes.first(4)) == (bytes[4] | (bytes[5] << 8))
                lane.clear
                return nil
              end
              lane[:length] = length
              lane[:state] = :payload
              bits.clear
            elsif lane[:state] == :payload && bits.length == lane[:length]
              mac = bits.each_slice(8).map { |byte| byte.each_with_index.sum { |b, n| b << n } }.pack('C*')
              lane.clear
              return WiFi.parse_frame(bytes: mac)&.merge(source: 'iq', integrity: 'plcp-crc16-and-mac-fcs32')
            end
            nil
          end
        end

        public_class_method def self.parse_frame(opts = {})
          bytes = opts[:bytes]
          return nil unless bytes.is_a?(String) && bytes.bytesize >= 14
          return nil unless Zlib.crc32(bytes[0...-4]) == bytes[-4, 4].unpack1('V')

          fc = bytes.unpack1('v')
          return nil unless fc.nobits?(3)

          type = (fc >> 2) & 3
          subtype = (fc >> 4) & 15
          return nil if type == 3

          control_lengths = { 10 => 16, 11 => 16, 12 => 10, 13 => 10, 14 => 16, 15 => 16 }
          length = type == 1 ? control_lengths[subtype] : 24
          return nil unless length && bytes.bytesize >= length + 4
          return nil if type == 1 && bytes.bytesize != length + 4

          address = ->(offset) { bytes[offset, 6].unpack('C*').map { |byte| format('%02x', byte) }.join(':') }
          frame = { protocol: 'WiFi', mode: :dsss_1mbps, source: 'mac', decoded: true,
                    integrity: 'mac-fcs32', type: type, subtype: subtype, duration: bytes[2, 2].unpack1('v'),
                    receiver: address.call(4), protected: fc.anybits?(0x4000), more_fragments: fc.anybits?(0x0400),
                    retry: fc.anybits?(0x0800), frame_hex: bytes.unpack1('H*'),
                    summary: "WiFi type=#{type} subtype=#{subtype}" }
          frame[:transmitter] = address.call(10) if length >= 16
          if type != 1
            ds = (fc >> 8) & 3
            return nil if type.zero? && ds != 0

            sequence = bytes[22, 2].unpack1('v')
            frame.merge!(sequence: sequence >> 4, fragment: sequence & 15, to_ds: ds.anybits?(1), from_ds: ds.anybits?(2))
            case ds
            when 0 then frame.merge!(destination: address.call(4), source_address: address.call(10), bssid: address.call(16))
            when 1 then frame.merge!(destination: address.call(16), source_address: address.call(10), bssid: address.call(4))
            when 2 then frame.merge!(destination: address.call(4), source_address: address.call(16), bssid: address.call(10))
            when 3
              length += 6
              return nil if bytes.bytesize < length + 4

              frame.merge!(destination: address.call(16), source_address: address.call(24))
            end
            if type == 2 && subtype >= 8
              return nil if bytes.bytesize < length + 6

              frame[:qos_control] = bytes[length, 2].unpack1('v')
              length += 2
              length += 4 if fc.anybits?(0x8000)
            end
          end
          return nil if bytes.bytesize < length + 4

          payload = bytes[length...-4]
          frame[:payload_hex] = payload.unpack1('H*')
          unless frame[:protected]
            if type.zero? && [4, 5, 8].include?(subtype)
              fixed = subtype == 4 ? 0 : 12
              return nil if payload.bytesize < fixed

              frame[:timestamp], frame[:beacon_interval], frame[:capabilities] = payload.unpack('Q<vv') if fixed.positive?
              elements = []
              while fixed < payload.bytesize
                return nil if fixed + 2 > payload.bytesize

                id, size = payload[fixed, 2].unpack('CC')
                return nil if fixed + 2 + size > payload.bytesize

                value = payload[fixed + 2, size]
                return nil if (id.zero? && size > 32) || (id == 3 && size != 1)

                elements << { id: id, hex: value.unpack1('H*') }
                frame[:ssid] = value.dup.force_encoding('UTF-8').scrub if id.zero?
                frame[:channel] = value.getbyte(0) if id == 3
                fixed += 2 + size
              end
              frame[:information_elements] = elements
            elsif type == 2 && payload.bytesize >= 8 && payload.start_with?([0xaa, 0xaa, 3, 0, 0, 0].pack('C*')) &&
                  frame[:fragment].zero? && fc.nobits?(0x0400) && frame.fetch(:qos_control, 0).nobits?(0x80)
              frame[:ethertype] = payload[6, 2].unpack1('n')
              frame[:network_payload_hex] = payload[8..].unpack1('H*')
            end
          end
          frame
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::WiFi.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        SUPPORTED_MODES = %i[dsss_1mbps].freeze
        DemodIQ = DSSSIQ

        # Never silently downgrade decode to energy detection.
        public_class_method def self.decode(opts = {})
          mode = opts.fetch(:mode, :dsss_1mbps).to_s.to_sym
          raise ArgumentError, "unsupported WiFi mode #{mode}; supported: #{SUPPORTED_MODES.join(', ')}" unless SUPPORTED_MODES.include?(mode)

          freq_obj = opts[:freq_obj] || {}
          rate = opts[:sample_rate] || freq_obj[:iq_rate] || 11_000_000
          demod = DSSSIQ.new(rate: rate)
          PWN::SDR::Decoder::Base.run_iq(opts.merge(freq_obj: freq_obj, protocol: 'WiFi',
                                                    sample_rate: rate, demod: demod, fallback: :raise))
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj]

          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_000_000).to_i
          proto = 'WiFi-802.11'
          demod = DetectorIQ.new(
            rate: rate, protocol: proto, modulation: 'OFDM',
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
            note: '20+ MHz OFDM — true-air I/Q path reports channel occupancy/duty.',
            describe: proc { |b| { modulation: 'OFDM', airtime_ms: b[:duration_ms] } }
          )
        end

        # IEEE 802.11b 18.2.3.6, reflected CCITT, complemented remainder.
        public_class_method def self.plcp_crc(opts = {})
          crc = 0xffff
          opts[:bytes].each do |byte|
            crc ^= byte
            8.times { crc = (crc >> 1) ^ (crc.odd? ? 0x8408 : 0) }
          end
          crc ^ 0xffff
        end

        TSHARK_FIELDS = %w[
          frame.time_relative wlan.fc.type_subtype wlan.bssid wlan.sa
          wlan.da wlan_radio.channel wlan_radio.signal_dbm wlan.ssid
        ].freeze

        public_class_method def self.parse_line(opts = {})
          f = opts[:line].to_s.split('|', -1)
          out = {
            protocol: 'WiFi', subtype: f[1], bssid: f[2], sa: f[3], da: f[4],
            channel: f[5], rssi: f[6], ssid: f[7]
          }.reject { |_, v| v.to_s.empty? }
          out[:summary] = "WiFi ch=#{out[:channel]} BSSID=#{out[:bssid]} SSID=#{out[:ssid]} RSSI=#{out[:rssi]}"
          out
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Supported mode: :dsss_1mbps only (default). Long PLCP, 1 Mbps DBPSK/Barker.
            # sample_rate: 11000000 (default), 22000000 or 44000000; centred IQ.
            # MAC: management/data (+QoS/WDS) headers, legacy control, beacon/probe IEs,
            # LLC/SNAP for unfragmented non-aggregated plaintext. Other bodies remain hex.
            # No OFDM, CCK, 2 Mbps, short preamble, decryption, or HT control decoding.
            # Ordered plaintext data-fragment reassembly: 64 flows, 2304 bytes, 1s capture-time expiry.
            # Final fragment includes msdu_hex/LLC fields; individual MPDU payload_hex stays unchanged.
            # Protected/aggregated frames stay opaque. No keys guessed, no ciphertext parsing.
            # No equalizer, resampler or clock-drift loop. Offline/streaming, NOT realtime guaranteed.
            # decode never falls back to a detector; unsupported mode/rate raises ArgumentError.
            # #{self}.detect uses the same source/lifecycle options for energy-only observations.
            # Check MAC FCS and return parsed frame fields, not PHY CRC status.
            #{self}.parse_frame(bytes: 'required - binary MAC frame String including trailing FCS')
            # Calculate the PLCP CRC16 over header octets.
            #{self}.plcp_crc(bytes: 'required - Array of PLCP header octets before the CRC')
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
