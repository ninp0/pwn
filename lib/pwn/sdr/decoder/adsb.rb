# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # ADS-B 1090 MHz Mode-S long-frame decoder. The UAT band selector
      # is retained for compatibility, but UAT demodulation is not implemented.
      #
      # Prefer PWN::FFI::{RTLSdr,AdalmPluto,HackRF} at exactly 2 Msps and run a
      # pure-Ruby Mode-S preamble correlator + 112-bit PPM slicer over
      # magnitude samples. Missing I/Q raises; use .detect for energy only.
      # Offline SBS-1 CSV → .parse_line.
      module ADSB
        SBS_FIELDS = %i[
          msg_type tx_type session_id aircraft_id icao24 flight_id
          date_gen time_gen date_log time_log callsign altitude_ft
          ground_speed_kt track_deg lat lon vertical_rate_fpm squawk
          alert emergency spi on_ground
        ].freeze

        # 8 μs Mode-S preamble at 2 Msps → 16 samples: 1 0 1 0 0 0 0 1 0 1 0 0 0 0 0 0
        PREAMBLE = [1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0].map(&:to_f).freeze
        SAMPLES_PER_US = 2 # @ 2 Msps
        # CRC-24 (Mode-S) generator 0x1FFF409  (poly over GF(2), 24-bit)
        MODE_S_CRC_POLY = 0x1FFF409

        # Streaming I/Q demod for Base.run_iq.
        class DemodIQ
          def initialize(rate: 2_000_000, reference: nil)
            raise ArgumentError, 'Mode S requires sample rate 2_000_000' unless (rate.to_f - 2_000_000).zero?

            @reference = reference
            @rate = rate.to_f
            @spb  = @rate / 1_000_000.0 # samples per µs (expect ~2)
            @mag  = []
            @seen = {}
            @cpr = {}
            @sample_offset = 0
          end

          def feed_iq(samples, rate: nil, &emit)
            @rate = rate.to_f if rate
            @spb  = @rate / 1_000_000.0
            raise ArgumentError, 'Mode S requires sample rate 2_000_000' unless @rate == 2_000_000

            samples = [@pending_i] + samples if @pending_i
            @pending_i = samples.length.odd? ? samples.last : nil
            samples = samples[0...-1] if @pending_i
            m2 = PWN::SDR::Decoder::DSP.mag_sq(iq: samples)
            @mag.concat(m2)
            # Scan the entire buffer FIRST so frames that land earlier in a
            # multi-ms chunk are not discarded by the ring-buffer clamp below.
            # Only AFTER scan() has consumed what it can do we cap residual
            # history (frame + preamble headroom ≈ 0.5 ms, keep 50 ms).
            scan(&emit)
            max = (@rate * 0.05).to_i
            return unless @mag.length > max

            @sample_offset += @mag.length - max
            @mag.shift(@mag.length - max)
          end

          private

          def scan
            plen = PREAMBLE.length
            return if @mag.length < plen + (112 * 2)

            # Sliding correlator for the 4-pulse Mode-S preamble. Require the
            # on-pulse peaks to dominate the off-slots by a clear margin and
            # require DF ∈ known set before emitting (cuts noise catastrophically).
            i = 0
            accepted = 0
            while i <= @mag.length - (plen + 224)
              # Pulse peaks at samples 0, 2, 7, 9; valleys at 1,3,4,5,6,8,10..
              p0 = @mag[i]
              p2 = @mag[i + 2]
              p7 = @mag[i + 7]
              p9 = @mag[i + 9]
              peak = (p0 + p2 + p7 + p9) / 4.0
              valley = (
                @mag[i + 1] + @mag[i + 3] + @mag[i + 4] + @mag[i + 5] +
                @mag[i + 6] + @mag[i + 8] + @mag[i + 10] + @mag[i + 12]
              ) / 8.0
              if peak > valley * 2.5 && peak.positive?
                bits = slice_ppm(@mag, i + plen, 112)
                if bits && bits.length == 112
                  df = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[0, 5])
                  # Only extended squitters use the plain CRC verified here.
                  if [17, 18].include?(df)
                    # ICAO all-zeros / all-ones is almost always garbage
                    icao_bits = bits[8, 24]
                    icao_int = PWN::SDR::Decoder::DSP.bits_to_int(bits: icao_bits)
                    if icao_int.positive? && icao_int != 0xFFFFFF && ADSB.crc_ok?(bits: bits)
                      msg = ADSB.decode_modes(bits: bits)
                      update_position(msg, (@sample_offset + i) / @rate)
                      key = msg[:raw_hex]
                      unless @seen[key]
                        @seen[key] = true
                        @seen.shift if @seen.length > 512
                        yield msg
                        accepted += 1
                      end
                      i += plen + 224
                      next
                    end
                  end
                end
              end
              i += 1
            end
            drop = [i - plen, 0].max
            @mag.shift(drop) if drop.positive?
            @sample_offset += drop
            accepted
          end

          # Capture-time seconds, not wall time: offline replay has the same
          # ten-second pairing constraint as the incoming sample stream.
          def update_position(msg, time)
            return unless msg.key?(:cpr_format)

            if msg[:on_ground]
              position = ADSB.surface_position(frame: msg, reference: @reference)
              msg.merge!(position) if position
              return
            end

            key = [msg[:df], msg[:icao24], msg[:type_code] < 19]
            pair = (@cpr[key] ||= {})
            pair[msg[:cpr_format]] = [msg.dup, time]
            @cpr.shift if @cpr.length > 512
            return unless pair[0] && pair[1]

            position = ADSB.airborne_position(even: pair[0][0], odd: pair[1][0], even_time: pair[0][1], odd_time: pair[1][1])
            msg.merge!(position) if position
          end

          # Mode-S Pulse-Position Modulation: 1 µs = 2 samples; high-first → 1.
          def slice_ppm(mag, start, nbits)
            bits = Array.new(nbits)
            nbits.times do |b|
              a = start + (b * 2)
              return nil if a + 1 >= mag.length

              bits[b] = mag[a] >= mag[a + 1] ? 1 : 0
            end
            bits
          end
        end

        # Supported Method Parameters::
        # crc = PWN::SDR::Decoder::ADSB.crc24(bits: Array<0|1>)
        # CRC over all bits except the final 24 (which hold the parity).

        public_class_method def self.crc24(opts = {})
          bits = opts[:bits] || []
          return nil if bits.length < 32

          # Mode-S CRC-24: left-shift register fed by every message bit
          # (including the 24 parity bits). A valid frame leaves residual 0.
          reg = 0
          bits.each do |b|
            reg <<= 1
            reg |= (b & 1)
            reg ^= MODE_S_CRC_POLY if reg.anybits?(0x1000000)
          end
          reg & 0xFFFFFF
        end

        # Supported Method Parameters::
        # ok = PWN::SDR::Decoder::ADSB.crc_ok?(bits: Array<0|1>)

        public_class_method def self.crc_ok?(opts = {})
          bits = opts[:bits] || []
          return false unless [56, 112].include?(bits.length)

          crc24(bits: bits).zero?
        end

        # Supported Method Parameters::
        # h = PWN::SDR::Decoder::ADSB.decode_modes(bits: Array<0|1> of length 56 or 112)

        public_class_method def self.decode_modes(opts = {})
          bits = opts[:bits] || []
          return nil unless bits.length == 112 && bits.all? { |b| [0, 1].include?(b) } && crc_ok?(bits: bits)
          return nil unless [17, 18].include?(DSP.bits_to_int(bits: bits[0, 5]))

          # DF (5) + CA (3) + ICAO (24) + ...
          df = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[0, 5])
          icao = format('%06X', PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[8, 24]))
          out = {
            protocol: 'ADSB',
            df: df,
            icao24: icao,
            bits: bits.length,
            raw_hex: bits.each_slice(4).map { |n| PWN::SDR::Decoder::DSP.bits_to_int(bits: n).to_s(16) }.join.upcase
          }
          # DF17/18 ME field (56 bits starting at bit 32)
          if [17, 18].include?(df) && bits.length >= 88
            tc = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[32, 5])
            out[:type_code] = tc
            if tc.between?(1, 4)
              # aircraft identification — 8× 6-bit AIS chars
              cs = bits[40, 48].each_slice(6).map { |ch| ais_char(code: PWN::SDR::Decoder::DSP.bits_to_int(bits: ch)) }.join.strip
              out[:callsign] = cs
            elsif tc.between?(5, 8)
              out.merge!(surface_movement(bits: bits))
              out[:cpr_format] = bits[53]
              out[:cpr_lat] = DSP.bits_to_int(bits: bits[54, 17])
              out[:cpr_lon] = DSP.bits_to_int(bits: bits[71, 17])
            elsif tc.between?(9, 18) || tc.between?(20, 22)
              out[:altitude_ft] = modes_altitude(bits12: bits[40, 12]) if tc.between?(9, 18)
              out[:gnss_height_m] = DSP.bits_to_int(bits: bits[40, 12]) if tc.between?(20, 22)
              out[:cpr_format] = bits[53]
              out[:cpr_lat] = DSP.bits_to_int(bits: bits[54, 17])
              out[:cpr_lon] = DSP.bits_to_int(bits: bits[71, 17])
            elsif tc == 19
              out.merge!(airborne_velocity(bits: bits))
            end
          end
          bits_s = []
          bits_s << "ICAO=#{out[:icao24]}"
          bits_s << "DF=#{df}"
          bits_s << "CS=#{out[:callsign]}" if out[:callsign]
          bits_s << "ALT=#{out[:altitude_ft]}ft" if out[:altitude_ft]
          bits_s << "TC=#{out[:type_code]}" if out[:type_code]
          out[:summary] = "ADSB #{bits_s.join(' ')}"
          out
        end

        private_class_method def self.surface_movement(opts = {})
          bits = opts[:bits]
          movement = DSP.bits_to_int(bits: bits[37, 7])
          out = { on_ground: true, movement: movement }
          out[:track_deg] = DSP.bits_to_int(bits: bits[45, 7]) * 360.0 / 128 if bits[44] == 1
          if movement == 1
            out[:ground_speed_kt] = 0.0
          elsif movement == 124
            out[:ground_speed_min_kt] = 175.0
          elsif movement.between?(2, 123)
            bins = [[2, 0.125, 0.125], [9, 1, 0.25], [13, 2, 0.5], [39, 15, 1], [94, 70, 2], [109, 100, 5]]
            lower, speed, step = bins.reverse.find { |entry| movement >= entry[0] }
            out[:ground_speed_kt] = speed + ((movement - lower) * step)
          end
          out
        end

        # Local surface CPR: reference must be within 45 NM of the aircraft.
        # This ambiguity constraint is caller-owned, not measurable from one
        # message. No reference means no invented position.
        public_class_method def self.surface_position(opts = {})
          frame = opts[:frame]
          reference = opts[:reference]
          return nil unless reference.is_a?(Array) && reference.length == 2 && reference.all? { |v| v.is_a?(Numeric) && v.finite? }
          return nil unless reference[0].between?(-90, 90) && reference[1].between?(-180, 180)
          return nil unless frame.is_a?(Hash) && (5..8).cover?(frame[:type_code]) && [0, 1].include?(frame[:cpr_format])
          return nil unless %i[cpr_lat cpr_lon].all? { |key| frame[key].is_a?(Integer) && frame[key].between?(0, 131_071) }

          odd = frame[:cpr_format]
          yz = frame[:cpr_lat] / 131_072.0
          xz = frame[:cpr_lon] / 131_072.0
          dlat = 90.0 / (60 - odd)
          j = (reference[0] / dlat).floor + (0.5 + ((reference[0] % dlat) / dlat) - yz).floor
          lat = dlat * (j + yz)
          return nil unless lat.between?(-90, 90)

          dlon = 90.0 / [cpr_nl(latitude: lat) - odd, 1].max
          m = (reference[1] / dlon).floor + (0.5 + ((reference[1] % dlon) / dlon) - xz).floor
          lon = (((dlon * (m + xz)) + 180) % 360) - 180
          { lat: lat, lon: lon }
        end

        private_class_method def self.airborne_velocity(opts = {})
          bits = opts[:bits]
          subtype = DSP.bits_to_int(bits: bits[37, 3])
          out = { velocity_subtype: subtype }
          return out unless subtype.between?(1, 4)

          scale = subtype.even? ? 4 : 1
          first = DSP.bits_to_int(bits: bits[46, 10])
          second = DSP.bits_to_int(bits: bits[57, 10])
          if subtype <= 2
            east = (first - 1) * scale * (bits[45] == 1 ? -1 : 1) if first.positive?
            north = (second - 1) * scale * (bits[56] == 1 ? -1 : 1) if second.positive?
            out[:east_velocity_kt] = east if east
            out[:north_velocity_kt] = north if north
            if east && north
              out[:ground_speed_kt] = Math.hypot(east, north)
              out[:track_deg] = (Math.atan2(east, north) * 180 / Math::PI) % 360 unless east.zero? && north.zero?
            end
          else
            out[:heading_deg] = first * 360.0 / 1024 if bits[45] == 1
            out[:airspeed_type] = bits[56] == 1 ? 'TAS' : 'IAS'
            out[:airspeed_kt] = (second - 1) * scale if second.positive?
          end
          vertical = DSP.bits_to_int(bits: bits[69, 9])
          if vertical.positive?
            out[:vertical_rate_fpm] = (vertical - 1) * 64 * (bits[68] == 1 ? -1 : 1)
            out[:vertical_rate_source] = bits[67] == 1 ? 'barometric' : 'GNSS'
          end
          difference = DSP.bits_to_int(bits: bits[81, 7])
          out[:gnss_baro_difference_ft] = (difference - 1) * 25 * (bits[80] == 1 ? -1 : 1) if difference.between?(1, 126)
          out
        end

        # Global airborne CPR only; timestamps are seconds on the same clock.
        # Surface CPR requires a reference and is deliberately not accepted.
        public_class_method def self.airborne_position(opts = {})
          even = opts[:even]
          odd = opts[:odd]
          times = [opts[:even_time], opts[:odd_time]]
          return nil unless even.is_a?(Hash) && odd.is_a?(Hash) && times.all? { |t| t.is_a?(Numeric) && t.finite? }
          return nil if (times[0] - times[1]).abs > 10
          return nil unless even[:icao24] == odd[:icao24] && even[:df] == odd[:df]
          return nil unless even[:cpr_format].eql?(0) && odd[:cpr_format] == 1
          return nil unless [even, odd].all? do |f|
            ((9..18).cover?(f[:type_code]) || (20..22).cover?(f[:type_code])) &&
            %i[cpr_lat cpr_lon].all? { |k| f[k].is_a?(Integer) && f[k].between?(0, 131_071) }
          end
          return nil unless (even[:type_code] < 19) == (odd[:type_code] < 19)

          yz = [even[:cpr_lat], odd[:cpr_lat]].map { |n| n / 131_072.0 }
          j = ((59 * yz[0]) - (60 * yz[1]) + 0.5).floor
          lat = [0, 1].map do |i|
            value = (360.0 / (60 - i)) * ((j % (60 - i)) + yz[i])
            value >= 270 ? value - 360 : value
          end
          return nil unless lat.all? { |v| v.abs <= 90 }

          nl = lat.map { |v| cpr_nl(latitude: v) }
          return nil unless nl[0] == nl[1]

          latest = times[0] >= times[1] ? 0 : 1
          xz = [even[:cpr_lon], odd[:cpr_lon]].map { |n| n / 131_072.0 }
          m = ((xz[0] * (nl[0] - 1)) - (xz[1] * nl[0]) + 0.5).floor
          ni = [nl[latest] - latest, 1].max
          lon = (360.0 / ni) * ((m % ni) + xz[latest])
          { lat: lat[latest], lon: lon >= 180 ? lon - 360 : lon }
        end

        private_class_method def self.cpr_nl(opts = {})
          latitude = opts[:latitude].abs
          return 1 if latitude > 87
          return 2 if latitude == 87

          (2 * Math::PI / Math.acos(1 - ((1 - Math.cos(Math::PI / 30)) / (Math.cos(latitude * Math::PI / 180)**2)))).floor
        end

        public_class_method def self.ais_char(opts = {})
          code = opts[:code]
          table = '#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######'
          table[code] || ' '
        end

        public_class_method def self.modes_altitude(opts = {})
          bits12 = opts[:bits12]
          return nil unless bits12.is_a?(Array) && bits12.length == 12 && bits12.all? { |bit| [0, 1].include?(bit) }

          if bits12[7] == 1
            n = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits12[0, 7] + bits12[8, 4])
            return (n * 25) - 1000
          end
          # Q=0: D2,D4,A1,A2,A4,B1,B2,B4 Gray-code 500-ft steps;
          # C1,C2,C4 encode the reflected five-state 100-ft sequence.
          coarse = [9, 11, 1, 3, 5, 6, 8, 10].map { |i| bits12[i] }
          fine = [0, 2, 4].map { |i| bits12[i] }
          n500, n100 = [coarse, fine].map do |gray|
            binary = 0
            gray.inject(0) do |value, bit|
              binary ^= bit
              (value << 1) | binary
            end
          end
          return nil if [0, 5, 6].include?(n100)

          n100 = 5 if n100 == 7
          n100 = 6 - n100 if n500.odd?
          (n500 * 500) + (n100 * 100) - 1300
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ADSB.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        # Energy detection only; does not identify or decode ADSB payloads.
        # Supported Method Parameters::
        # ADSB.detect(freq_obj: Hash, threshold: 8.0, on_frame: Proc)
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(
                              protocol: 'ADSB',
                              note: 'Energy detection only; no protocol payload decoding.',
                              describe: proc { |_burst| { event: 'detection', capability: 'energy-detection', decoded: false } }
                            ))
        end

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz  = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          uat = hz.between?(977_000_000, 979_000_000)
          raise ArgumentError, 'ADSB UAT decoding is not implemented; use detect for energy only' if uat

          proto = 'ADSB-1090ES'
          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_000_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            fallback: :raise,
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, reference: opts[:reference]),
            note: 'Mode-S 1 Mbit/s PPM at 2 Msps; DF17/18 CRC-validated frames only.',
            describe: proc { |b| { modulation: 'PPM', frame_len_us: 120, classification: b[:duration_ms] < 5 ? 'squitter' : 'interrogation-train' } }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ADSB.parse_line(line: 'MSG,3,1,1,ABCDEF,...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          return nil unless line.start_with?('MSG,')

          f   = line.split(',', -1)
          out = { protocol: 'ADSB' }
          SBS_FIELDS.each_with_index { |k, i| out[k] = f[i] unless f[i].to_s.empty? }
          bits = []
          bits << "ICAO=#{out[:icao24]}" if out[:icao24]
          bits << "CS=#{out[:callsign].to_s.strip}" if out[:callsign]
          bits << "ALT=#{out[:altitude_ft]}ft" if out[:altitude_ft]
          bits << "POS=#{out[:lat]},#{out[:lon]}" if out[:lat] && out[:lon]
          bits << "GS=#{out[:ground_speed_kt]}kt" if out[:ground_speed_kt]
          bits << "SQK=#{out[:squawk]}" if out[:squawk]
          out[:summary] = "ADSB #{bits.join(' ')}".strip
          out
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
            # Run crc24 and return its result
            #{self}.crc24(
              bits: 'optional - bits value consumed by #crc24 (defaults to [])'
            )

            # Run crc ok and return its result
            #{self}.crc_ok?(
              bits: 'optional - bits value consumed by #crc_ok? (defaults to [])'
            )

            # Run decode modes and return its result
            #{self}.decode_modes(
              bits: 'optional - bits value consumed by #decode_modes (defaults to [])'
            )

            # Resolve local surface CPR using a reference within 45 NM of the aircraft.
            #{self}.surface_position(frame: {}, reference: [52.0, 4.0])

            # Resolve a same-aircraft airborne even/odd CPR pair within ten seconds.
            #{self}.airborne_position(
              even: 'required - decoded even airborne CPR frame Hash',
              odd: 'required - decoded odd airborne CPR frame Hash',
              even_time: 'required - even frame capture time in seconds on the shared clock',
              odd_time: 'required - odd frame capture time in seconds on the shared clock'
            )

            # Run ais char and return its result
            #{self}.ais_char(
              code: 'optional - code value consumed by #ais_char'
            )

            # Run modes altitude and return its result
            #{self}.modes_altitude(
              bits12: 'optional - bits12 value consumed by #modes_altitude'
            )

            # Run decode and return its result
            #{self}.decode(
              reference: 'optional - [latitude, longitude] within 45 NM for local surface CPR',
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
