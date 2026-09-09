# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # GPS L1 C/A acquisition (.detect) and optional native IQ/LNAV decoding.
      # LNAV framing/parity does not imply ephemeris assembly or PVT.
      #
      # Parallel-code-phase search: 1 ms of I/Q resampled to 2.046 Msps
      # (2 samp/chip), FFT-correlated (via PWN::FFI::FFTW.cfft) against
      # each PRN 1..32 Gold code across ±5 kHz Doppler in 500 Hz steps.
      # Emits {prn:, doppler_hz:, code_phase_chips:, cn0_db_hz:} for every
      # satellite whose peak/next-peak ratio clears threshold — the same
      # cold-start acquisition every GNSS receiver runs, no gnss-sdr binary.
      module GPS
        CHIP_RATE   = 1_023_000
        ACQ_RATE    = 2_046_000 # 2 samp/chip → 2046-point FFT
        DOPP_RANGE  = 5000
        DOPP_STEP   = 500
        ACQ_THRESH  = 2.5 # peak / mean ratio

        # Streaming L1 C/A acquisition demod for Base.run_iq.
        class DemodIQ
          def initialize(rate:)
            @rate  = rate.to_f
            @buf   = []
            @seen  = {}
            @codes = {}
          end

          def feed_iq(samples, rate: nil)
            @rate = rate.to_f if rate
            @buf.concat(samples)
            need = (@rate / 1000.0).ceil * 2 # 1 ms of interleaved complex samples
            while @buf.length >= need
              ms = PWN::SDR::Decoder::DSP.resample_iq(
                iq: @buf.shift(need), src_rate: @rate, dst_rate: ACQ_RATE
              )[0, 2046 * 2]
              next if ms.nil? || ms.length < 2046 * 2

              acquire(ms).each do |h|
                key = "PRN#{h[:prn]}"
                next if @seen[key] && (@seen[key] - h[:cn0_db_hz]).abs < 1.5

                @seen[key] = h[:cn0_db_hz]
                yield h.merge(capability: 'acquisition-only', decoded: false)
              end
            end
          end

          private

          def code_fft(prn)
            @codes[prn] ||= begin
              chips = PWN::SDR::Decoder::DSP.ca_code(prn: prn)
              # upsample to 2 samp/chip, complex (Q=0)
              iq = Array.new(2046 * 2, 0.0)
              2046.times { |i| iq[i * 2] = chips[i / 2] }
              PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: iq, n: 2046) : PWN::SDR::Decoder::DSP.dft_naive(iq: iq, n: 2046)
            end
          end

          def acquire(ms_iq)
            out = []
            (1..32).each do |prn|
              cf = code_fft(prn)
              best = { peak: 0.0, dopp: 0, code: 0, floor: 1.0 }
              (-DOPP_RANGE..DOPP_RANGE).step(DOPP_STEP) do |fd|
                mixed = PWN::SDR::Decoder::DSP.mix_iq(iq: ms_iq, rate: ACQ_RATE, freq: fd)
                sig_f = PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: mixed, n: 2046) : PWN::SDR::Decoder::DSP.dft_naive(iq: mixed, n: 2046)
                # X = FFT(sig) · conj(FFT(code)); corr = |IFFT(X)|
                x_iq = Array.new(2046 * 2)
                2046.times do |k|
                  ar, ai = sig_f[k]
                  br, bi = cf[k]
                  x_iq[k * 2]       = (ar * br) + (ai * bi)
                  x_iq[(k * 2) + 1] = (ai * br) - (ar * bi)
                end
                corr = PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: x_iq, n: 2046, sign: :backward) : PWN::SDR::Decoder::DSP.dft_naive(iq: x_iq, n: 2046)
                mag = corr.map { |re, im| (re * re) + (im * im) }
                pk_i = mag.each_with_index.max_by(&:first).last
                pk   = mag[pk_i]
                # exclude ±2 chips around peak for floor estimate
                floor = (mag.sum - mag[[pk_i - 4, 0].max, 9].sum) / (mag.length - 9)
                best = { peak: pk, floor: floor, dopp: fd, code: pk_i } if pk / floor > best[:peak] / [best[:floor], 1e-12].max
              end
              ratio = best[:peak] / [best[:floor], 1e-12].max
              next unless ratio >= ACQ_THRESH

              cn0 = 10.0 * Math.log10(ratio * 1000.0) # 1 ms coherent
              out << {
                protocol: 'GPS', event: 'acquisition', modulation: 'BPSK/DSSS',
                prn: prn, doppler_hz: best[:dopp],
                code_phase_chips: (best[:code] / 2.0).round(1),
                peak_to_floor: ratio.round(2), cn0_db_hz: cn0.round(1),
                summary: "GPS PRN#{prn} acquired: Doppler=#{best[:dopp]}Hz code=#{(best[:code] / 2.0).round(1)} C/N0≈#{cn0.round(1)}dB-Hz"
              }
            end
            out
          end
        end

        # Optional native GNSS-SDR receiver, with a Ruby protocol boundary.
        # Configuration and process lifetime are kept together for auditability.
        class IQTracker # rubocop:disable Metrics/ClassLength
          def initialize(opts)
            @opts = opts
            @file = File.expand_path(opts[:file].to_s)
            raise ArgumentError, 'GPS IQ requires explicit source: :file and a regular file' unless opts[:source] == :file && File.file?(@file)
            raise ArgumentError, 'GPS filename contains configuration delimiters' if @file.match?(/[\r\n;]/)

            @rate = Integer(opts.fetch(:sample_rate, 4_000_000))
            raise ArgumentError, 'GPS sample_rate must be between 2 and 25 Msps' unless @rate.between?(2_000_000, 25_000_000)

            @format = { cs16: ['ishort', 'Ishort_To_Complex', 4], cs8: ['ibyte', 'Ibyte_To_Complex', 2], cf32: ['gr_complex', 'Pass_Through', 8] }[opts.fetch(:iq_format, :cs16)]
            raise ArgumentError, 'GPS iq_format must be :cs16, :cs8 or :cf32' unless @format
            raise ArgumentError, 'GPS IQ file contains an incomplete sample or is empty' if File.empty?(@file) || (File.size(@file) % @format[2]).positive?

            @duration = Float(opts.fetch(:duration, 300))
            raise ArgumentError, 'GPS duration must be finite and positive' unless @duration.finite? && @duration.positive?
          end

          def configuration(port)
            {
              'GNSS-SDR.internal_fs_sps' => 2_000_000,
              'ControlThread.wait_for_flowgraph' => false,
              'SignalSource.implementation' => 'File_Signal_Source',
              'SignalSource.filename' => @file,
              'SignalSource.item_type' => @format[0],
              'SignalSource.sampling_frequency' => @rate,
              'SignalSource.samples' => 0,
              'SignalSource.repeat' => false,
              'SignalSource.enable_throttle_control' => true,
              'SignalConditioner.implementation' => 'Signal_Conditioner',
              'DataTypeAdapter.implementation' => @format[1],
              'InputFilter.implementation' => 'Pass_Through',
              'Resampler.implementation' => 'Direct_Resampler',
              'Resampler.sample_freq_in' => @rate,
              'Resampler.sample_freq_out' => 2_000_000,
              'Resampler.item_type' => 'gr_complex',
              'Channels_1C.count' => 8,
              'Channels.in_acquisition' => 1,
              'Channel.signal' => '1C',
              'Acquisition_1C.implementation' => 'GPS_L1_CA_PCPS_Acquisition',
              'Acquisition_1C.item_type' => 'gr_complex',
              'Acquisition_1C.coherent_integration_time_ms' => 1,
              'Acquisition_1C.pfa' => 0.01,
              'Acquisition_1C.doppler_max' => 10_000,
              'Acquisition_1C.doppler_step' => 250,
              'Acquisition_1C.blocking' => true,
              'Tracking_1C.implementation' => 'GPS_L1_CA_DLL_PLL_Tracking',
              'Tracking_1C.item_type' => 'gr_complex',
              'Tracking_1C.pll_bw_hz' => 40.0,
              'Tracking_1C.dll_bw_hz' => 4.0,
              'TelemetryDecoder_1C.implementation' => 'GPS_L1_CA_Telemetry_Decoder',
              'Observables.implementation' => 'Hybrid_Observables',
              'PVT.implementation' => 'RTKLIB_PVT',
              'PVT.positioning_mode' => 'Single',
              'PVT.flag_rtcm_server' => false,
              'PVT.flag_rtcm_tty_port' => false,
              'PVT.flag_nmea_tty_port' => false,
              'NavDataMonitor.enable_monitor' => true,
              'NavDataMonitor.client_addresses' => '127.0.0.1',
              'NavDataMonitor.port' => port
            }.map { |key, value| "#{key}=#{value}" }.unshift('[GNSS-SDR]').join("\n")
          end

          def run
            require 'socket'
            require 'io/wait'
            require 'tmpdir'
            require 'json'
            frames = []
            count = 0
            reason = :eof
            socket = UDPSocket.new
            socket.bind('127.0.0.1', 0)
            Dir.mktmpdir('pwn-gps-') do |directory|
              config = File.join(directory, 'receiver.conf')
              diagnostics = File.join(directory, 'receiver.log')
              File.write(config, configuration(socket.addr[1]))
              begin
                pid = Process.spawn(@opts.fetch(:gnss_sdr, 'gnss-sdr'), "--config_file=#{config}", "--log_dir=#{directory}", in: File::NULL, out: diagnostics, err: %i[child out], chdir: directory, pgroup: true)
              rescue Errno::ENOENT
                raise LoadError, 'GPS IQ tracking requires optional native gnss-sdr (tested 0.0.21); install gnss-sdr or use :lnav_bits'
              end
              deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @duration
              begin
                loop do
                  if @opts[:stop]&.call
                    reason = :stopped
                    break
                  end
                  if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
                    reason = :duration
                    break
                  end
                  if socket.wait_readable(0.05)
                    packet = self.class.parse_packet(packet: socket.recv(4096))
                    if packet && packet[:system] == 'G' && packet[:signal] == '1C'
                      frame = GPS.decode_monitor(packet)
                      if frame
                        count += 1
                        frames << frame if frames.length < 1000
                        @opts[:output]&.write("#{JSON.generate(frame)}\n")
                        @opts[:output]&.flush
                        @opts[:on_frame]&.call(frame)
                      end
                    end
                    next
                  end
                  status = Process.waitpid2(pid, Process::WNOHANG)
                  next unless status

                  pid = nil
                  raise IOError, "gnss-sdr failed: #{File.read(diagnostics)[-4000, 4000] || File.read(diagnostics)}" unless status[1].success?

                  break
                end
              ensure
                if pid
                  Process.kill('TERM', -pid)
                  limit = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
                  until Process.waitpid(pid, Process::WNOHANG)
                    if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= limit
                      Process.kill('KILL', -pid)
                      Process.waitpid(pid)
                      break
                    end
                    sleep 0.02
                  end
                end
              end
            end
            { protocol: 'GPS', backend: 'gnss-sdr', frames: frames, frame_count: count, reason: reason, decoded: count.positive? }
          ensure
            socket&.close
          end

          public_class_method def self.parse_packet(opts = {})
            packet = opts[:packet]
            return nil unless packet.bytesize <= 4096

            bytes = packet.bytes
            read_varint = lambda do
              value = 0
              10.times do |index|
                byte = bytes.shift
                raise ArgumentError unless byte

                value |= (byte & 127) << (index * 7)
                return value if byte < 128
              end
              raise ArgumentError
            end
            fields = {}
            until bytes.empty?
              tag = read_varint.call
              key = { 1 => :system, 2 => :signal, 3 => :prn, 4 => :tow_ms, 5 => :nav_message }[tag >> 3]
              case tag & 7
              when 0
                value = read_varint.call
              when 2
                length = read_varint.call
                return nil if length > bytes.length

                value = bytes.shift(length).pack('C*')
              else
                return nil
              end
              fields[key] = value if key
            end
            fields
          rescue ArgumentError
            nil
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GPS.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # IQ mode supervises an optional native GNSS-SDR file receiver. It never
        # selects hardware. Callbacks/output are synchronous; duration/stop are
        # checked between callbacks. Detection alone uses Base.run_iq.
        public_class_method def self.decode(opts = {})
          mode = opts.fetch(:mode, :iq)
          raise ArgumentError, 'GPS mode must be :iq or :lnav_bits' unless %i[iq lnav_bits].include?(mode)
          return IQTracker.new(opts).run if mode == :iq

          chunks = opts[:bit_chunks]
          raise ArgumentError, ':lnav_bits requires enumerable bit_chunks of tracked 50 bit/s NAV data' unless chunks.respond_to?(:each)

          buffer = []
          frames = []
          chunks.each do |chunk|
            raise ArgumentError, 'bit_chunks must contain arrays of binary bits' unless chunk.is_a?(Array) && chunk.all? { |b| b.is_a?(Integer) && [0, 1].include?(b) }

            buffer.concat(chunk)
            while buffer.length >= 300
              frame = decode_subframe(bits: buffer.first(300))
              buffer.shift(frame ? 300 : 1)
              next unless frame

              frames << frame
              opts[:on_frame]&.call(frame)
            end
          end
          frames
        end

        # IS-GPS-200 Table 20-XIV parity matrix. Input is already tracked
        # LNAV symbols, not C/A chips or IQ. All ten words must pass parity.
        LNAV_PARITY_MASKS = [0xbb1f3480, 0x5d8f9a40, 0xaec7cd00, 0x5763e680, 0x6bb1f340, 0x8b7a89c0].freeze

        public_class_method def self.decode_subframe(opts = {})
          bits = opts[:bits]
          raise ArgumentError, 'LNAV subframe requires exactly 300 binary bits' unless bits.is_a?(Array) && bits.length == 300 && bits.all? { |b| b.is_a?(Integer) && [0, 1].include?(b) }

          preamble = bits.first(8).join
          return nil unless %w[10001011 01110100].include?(preamble)

          raw_words = bits.each_slice(30).map { |word| word.reduce(0) { |a, b| (a << 1) | b } }
          [0, 0x3fffffff].each do |polarity|
            4.times do |initial|
              previous = initial
              data = []
              raw_words.each do |raw|
                raw ^= polarity
                word = (previous << 30) | raw
                word ^= 0x3fffffc0 if previous.odd?
                parity = LNAV_PARITY_MASKS.reduce(0) { |a, mask| (a << 1) | ((word & mask).digits(2).sum & 1) }
                break unless parity == (raw & 0x3f)

                data << ((word >> 6) & 0xffffff)
                previous = raw & 3
              end
              next unless data.length == 10 && (data[0] >> 16) == 0x8b

              subframe_id = (data[1] >> 2) & 7
              tow = data[1] >> 7
              next unless subframe_id.between?(1, 5) && tow < 100_800
              next unless (raw_words[1] ^ polarity).nobits?(3) && (raw_words[9] ^ polarity).nobits?(3)

              frame = {
                protocol: 'GPS', event: 'lnav-subframe', capability: 'lnav-symbol-decode', decoded: true,
                checksum_verified: true, integrity: { algorithm: 'LNAV-word-parity', valid: true, words_verified: 10 },
                subframe_id: subframe_id, tow_next_seconds: tow * 6,
                alert: (data[1] >> 6).allbits?(1), anti_spoof: (data[1] >> 5).allbits?(1),
                payload_hex: data.map { |word| format('%06x', word) }.join, payload_bits: 240,
                summary: "GPS LNAV subframe #{subframe_id} parity verified TOW(next)=#{tow * 6}s"
              }
              frame[:week_mod1024] = data[2] >> 14 if subframe_id == 1
              return frame
            end
          end
          nil
        end

        # GNSS-SDR monitor words have data D30* de-inversion already applied.
        # Restore the transmitted representation; never bypass our parity checks.
        public_class_method def self.decode_monitor(opts = {})
          message = opts[:nav_message]
          return nil unless message.is_a?(String) && message.match?(/\A[01]{300}\z/) && opts[:prn].is_a?(Integer) && opts[:prn].between?(1, 32)

          previous = 0 # LNAV word 10 terminates with D29*=D30*=0.
          bits = message.scan(/.{30}/).flat_map do |encoded|
            word = encoded.to_i(2)
            raw = previous.odd? ? word ^ 0x3fffffc0 : word
            previous = word & 3
            format('%030b', raw).chars.map(&:to_i)
          end
          frame = decode_subframe(bits: bits)
          frame&.merge(prn: opts[:prn], capability: 'iq-lnav-decode', backend: 'gnss-sdr')
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj] || {}
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_048_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: 'GPS-L1CA',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: 'BPSK/DSSS 1.023 Mcps — I/Q→FFT parallel-code-phase acquisition (PWN::FFI::FFTW) → PRN/Doppler/C-N0.',
            describe: proc { |_b| { modulation: 'BPSK/DSSS', chip_rate: CHIP_RATE } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'GPS' }
          out[:prn]  = ::Regexp.last_match(1) if line =~ /PRN[ =]?(\d{1,2})/
          out[:cn0]  = ::Regexp.last_match(1) if line =~ /CN0[ =]?([\d.]+)/i
          out[:lat]  = ::Regexp.last_match(1) if line =~ /Lat(?:itude)?\s*=\s*(-?[\d.]+)/i
          out[:lon]  = ::Regexp.last_match(1) if line =~ /Long(?:itude)?\s*=\s*(-?[\d.]+)/i
          out[:alt]  = ::Regexp.last_match(1) if line =~ /Height\s*=\s*(-?[\d.]+)/i
          out[:nmea] = line if line.start_with?('$G')
          out[:summary] = out[:lat] ? "GPS FIX #{out[:lat]},#{out[:lon]}" : "GPS PRN#{out[:prn]} CN0=#{out[:cn0]}"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Parse a bounded GNSS-SDR monitor protobuf datagram.
            #{self}::IQTracker.parse_packet(packet: 'required - binary String containing one monitor datagram')

            # Track L1 C/A IQ and emit independently parity-verified LNAV frames.
            # Requires optional native gnss-sdr; never opens RF hardware.
            #{self}.decode(
              mode: 'optional - :iq (default) or :lnav_bits',
              source: 'required - :file for IQ mode',
              file: 'required - regular interleaved IQ file for IQ mode',
              sample_rate: 'optional - 2000000..25000000 Hz, default 4000000',
              iq_format: 'optional - :cs16 (default), :cs8 or :cf32, native little-endian',
              gnss_sdr: 'optional - native receiver executable, default gnss-sdr',
              duration: 'optional - positive finite timeout, default 300 seconds',
              stop: 'optional - cooperative callable checked between callbacks',
              output: 'optional - writable JSONL IO',
              bit_chunks: 'required - Enumerable of Array<0|1> for :lnav_bits only',
              on_frame: 'optional - synchronous callback before source EOF'
            )
            # Restore GNSS-SDR monitor D30 inversion and verify all word parities.
            #{self}.decode_monitor(
              nav_message: 'required - 300-character monitor bit string',
              prn: 'required - GPS PRN integer 1..32'
            )
            # Verify all ten LNAV word parities and extract subframe header fields.
            #{self}.decode_subframe(bits: 'required - exactly 300 binary bits; nil on integrity failure')

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
