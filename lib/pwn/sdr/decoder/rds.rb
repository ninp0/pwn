# frozen_string_literal: true

require 'json'
require 'tty-spinner'

module PWN
  module SDR
    module Decoder
      # RDS Decoder Module for FM Radio Signals.
      #
      # Two entry points:
      #   .sample  — non-interactive structured Hash (agents / cron / tools)
      #   .decode  — realtime JSONL/callback stream with optional ENTER stop
      #
      # Both share the same GQRX RDS protocol path (U RDS, p RDS_PI / PS_NAME /
      # RADIOTEXT). .sample is the canonical mid-layer API that Extrospection
      # and any other automation should call.
      module RDS
        DEFAULT_SETTLE_SECS = 8.0
        DEFAULT_INTERVAL    = 0.75
        CALLSIGN_RX         = /\A[A-Z]{1,2}[A-Z0-9]{2,4}\z/
        CALLSIGN_RT_RX      = /\A([A-Z]{1,2}[A-Z0-9]{2,4})\b/

        # Supported Method Parameters::
        # rds_hash = PWN::SDR::Decoder::RDS.sample(
        #   gqrx_sock:   'required unless freq_obj - TCPSocket from GQRX.connect',
        #   freq_obj:    'required unless gqrx_sock - Hash from GQRX.init_freq',
        #   settle_secs: 'optional - seconds to sample (default 8, max 30)',
        #   interval:    'optional - poll interval seconds (default 0.75)',
        #   leave_enabled: 'optional - leave RDS decoder ON after sample (default false)'
        # )
        #
        # Returns::
        #   {
        #     pi:, ps_name:, radiotext:, station:,
        #     samples: Integer, settle_secs: Float,
        #     error: String?   # present when RDS backend is unavailable
        #   }

        public_class_method def self.sample(opts = {})
          sock = resolve_sock(opts)
          raise ArgumentError, 'gqrx_sock: or freq_obj: with :gqrx_sock required' unless sock

          settle   = (opts[:settle_secs] || DEFAULT_SETTLE_SECS).to_f.clamp(0.5, 30.0)
          interval = [(opts[:interval] || DEFAULT_INTERVAL).to_f, 0.1].max
          leave_on = opts[:leave_enabled] ? true : false
          samples  = []

          unless enable_rds!(sock: sock)
            return {
              pi: nil,
              ps_name: nil,
              radiotext: nil,
              station: nil,
              samples: 0,
              settle_secs: settle,
              error: 'RDS not supported by this radio backend'
            }
          end

          deadline = Time.now + settle
          while Time.now < deadline
            snap = poll_once(sock: sock)
            samples << snap unless snap[:pi].empty? && snap[:ps].empty? && snap[:rt].empty?

            # Early exit once we have a non-zero PI and a non-trivial RT —
            # give one more interval for RadioText to finish filling.
            pi = snap[:pi]
            rt = snap[:rt]
            if pi =~ /\A[0-9A-F]{4}\z/ && pi != '0000' && rt.length >= 8
              sleep interval
              snap2 = poll_once(sock: sock)
              samples << snap2
              break if snap2[:rt].length >= rt.length
            end

            sleep interval
          end

          disable_rds!(sock: sock) unless leave_on

          aggregate(samples: samples, settle_secs: settle)
        rescue ArgumentError
          raise
        rescue StandardError => e
          disable_rds!(sock: sock) if sock && !leave_on
          {
            pi: nil,
            ps_name: nil,
            radiotext: nil,
            station: nil,
            samples: samples&.length.to_i,
            settle_secs: settle,
            error: "#{e.class}: #{e.message}"
          }
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RDS.decode(
        #   freq_obj: 'required - Hash returned from PWN::SDR::GQRX.init_freq'
        # )
        #
        # Shared realtime runner: emits changed valid PI/PS/RT snapshots.
        # .sample remains the finite, aggregated snapshot API.

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        # Energy detection only; does not identify or decode RDS payloads.
        # Supported Method Parameters::
        # RDS.detect(freq_obj: Hash, threshold: 8.0, on_frame: Proc)
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(
                              protocol: 'RDS',
                              note: 'Energy detection only; no protocol payload decoding.',
                              describe: proc { |_burst| { event: 'detection', capability: 'energy-detection', decoded: false } }
                            ))
        end

        public_class_method def self.decode(opts = {})
          return decode_mpx(opts) if opts.fetch(:backend, :gqrx).to_sym == :redsea
          raise ArgumentError, 'backend must be :gqrx or :redsea' unless opts.fetch(:backend, :gqrx).to_sym == :gqrx

          freq_obj = opts[:freq_obj]
          raise ArgumentError, 'freq_obj: required' unless freq_obj.is_a?(Hash)

          gqrx_sock = freq_obj[:gqrx_sock]
          raise ArgumentError, 'freq_obj[:gqrx_sock] required' unless gqrx_sock
          raise 'RDS not supported by this radio backend' unless enable_rds!(sock: gqrx_sock)

          interval = [(opts[:interval] || DEFAULT_INTERVAL).to_f, 0.01].max
          first = true
          reader = proc do
            sleep interval unless first
            first = false
            poll_once(sock: gqrx_sock)
          end
          last_resp = nil
          Base.send(:run_stream, opts.merge(
                                   protocol: 'RDS', reader: reader,
                                   log_obj: Base.send(:strip_freq_obj, freq_obj: freq_obj)
                                 )) do |snap, emit|
            next unless snap

            pi = snap[:pi].to_s.upcase
            next unless pi.match?(/\A[0-9A-F]{4}\z/) && pi != '0000'

            response = { rds_pi: pi, rds_ps_name: snap[:ps].to_s, rds_radiotext: snap[:rt].to_s }
            next if response == last_resp

            last_resp = response.dup
            emit.call(response.merge(
                        protocol: 'RDS', event: 'station', capability: 'backend-rds',
                        summary: "Program ID: #{pi} | Station Name: #{response[:rds_ps_name]} | Radio Txt: #{response[:rds_radiotext]}"
                      ))
          end
        ensure
          disable_rds!(sock: gqrx_sock) if gqrx_sock
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Native PHY: backend: :redsea runs the actual C++/liquid-dsp decoder.
            # Requires an explicit FM-MPX file or raw mono s16le MPX IO (not speaker audio).
            # No implicit RF. Emits only complete four-block syndrome-checked groups.
            #{self}.decode(freq_obj: {}, backend: :redsea, executable: 'redsea', file: 'mpx.flac', interactive: false)
            # Default backend: :gqrx retains historical metadata snapshots, not native PHY.
            # Detect energy only (not protocol payloads); accepts Base runner controls.
            #{self}.detect(freq_obj: {}, threshold: 8.0, on_frame: nil)
            # Run sample and return its result
            #{self}.sample(
              gqrx_sock: 'required - required unless freq_obj - TCPSocket from GQRX.connect',
              freq_obj: 'required - required unless gqrx_sock - Hash from GQRX.init_freq',
              settle_secs: 'optional - seconds to sample (default 8, max 30)',
              interval: 'optional - poll interval seconds (default 0.75)',
              leave_enabled: 'optional - leave RDS decoder ON after sample (default false)',
              pi: 'required - ps_name:, radiotext:, station:',
              samples: 'required - Integer, settle_secs: Float',
              error: 'required - String?   # present when RDS backend is unavailable'
            )

            # Realtime RDS snapshots via Base (ENTER or stop/duration ends the stream)
            #{self}.decode(
              freq_obj: 'required - Hash returned from PWN::SDR::GQRX.init_freq',
              on_frame: 'optional - callback receiving each emitted Hash',
              output: 'optional - writable IO (default stdout)',
              interactive: 'optional - false disables ENTER input',
              duration: 'optional - finite seconds to run',
              stop: 'optional - callable returning true to stop',
              queue_size: 'optional - bounded pending snapshots (default 8)',
              log_file: 'optional - JSONL path or false to disable logging',
              interval: 'optional - polling interval seconds (default 0.75)'
              # backend: :redsea; executable: native binary path; file: containerized MPX
              # source: raw MPX IO; sample_rate: 128000..384000 (default 192000)
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        # ---- internals -------------------------------------------------------

        # Native redsea (C++/liquid-dsp) receives 57 kHz RDS from FM MPX,
        # not GQRX station strings. No RF source is chosen implicitly.
        private_class_method def self.decode_mpx(opts = {})
          require 'open3'
          require 'json'
          source = opts[:source]
          file = opts[:file]
          raise ArgumentError, 'provide exactly one MPX file: or raw s16le source:' unless file.nil? ^ source.nil?
          raise ArgumentError, 'source must be a readable IO' if source && !source.respond_to?(:readpartial)

          rate = Integer(opts.fetch(:sample_rate, 192_000))
          raise ArgumentError, 'MPX sample rate must be 128000..384000 Hz' unless (128_000..384_000).cover?(rate)

          args = [opts.fetch(:executable, 'redsea').to_s, '--no-fec', '--show-raw']
          args.concat(file ? ['--file', File.expand_path(file)] : ['--input', 'mpx', '--samplerate', rate.to_s])
          input, output, error, child = Open3.popen3(*args)
          stderr = ''.b
          errors = Thread.new do
            loop do
              chunk = error.readpartial(4096)
              stderr << chunk if stderr.bytesize < 16_384
            end
          rescue EOFError
            nil
          end
          feeder = if source
                     Thread.new do
                       count = 0
                       begin
                         loop do
                           bytes = source.readpartial(8192)
                           count += bytes.bytesize
                           input.write(bytes)
                         end
                       rescue EOFError
                         raise IOError, 'Incomplete MPX s16le sample at EOF' if count.odd?
                       ensure
                         input.close unless input.closed?
                       end
                     end
                   else
                     input.close
                     nil
                   end
          feeder.report_on_exception = false if feeder
          reader = lambda do
            line = output.gets(65_537)
            raise IOError, 'Oversized redsea response' if line && line.bytesize > 65_536

            if line.nil?
              status = child.value
              errors.join
              raise IOError, "redsea failed (#{status.exitstatus}): #{stderr}" unless status.success?
              raise IOError, 'redsea exited before MPX source EOF' if feeder&.alive?

              feeder&.value
            end
            line
          end
          Base.send(:run_stream, opts.merge(protocol: 'RDS', reader: reader, log_obj: { backend: 'redsea', input: 'FM-MPX' })) do |line, emit|
            next unless line

            fields = JSON.parse(line)
            # --no-fec rejects invalid syndromes, but redsea can still print
            # partial groups. Require all four intact blocks before claiming CRC.
            raw = fields['raw_data'].to_s
            next unless raw.match?(/\A[0-9A-F]{4}(?: [0-9A-F]{4}){3}\z/) && fields['group']
            next unless fields['pi'].to_s.match?(/\A0x[0-9A-F]{4}\z/)

            emit.call(protocol: 'RDS', event: 'group', capability: 'native-mpx-rds',
                      decoded: true, checksum_verified: true, encrypted: false,
                      rds_pi: fields['pi'].delete_prefix('0x'), group: fields['group'],
                      raw_group_hex: raw.delete(' '), backend: 'redsea', backend_fields: fields)
          end
        ensure
          if child&.alive?
            begin
              Process.kill('TERM', child.pid)
            rescue Errno::ESRCH
              nil
            end
            unless child.join(0.5)
              begin
                Process.kill('KILL', child.pid)
              rescue Errno::ESRCH
                nil
              end
            end
          end
          [feeder, errors].compact.each do |thread|
            thread.kill if thread.alive?
            thread.join
          end
          [input, output, error, source].compact.each { |io| io.close if io.respond_to?(:closed?) && !io.closed? }
          child&.join(1)
        end

        private_class_method def self.resolve_sock(opts = {})
          return opts[:gqrx_sock] if opts[:gqrx_sock]

          fo = opts[:freq_obj]
          return fo[:gqrx_sock] if fo.is_a?(Hash)

          nil
        end

        private_class_method def self.enable_rds!(opts = {})
          sock = opts[:sock]
          begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U RDS 0', resp_ok: 'RPRT 0')
          rescue StandardError
            nil
          end
          begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U RDS 1', resp_ok: 'RPRT 0')
            true
          rescue StandardError
            false
          end
        end

        private_class_method def self.disable_rds!(opts = {})
          sock = opts[:sock]
          PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U RDS 0')
        rescue StandardError
          nil
        end

        private_class_method def self.poll_once(opts = {})
          sock = opts[:sock]
          pi = begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'p RDS_PI').to_s.strip.chomp.upcase
          rescue StandardError
            ''
          end
          ps = begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'p RDS_PS_NAME').to_s.strip.chomp
          rescue StandardError
            ''
          end
          rt = begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'p RDS_RADIOTEXT').to_s.strip.chomp
          rescue StandardError
            ''
          end
          { pi: pi, ps: ps, rt: rt }
        end

        # Fold raw poll samples into the public Hash shape expected by
        # Extrospection.rf_tune / agents (pi / ps_name / radiotext / station).
        private_class_method def self.aggregate(opts = {})
          samples = opts[:samples] || []
          settle  = opts[:settle_secs]

          best_pi = samples.map { |s| s[:pi] }.find { |p| p =~ /\A[0-9A-F]{4}\z/ && p != '0000' }
          station_samples = samples.select { |s| s[:pi] == best_pi }

          # PS often scrolls (artist / title / callsign cycle) — collect every
          # non-empty sample, prefer a short all-caps callsign-like token, and
          # fall back to the longest only when no callsign was seen.
          ps_candidates = station_samples.map { |s| s[:ps].to_s.strip }.reject(&:empty?)
          callsign_like = ps_candidates.find { |p| p =~ CALLSIGN_RX }
          best_ps = callsign_like || ps_candidates.max_by(&:length)
          best_ps = "#{best_ps}        "[0, 8].rstrip if best_ps
          best_rt = station_samples.map { |s| s[:rt].to_s.rstrip }.reject(&:empty?).max_by(&:length)

          station = nil
          if best_rt && best_rt =~ CALLSIGN_RT_RX
            station = Regexp.last_match(1)
          elsif callsign_like
            station = callsign_like
          elsif best_ps && best_ps =~ CALLSIGN_RX
            station = best_ps
          end

          # If station callsign is known and best_ps is just a mid-scroll
          # fragment of RadioText, prefer station so callers use station + RT.
          best_ps = station if station && best_ps && best_rt && best_ps != station && best_rt.include?(best_ps)

          {
            pi: best_pi,
            ps_name: best_ps,
            radiotext: best_rt,
            station: station,
            samples: samples.length,
            settle_secs: settle
          }
        end
      end
    end
  end
end
