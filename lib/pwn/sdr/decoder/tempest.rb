# frozen_string_literal: true

require 'tempfile'

module PWN
  module SDR
    module Decoder
      # Pure-Ruby TEMPEST / Van Eck raster decoder. Recovers a greyscale
      # candidate raster from AM on a display pixel-clock harmonic
      # captured as I/Q (RTL-SDR, HackRF, Pluto, Soapy, or a .cu8/.cs16 file).
      # Magnitude envelope is resampled to one sample per pixel, packed into
      # H×V lines using a VESA timing, and written as Netpbm P5 PGM.
      # No TempestSDR / GNU Radio dependency. Assumes known timing and frame
      # origin; no automatic sync acquisition, drift tracking, or proof that
      # the raster is a monitor image. Sample-and-hold interpolation cannot
      # recover pixel detail absent from the capture bandwidth.
      module Tempest
        MODES = {
          'vga_640x480_60' => {
            h_active: 640, h_total: 800, v_active: 480, v_total: 525,
            refresh: 60.0, pixel_clock: 25_175_000
          },
          'svga_800x600_60' => {
            h_active: 800, h_total: 1_056, v_active: 600, v_total: 628,
            refresh: 60.0, pixel_clock: 40_000_000
          },
          'xga_1024x768_60' => {
            h_active: 1_024, h_total: 1_344, v_active: 768, v_total: 806,
            refresh: 60.0, pixel_clock: 65_000_000
          },
          'hd_1280x720_60' => {
            h_active: 1_280, h_total: 1_650, v_active: 720, v_total: 750,
            refresh: 60.0, pixel_clock: 74_250_000
          }
        }.freeze

        # Streaming I/Q demodulator for Base.run_iq.
        class Demod
          def initialize(opts = {})
            timing = PWN::SDR::Decoder::Tempest.resolve_timing(opts)
            @h_active = timing[:h_active]
            @h_total  = timing[:h_total]
            @v_active = timing[:v_active]
            @v_total  = timing[:v_total]
            @refresh  = timing[:refresh]
            unless [@h_active, @h_total, @v_active, @v_total].all?(&:positive?) &&
                   @h_active <= @h_total && @v_active <= @v_total && @refresh.finite? && @refresh.positive?
              raise ArgumentError, 'invalid raster timing: active dimensions must fit positive totals and refresh'
            end

            @pixel_hz = (@h_total * @v_total * @refresh).to_f
            raise ArgumentError, 'pixel rate must be finite' unless @pixel_hz.finite?

            stamp = Time.now.strftime('%Y%m%d_%H%M%S')
            @pgm_path = opts[:out_path] || "/tmp/tempest_#{stamp}.pgm"
            @frames_want = opts[:continuous] ? nil : [opts[:frames].to_i, 1].max
            @mag_buf = []
            @src_rate = nil
            @phase = 0.0
            @pending_i = nil
            @written = 0
          end

          def feed_iq(iq_samples, rate:, &emit)
            raise ArgumentError, 'sample rate must be finite and positive' unless rate.to_f.finite? && rate.to_f.positive?
            raise ArgumentError, 'sample rate changed during raster' if @src_rate && (@src_rate - rate.to_f).abs > 1e-9

            @src_rate ||= rate.to_f
            iq_samples.each do |value|
              break if @frames_want && @written >= @frames_want

              if @pending_i.nil?
                @pending_i = value
                next
              end
              magnitude = Math.hypot(@pending_i, value)
              @pending_i = nil
              # Stateful sample-and-hold: transport chunk boundaries never reset
              # pixel phase. Retain at most one raster, even during upsampling.
              @phase += @pixel_hz
              while @phase >= @src_rate
                @phase -= @src_rate
                @mag_buf << magnitude
                drain(emit: emit) if @mag_buf.length == @h_total * @v_total
                break if @frames_want && @written >= @frames_want
              end
            end
          end

          def finish
            drain(force: true)
            { path: @pgm_path, width: @h_active, height: @v_active, frames: @written }
          end

          private

          def drain(opts = {})
            emit = opts[:emit]
            force = opts[:force] ? true : false
            need = @h_total * @v_total
            while @mag_buf.length >= need && (@frames_want.nil? || @written < @frames_want)
              frame = @mag_buf.shift(need)
              write_pgm(pixels: frame)
              @written += 1
              emit&.call(
                protocol: 'TEMPEST',
                event: 'frame',
                frames: @written,
                width: @h_active,
                height: @v_active,
                pgm: @pgm_path,
                summary: "TEMPEST frame #{@written} #{@h_active}x#{@v_active} → #{@pgm_path}"
              )
            end
            @mag_buf.clear if force
          end

          def write_pgm(opts = {})
            pixels = Array(opts[:pixels])
            span_lo = pixels.min || 0.0
            span_hi = pixels.max || 1.0
            span = span_hi - span_lo
            span = 1.0 if span <= 0
            Tempfile.create(['tempest', '.pgm'], File.dirname(@pgm_path)) do |io|
              io.binmode
              io.write("P5\n#{@h_active} #{@v_active}\n255\n")
              @v_active.times do |row|
                base = row * @h_total
                row_pix = pixels[base, @h_active] || []
                bytes = row_pix.map { |v| (((v - span_lo) / span) * 255).clamp(0, 255).round }
                io.write(bytes.pack('C*'))
              end
              io.close
              File.rename(io.path, @pgm_path)
            end
          end
        end

        # Supported Method Parameters::
        # modes = PWN::SDR::Decoder::Tempest.modes(
        #   name: 'optional - Symbol/String mode key to return one timing Hash'
        # )

        public_class_method def self.modes(opts = {})
          name = opts[:name]
          return MODES.dup if name.nil? || name.to_s.empty?

          key = name.to_s.downcase
          timing = MODES[key]
          raise "ERROR: unknown TEMPEST mode #{name.inspect}. Supported: #{MODES.keys.join(', ')}" unless timing

          timing
        end

        # Supported Method Parameters::
        # timing = PWN::SDR::Decoder::Tempest.resolve_timing(
        #   mode: 'optional - Symbol/String key from #modes (default vga_640x480_60)',
        #   h_active: 'optional - visible pixels per line (overrides mode)',
        #   h_total: 'optional - samples per line including blanking',
        #   v_active: 'optional - visible lines per frame',
        #   v_total: 'optional - lines per frame including blanking',
        #   refresh: 'optional - frames per second'
        # )

        public_class_method def self.resolve_timing(opts = {})
          base = modes(name: opts[:mode] || 'vga_640x480_60')
          {
            h_active: (opts[:h_active] || base[:h_active]).to_i,
            h_total: (opts[:h_total] || base[:h_total]).to_i,
            v_active: (opts[:v_active] || base[:v_active]).to_i,
            v_total: (opts[:v_total] || base[:v_total]).to_i,
            refresh: (opts[:refresh] || base[:refresh]).to_f
          }
        end

        # Supported Method Parameters::
        # result = PWN::SDR::Decoder::Tempest.reconstruct(
        #   iq: 'required - interleaved I/Q Array<Float> [I0,Q0,I1,Q1,…]',
        #   sample_rate: 'required - capture sample rate in Hz',
        #   mode: 'optional - VESA mode key from #modes',
        #   h_active: 'optional - visible pixels per line',
        #   h_total: 'optional - samples per line including blanking',
        #   v_active: 'optional - visible lines per frame',
        #   v_total: 'optional - lines per frame including blanking',
        #   refresh: 'optional - frames per second (default from mode)',
        #   frames: 'optional - number of frames to write (default 1)',
        #   out_path: 'optional - destination .pgm path (default /tmp/tempest_*.pgm)'
        # )

        public_class_method def self.reconstruct(opts = {})
          iq = opts[:iq]
          raise 'ERROR: :iq is required (interleaved I/Q Array<Float>)' unless iq.is_a?(Array) && iq.length >= 2

          rate = opts[:sample_rate].to_f
          raise 'ERROR: :sample_rate must be a positive Hz value' unless rate.positive?

          demod = Demod.new(opts)
          demod.feed_iq(iq, rate: rate)
          demod.finish
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Tempest.decode(
        #   freq_obj: 'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
        #   mode: 'optional - VESA mode key from #modes (default vga_640x480_60)',
        #   h_active: 'optional - visible pixels per line',
        #   h_total: 'optional - samples per line including blanking',
        #   v_active: 'optional - visible lines per frame',
        #   v_total: 'optional - lines per frame including blanking',
        #   refresh: 'optional - frames per second',
        #   frames: 'optional - maximum frame updates (default continuous; use stop/duration to end stream)',
        #   out_path: 'optional - destination .pgm path',
        #   source: 'optional - :auto|:rtlsdr|:hackrf|:adalm_pluto|:soapy|:file',
        #   file: 'optional - path to .cu8/.cs16/.iq capture',
        #   sample_rate: 'optional - I/Q rate Hz (default freq_obj[:iq_rate] or 2_048_000)'
        # )

        # Energy detection only; does not identify or decode Tempest payloads.
        # Supported Method Parameters::
        # Tempest.detect(freq_obj: Hash, threshold: 8.0, on_frame: Proc)
        public_class_method def self.detect(opts = {})
          Base.run_detector(opts.merge(
                              protocol: 'TEMPEST',
                              note: 'Energy detection only; no protocol payload decoding.',
                              describe: proc { |_burst| { event: 'detection', capability: 'energy-detection', decoded: false } }
                            ))
        end

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          demod = Demod.new(opts.merge(continuous: opts.fetch(:continuous, !opts.key?(:frames))))
          PWN::SDR::Decoder::Base.run_iq(opts.merge(
                                           freq_obj: freq_obj,
                                           protocol: 'TEMPEST',
                                           fallback: :raise,
                                           demod: demod,
                                           sample_rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 2_048_000).to_i,
                                           fm_demod: false,
                                           note: 'TEMPEST magnitude raster preview requires known timing and alignment; not automatic monitor recovery.'
                                         ))
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
            # Return VESA timing hashes (or one named mode).
            #{self}.modes(
              name: 'optional - Symbol/String mode key such as :vga_640x480_60'
            )

            # Merge a named mode with operator overrides into one timing Hash.
            #{self}.resolve_timing(
              mode: 'optional - Symbol/String key from #modes (default vga_640x480_60)',
              h_active: 'optional - visible pixels per line (overrides mode)',
              h_total: 'optional - samples per line including blanking',
              v_active: 'optional - visible lines per frame',
              v_total: 'optional - lines per frame including blanking',
              refresh: 'optional - frames per second'
            )

            # Rebuild a greyscale PGM from an in-memory I/Q capture (no radio).
            #{self}.reconstruct(
              iq: 'required - interleaved I/Q Array<Float> [I0,Q0,I1,Q1,…]',
              sample_rate: 'required - capture sample rate in Hz',
              mode: 'optional - VESA mode key from #modes',
              h_active: 'optional - visible pixels per line',
              h_total: 'optional - samples per line including blanking',
              v_active: 'optional - visible lines per frame',
              v_total: 'optional - lines per frame including blanking',
              refresh: 'optional - frames per second (default from mode)',
              frames: 'optional - number of frames to write (default 1)',
              out_path: 'optional - destination .pgm path (default /tmp/tempest_*.pgm)'
            )

            # Live-decode video emanations from GQRX freq_obj / SDR I/Q / capture file.
            #{self}.decode(
              freq_obj: 'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
              mode: 'optional - VESA mode key from #modes (default vga_640x480_60)',
              h_active: 'optional - visible pixels per line',
              h_total: 'optional - samples per line including blanking',
              v_active: 'optional - visible lines per frame',
              v_total: 'optional - lines per frame including blanking',
              refresh: 'optional - frames per second',
              frames: 'optional - maximum frame updates (default continuous; use stop/duration to end stream)',
              out_path: 'optional - destination .pgm path',
              source: 'optional - :auto|:rtlsdr|:hackrf|:adalm_pluto|:soapy|:file',
              file: 'optional - path to .cu8/.cs16/.iq capture',
              sample_rate: 'optional - I/Q rate Hz (default freq_obj[:iq_rate] or 2_048_000)',
              continuous: 'optional - update latest PGM indefinitely (default true without frames)',
              on_frame: 'optional - callback receiving each frame Hash after atomic PGM update',
              output: 'optional - IO for immediate JSONL events (default stdout)',
              interactive: 'optional - stop on ENTER (default true)',
              duration: 'optional - maximum stream seconds',
              stop: 'optional - callable cancellation predicate',
              queue_size: 'optional - bounded Base input queue size',
              log_file: 'optional - JSONL log path or false to disable'
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
