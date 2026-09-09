# frozen_string_literal: true

require 'ffi'
require 'rbconfig'

module PWN
  module SDR
    module Decoder
      # LTE PSS observations (.detect) and optional native PBCH MIB (.decode).
      # PBCH: acquired or caller-aligned SF0, 1.92Msps, FDD, normal CP, 2 ports.
      # No SIB/traffic decoding or live-RF validation.
      module LTE
        FS_BASE   = 1_920_000
        NFFT      = 128
        CP_NORM   = 9 # samples @ 1.92 Msps for symbols 1..6 (10 for symbol 0)
        PSS_ROOTS = { 0 => 25, 1 => 29, 2 => 34 }.freeze

        # Optional native implementation; never compiles or fetches at runtime.
        # ABI contains only flat scalar buffers, not version-sensitive structs.
        class PBCHIQ
          def initialize(pci:)
            @pci = pci
            @buffer = []
            path = File.expand_path("../../../../ext/pwn_lte/libpwn_lte.#{RbConfig::CONFIG.fetch('DLEXT')}", __dir__)
            @native = Module.new do
              extend ::FFI::Library

              ffi_lib path
              attach_function :pwn_lte_pbch, %i[pointer uint uint pointer pointer pointer], :int
            end
          rescue LoadError => e
            raise LoadError, "LTE PBCH native backend unavailable; build ext/pwn_lte/build.rb against srsRAN_4G: #{e.message}"
          end

          def feed_iq(samples, rate: nil)
            raise ArgumentError, 'PBCH requires 1.92 Msps' if rate && rate != FS_BASE

            @buffer.concat(samples)
            while @buffer.length >= 3840
              frame = decode_subframe(@buffer.shift(3840))
              yield frame if frame
            end
          end

          def flush
            raise ArgumentError, 'truncated LTE subframe zero (requires 1920 complex samples)' unless @buffer.empty?
          end

          private

          def decode_subframe(samples)
            input = ::FFI::MemoryPointer.new(:float, 3840)
            input.write_array_of_float(samples)
            payload = ::FFI::MemoryPointer.new(:uint8, 24)
            ports = ::FFI::MemoryPointer.new(:uint)
            offset = ::FFI::MemoryPointer.new(:int)
            status = @native.pwn_lte_pbch(input, 1920, @pci, payload, ports, offset)
            raise 'LTE native PBCH decoder failed' if status.negative?
            return nil if status.zero?

            bits = payload.read_array_of_uint8(24).join
            bandwidth = bits[0, 3].to_i(2)
            return nil if bandwidth > 5

            {
              protocol: 'LTE', event: 'mib', decoded: true, capability: 'aligned-pbch-mib',
              backend: 'srsRAN_4G', checksum_verified: true,
              integrity: { algorithm: 'PBCH-CRC16', valid: true },
              payload_hex: [bits].pack('B*').unpack1('H*'), payload_bits: 24,
              pci: @pci, pci_source: 'caller', ports: ports.read_uint,
              prb: [6, 15, 25, 50, 75, 100][bandwidth],
              phich_duration: bits[3] == '0' ? 'normal' : 'extended',
              phich_resource: ['1/6', '1/2', '1', '2'][bits[4, 2].to_i(2)],
              sfn_msb: bits[6, 8].to_i(2) << 2, sfn_offset: offset.read_int,
              summary: "LTE PBCH MIB CRC verified (caller-aligned SF0, PCI=#{@pci})"
            }
          ensure
            input&.free
            payload&.free
            ports&.free
            offset&.free
          end
        end

        # Continuous offline IQ acquisition; overlap protects SF0 at window edges.
        # Only a CRC-verified PBCH payload is emitted, never a synchronization hit.
        class AcquiredPBCHIQ < PBCHIQ
          def initialize
            super(pci: nil)
            @native.attach_function :pwn_lte_acquire, %i[pointer uint pointer pointer pointer pointer], :int
            @sample_offset = 0
            @last_timing = nil
          end

          def feed_iq(samples, rate: nil)
            raise ArgumentError, 'PBCH requires 1.92 Msps' if rate && rate != FS_BASE

            @buffer.concat(samples)
            while @buffer.length >= 19_200
              frame = acquire(@buffer.first(19_200))
              yield frame if frame
              @buffer.shift(15_360)
              @sample_offset += 7680
            end
          end

          def flush
            frame = acquire(@buffer) if @buffer.length >= 3840
            yield frame if frame
            @buffer.clear
          end

          private

          def acquire(samples)
            input = ::FFI::MemoryPointer.new(:float, samples.length)
            input.write_array_of_float(samples)
            sf0 = ::FFI::MemoryPointer.new(:float, 3840)
            pci = ::FFI::MemoryPointer.new(:uint)
            start = ::FFI::MemoryPointer.new(:uint)
            cfo = ::FFI::MemoryPointer.new(:float)
            status = @native.pwn_lte_acquire(input, samples.length / 2, sf0, pci, start, cfo)
            raise 'LTE native acquisition failed' if status.negative?
            return nil if status.zero?

            timing = @sample_offset + start.read_uint
            return nil if timing == @last_timing

            @pci = pci.read_uint
            frame = decode_subframe(sf0.read_array_of_float(3840))
            return nil unless frame

            @last_timing = timing
            frame.merge(capability: 'acquired-pbch-mib', pci_source: 'pss-sss',
                        timing_sample: timing, cfo_hz: cfo.read_float,
                        summary: "LTE PBCH MIB CRC verified (PSS/SSS acquired PCI=#{@pci})")
          ensure
            [input, sf0, pci, start, cfo].each { |pointer| pointer&.free }
          end
        end

        # Streaming PSS observation detector for Base.run_iq.
        class DemodIQ
          def initialize(rate:)
            @rate = rate.to_f
            @buf  = []
            @seen = {}
            @pss  = build_pss
          end

          def feed_iq(samples, rate: nil, &emit)
            @rate = rate.to_f if rate
            @input ||= []
            @input.concat(samples)
            window = [(@rate * 0.005).round, 1].max * 2
            process_window(@input.shift(window), &emit) while @input.length >= window
          end

          def process_window(samples, &)
            r = PWN::SDR::Decoder::DSP.resample_iq(
              iq: samples, src_rate: @rate, dst_rate: FS_BASE
            )
            @buf.concat(r)
            # need ≥ one 5 ms half-frame @ 1.92 Msps = 9600 complex
            return if @buf.length < 9600 * 2 * 2

            hit = search_pss
            if hit
              # Magnitude-only SSS cannot recover BPSK signs or identify PCI.
              nid1 = nil
              pci  = nid1 ? (3 * nid1) + hit[:nid2] : nil
              key  = pci || "N2=#{hit[:nid2]}"
              unless @seen[key]
                @seen[key] = true
                yield(
                  protocol: 'LTE', event: 'cell', modulation: 'OFDMA',
                  capability: 'cell-search-only', decoded: false,
                  nid2: hit[:nid2], nid1: nid1, pci: pci,
                  cfo_hz: hit[:cfo_hz], pss_normalized_correlation: hit[:ratio],
                  timing_sample: hit[:pos],
                  summary: pci ? "LTE cell PCI=#{pci} (N_ID_1=#{nid1} N_ID_2=#{hit[:nid2]}) CFO=#{hit[:cfo_hz]}Hz" : "LTE PSS lock N_ID_2=#{hit[:nid2]} CFO=#{hit[:cfo_hz]}Hz (SSS unsupported)"
                )
              end
            end
            @buf.shift(@buf.length - (9600 * 2)) if @buf.length > 9600 * 4
          end

          private

          # Build 3 time-domain PSS templates (128 complex samples each).
          def build_pss
            PSS_ROOTS.transform_values do |root|
              zc = PWN::SDR::Decoder::DSP.zadoff_chu(root: root, n: 63)
              # Map 62 ZC values (drop k=31) onto ±31 subcarriers of a 128-FFT.
              spec = Array.new(NFFT * 2, 0.0)
              62.times do |m|
                zi = m < 31 ? m : m + 1 # skip DC element
                sc = m - 31
                k  = sc.negative? ? sc + NFFT : sc + 1 # DC left null
                spec[k * 2]       = zc[zi * 2]
                spec[(k * 2) + 1] = zc[(zi * 2) + 1]
              end
              td = PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: spec, n: NFFT, sign: :backward) : PWN::SDR::Decoder::DSP.dft_naive(iq: spec, n: NFFT)
              td.flat_map { |re, im| [re, im] }
            end
          end

          def search_pss
            n = @buf.length / 2
            best = nil
            @pss.each do |nid2, tmpl|
              template_energy = tmpl.sum { |v| v * v }
              # sliding conj-multiply-accumulate every 4th sample for speed
              i = 0
              while i < n - NFFT
                acc_r = 0.0
                acc_i = 0.0
                energy = 0.0
                NFFT.times do |j|
                  ar = @buf[(i + j) * 2]
                  ai = @buf[((i + j) * 2) + 1]
                  energy += (ar * ar) + (ai * ai)
                  br = tmpl[j * 2]
                  bi = tmpl[(j * 2) + 1]
                  acc_r += (ar * br) + (ai * bi)
                  acc_i += (ai * br) - (ar * bi)
                end
                # Squared normalized correlation is gain/FFT-scaling invariant.
                pk = ((acc_r * acc_r) + (acc_i * acc_i)) / [energy * template_energy, 1e-30].max
                best = { nid2: nid2, pos: i, pk: pk, ang: Math.atan2(acc_i, acc_r) } if best.nil? || pk > best[:pk]
                i += 4
              end
            end
            return nil unless best

            ratio = best[:pk]
            return nil unless ratio > 0.5

            # coarse CFO from CP: correlate CP with tail of same OFDM symbol
            pos = best[:pos]
            cfo = cp_cfo(pos)
            best.merge(ratio: ratio.round(4), cfo_hz: cfo)
          end

          def cp_cfo(pos)
            return 0 if pos < CP_NORM

            a = @buf[(pos - CP_NORM) * 2, CP_NORM * 2]
            b = @buf[(pos + NFFT - CP_NORM) * 2, CP_NORM * 2]
            r = 0.0
            im = 0.0
            CP_NORM.times do |j|
              r  += (a[j * 2] * b[j * 2]) + (a[(j * 2) + 1] * b[(j * 2) + 1])
              im += (a[(j * 2) + 1] * b[j * 2]) - (a[j * 2] * b[(j * 2) + 1])
            end
            (Math.atan2(im, r) * FS_BASE / (2 * Math::PI * NFFT)).round
          end
        end

        # SSS helper: (m0, m1) pair for a given N_ID_1 per TS 36.211 §6.11.2.
        public_class_method def self.sss_indices(opts = {})
          nid1 = opts[:nid1].to_i
          qp = (nid1 / 30)
          q  = ((nid1 + (qp * (qp + 1) / 2)) / 30)
          mp = nid1 + (q * (q + 1) / 2)
          m0 = mp % 31
          m1 = (m0 + (mp / 31) + 1) % 31
          [m0, m1]
        end

        # Length-31 m-sequence x^5+x^2+1, cyclic-shifted by `shift`, as ±1.
        public_class_method def self.mseq(opts = {})
          @mseq_base ||= begin
            reg = [0, 0, 0, 0, 1]
            Array.new(31) do
              o = reg[0]
              fb = reg[0] ^ reg[3]
              reg = reg[1..] + [fb]
              1 - (2 * o)
            end
          end
          sh = opts[:shift].to_i
          Array.new(31) { |n| @mseq_base[(n + sh) % 31] }
        end

        # Scrambling sequence c0 (x^5+x^3+1) tied to N_ID_2, ±1.
        public_class_method def self.cseq(opts = {})
          @cseq_base ||= begin
            reg = [0, 0, 0, 0, 1]
            Array.new(31) do
              o = reg[0]
              fb = reg[0] ^ reg[2]
              reg = reg[1..] + [fb]
              1 - (2 * o)
            end
          end
          sh = opts[:nid2].to_i
          Array.new(31) { |n| @cseq_base[(n + sh) % 31] }
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::LTE.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          raise NotImplementedError, "IQ mode #{opts[:mode] || :iq} is unsupported; use :pbch_iq for offline acquisition, :pbch_sf0_iq for aligned SF0, or .detect for observations" unless %i[pbch_sf0_iq pbch_iq].include?(opts[:mode])

          raise NotImplementedError, 'PBCH bridge supports only FDD, normal CP, two transmit ports' unless opts.fetch(:duplex, :fdd) == :fdd && opts.fetch(:cyclic_prefix, :normal) == :normal && opts.fetch(:tx_ports, 2) == 2

          rate = opts.fetch(:sample_rate, FS_BASE)
          raise ArgumentError, 'PBCH requires sample_rate: 1920000' unless rate == FS_BASE
          raise ArgumentError, 'PBCH requires integer PCI in 0..503 (caller supplied, not acquired)' if opts[:mode] == :pbch_sf0_iq && !(opts[:pci].is_a?(Integer) && opts[:pci].between?(0, 503))

          source = opts[:source]
          offline = source.respond_to?(:read) || (source.is_a?(Hash) && source[:kind] == :io && source[:io].respond_to?(:read)) || (opts[:file] && [nil, :file].include?(source))
          raise ArgumentError, 'PBCH requires an explicit offline file or IO; hardware acquisition is not supported' unless offline

          Base.run_iq(opts.merge(freq_obj: opts[:freq_obj] || {}, protocol: 'LTE', sample_rate: rate,
                                 demod: opts[:mode] == :pbch_iq ? AcquiredPBCHIQ.new : PBCHIQ.new(pci: opts[:pci]),
                                 note: 'Native PBCH MIB only: 1.92Msps FDD normal CP, two TX ports. :pbch_iq acquires PSS/SSS; :pbch_sf0_iq requires aligned SF0 and PCI. No SIB/traffic.'))
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj] || {}
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 1_920_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: 'LTE',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: 'OFDMA PSS correlation observations only; SSS/PCI, PBCH/MIB and traffic decoding are unsupported.',
            describe: proc { |_b| { modulation: 'OFDMA', subcarrier_khz: 15 } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'LTE' }
          out[:earfcn] = ::Regexp.last_match(1) if line =~ /EARFCN[:= ]+(\d+)/i
          out[:pci]    = ::Regexp.last_match(1) if line =~ /(?:PCI|N_id_cell|Id)[:= ]+(\d{1,3})/i
          out[:prb]    = (::Regexp.last_match(1) || ::Regexp.last_match(2)) if line =~ /(?:PRB[:= ]+(\d+)|(\d+)\s*PRB)/i
          out[:rsrp]   = ::Regexp.last_match(1) if line =~ /(-?\d+(?:\.\d+)?)\s*dBm/
          out[:summary] = "LTE PCI=#{out[:pci]} EARFCN=#{out[:earfcn]} PRB=#{out[:prb]} RSRP=#{out[:rsrp]}dBm"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # SSS helper: (m0, m1) pair for a given N_ID_1 per TS 36.211 §6.11.2
            #{self}.sss_indices(
              nid1: 'optional - nid1 value consumed by #sss_indices'
            )

            # Length-31 m-sequence x^5+x^2+1, cyclic-shifted by `shift`, as ±1
            #{self}.mseq(
              shift: 'optional - shift value consumed by #mseq'
            )

            # Scrambling sequence c0 (x^5+x^3+1) tied to N_ID_2, ±1
            #{self}.cseq(
              nid2: 'optional - nid2 value consumed by #cseq'
            )

            # Optional native PBCH MIB: see ext/pwn_lte/README.md for build/provenance.
            # Input is consecutive, separately extracted 1ms subframe-zero blocks.
            # Not a continuous capture; caller supplies PCI/timing/frequency correction.
            # Only FDD, normal CP, two TX ports; no SIB or traffic.
            # For continuous central-six-PRB IQ, use mode: :pbch_iq and omit PCI.
            # This acquires PSS/SSS timing/PCI and estimates fractional CFO.
            #{self}.decode(
              mode: 'required - :pbch_sf0_iq for aligned subframe-zero IQ blocks',
              pci: 'required - physical cell identity integer from 0 through 503',
              sample_rate: 1920000,
              source: :file, file: 'aligned-sf0.cs16', iq_format: :cs16,
              duplex: :fdd, cyclic_prefix: :normal, tx_ports: 2,
              interactive: false, log_file: false,
              on_frame: proc { |frame| p frame }
            )
            # Other PHY modes remain unsupported; detection is always explicit.
            #{self}.detect(freq_obj: {}, source: :file, file: 'capture.cu8')
            # Run detection only.
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
