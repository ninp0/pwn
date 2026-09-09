# frozen_string_literal: true

require 'ffi'
require 'rbconfig'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Optional bundled double-precision packed IQ kernels. Explicit build only;
    # no runtime compiler, search-path loading, or shared temporary cache.
    module DSPNative
      extend PubFFI::Library

      @load_error = nil
      begin
        ffi_lib File.expand_path("../../../ext/pwn_dsp/libpwn_dsp.#{RbConfig::CONFIG.fetch('DLEXT')}", __dir__)
        attach_function :pwn_dsp_iq, %i[pointer size_t int int double pointer int pointer], :size_t
        attach_function :pwn_dsp_fft, %i[pointer size_t pointer], :int
        private_class_method :pwn_dsp_iq, :pwn_dsp_fft
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      # Supported Method Parameters::
      # PWN::FFI::DSPNative.available?
      public_class_method def self.available?
        @load_error.nil?
      end

      # Supported Method Parameters::
      # result = PWN::FFI::DSPNative.process_iq(data:, format: :cu8,
      #   operation: :fm, previous: nil, kf: 1.0)
      # Complete packed IQ pairs only. Returns samples and final previous pair.
      public_class_method def self.process_iq(opts = {})
        raise "ERROR: optional DSP helper unavailable: #{@load_error}" unless available?

        format = opts.fetch(:format, :cu8).to_sym
        operation = opts.fetch(:operation, :fm).to_sym
        format_id = { cu8: 0, cs16le: 1, f64: 2 }.fetch(format)
        operation_id = { unpack: 0, mag: 1, fm: 2 }.fetch(operation)
        width = [2, 4, 16][format_id]
        data = opts[:data].to_s
        raise ArgumentError, 'incomplete IQ pair' unless (data.bytesize % width).zero?

        n = data.bytesize / width
        previous = opts[:previous]
        return { samples: [], previous: previous } if n.zero?

        raise ArgumentError, 'previous must contain two scalars' if previous && previous.length != 2

        input = PubFFI::MemoryPointer.from_string(data)
        output = PubFFI::MemoryPointer.new(:double, 2 * n)
        last = PubFFI::MemoryPointer.new(:double, 2)
        last.write_array_of_double(previous || [0.0, 0.0])
        count = pwn_dsp_iq(input, n, format_id, operation_id, opts.fetch(:kf, 1.0).to_f, last, previous ? 1 : 0, output)
        { samples: output.read_array_of_double(count), previous: last.read_array_of_double(2) }
      ensure
        input&.free
        output&.free
        last&.free
      end

      # Supported Method Parameters::
      # magnitudes = PWN::FFI::DSPNative.cfft_mag(iq:, n:)
      # Power-of-two FFT; input is zero-padded/truncated, output unshifted.
      public_class_method def self.cfft_mag(opts = {})
        raise "ERROR: optional DSP helper unavailable: #{@load_error}" unless available?

        iq = opts[:iq]
        n = opts.fetch(:n, iq.length / 2).to_i
        raise ArgumentError, 'n must be a positive power of two' unless n.positive? && n.nobits?(n - 1)

        input = PubFFI::MemoryPointer.new(:double, 2 * n)
        src = iq.first(n * 2).pack('d*')
        input.put_bytes(0, src)
        output = PubFFI::MemoryPointer.new(:double, n)
        raise 'ERROR: native FFT failed' unless pwn_dsp_fft(input, n, output).zero?

        output.read_array_of_double(n)
      ensure
        input&.free
        output&.free
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>
      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display Usage for this Module
      public_class_method def self.help
        puts "USAGE:
          # Check whether the explicitly built helper is available.
          #{self}.available?
          # Read the optional native-library load error.
          #{self}.load_error
          # Process complete packed IQ pairs in one contiguous native loop.
          #{self}.process_iq(
            data: 'required - packed String containing complete IQ pairs',
            format: 'optional - :cu8, :cs16le, or host-native :f64 (default :cu8)',
            operation: 'optional - :unpack, :mag, or :fm (default :fm)',
            previous: 'optional - previous [I,Q] pair for FM continuity',
            kf: 'optional - multiply phase radians by this scale (default 1.0)'
          )
          # Compute unshifted power-of-two FFT magnitudes with zero padding.
          #{self}.cfft_mag(
            iq: 'required - interleaved Array<Float>',
            n: 'optional - positive power-of-two size (default iq.length / 2)'
          )
          # Print module authors.
          #{self}.authors
        "
      end
    end
  end
end
