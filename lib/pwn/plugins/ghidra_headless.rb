# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'digest'
require 'open3'
require 'tmpdir'
require 'tempfile'
require 'pwn/plugins/binary_analysis'

module PWN
  module Plugins
    # analyzeHeadless wrapper that exports decompiled C plus the symbol
    # table as JSON, cached by binary SHA-256.
    module GhidraHeadless
      public_class_method def self.required_bins
        %w[analyzeHeadless]
      end

      public_class_method def self.analyze(opts = {})
        path = (opts[:bin] || opts[:path]).to_s
        raise 'ERROR: bin is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        path = File.realpath(path)
        sha = Digest::SHA256.file(path).hexdigest
        cache = File.join(File.expand_path(opts[:cache_dir] || '~/.pwn/ghidra_cache'), "#{sha}.json")
        if File.file?(cache) && opts[:backend] != 'binutils'
          row = JSON.parse(File.read(cache), symbolize_names: true)
          return select_functions(row: row.merge(cached: true), function: opts[:function]) if row[:sha256] == sha && row[:status] == 'ok'
        end

        row = if opts[:backend] != 'binutils' && BinaryAnalysis.available?(name: 'analyzeHeadless')
                run_headless(path: path, sha: sha, timeout: opts.fetch(:timeout, 300))
              else
                BinaryAnalysis.analyze(opts.merge(path: path)).merge(engine: 'binutils', decompiled: { functions: [], symbols: [], types: [] })
              end
        row = row.merge(sha256: sha, cached: false, risk_level: 'low')
        if row[:status] == 'ok'
          FileUtils.mkdir_p(File.dirname(cache), mode: 0o700)
          Tempfile.create(['ghidra', '.json'], File.dirname(cache)) do |file|
            file.write(JSON.generate(row))
            file.close
            File.rename(file.path, cache)
          end
        end
        select_functions(row: row, function: opts[:function])
      end

      public_class_method def self.decompile(opts = {})
        analyze(opts)
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run analyzeHeadless and cache decompiled C + symbols as JSON.
          #{self}.analyze(
            bin: 'required - filesystem path of the binary',
            path: 'optional - alias for bin',
            function: 'optional - function name to decompile'
          )

          # Alias of #analyze.
          #{self}.decompile(
            bin: 'required - filesystem path of the binary',
            path: 'optional - alias for bin',
            function: 'optional - function name to decompile'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
          # Invoke required_bins with the documented options; normalized path APIs report their backend.
          #{self}.required_bins
          # Invoke analyze with the documented options; normalized path APIs report their backend.
          #{self}.analyze(
            backend: 'optional - analysis backend name; binutils forces lightweight fallback',
            bin: 'optional - filesystem path to the binary to analyze',
            cache_dir: 'optional - directory for successful SHA256-keyed Ghidra JSON exports',
            function: 'optional - function symbol name to select from analysis',
            path: 'optional - filesystem path to the local artifact or binary',
            timeout: 'optional - positive subprocess or HTTP deadline in seconds'
          )
          # Invoke decompile with the documented options; normalized path APIs report their backend.
          #{self}.decompile
          # Invoke authors with the documented options; normalized path APIs report their backend.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.select_functions(opts = {})
        row = opts[:row]
        function = opts[:function]
        return row if function.to_s.empty?

        payload = row[:decompiled] || {}
        row.merge(decompiled: payload.merge(functions: Array(payload[:functions]).select { |fn| fn[:name] == function.to_s }))
      end

      private_class_method def self.run_headless(opts = {})
        path = opts[:path].to_s
        Dir.mktmpdir('pwn-ghidra') do |dir|
          out = File.join(dir, 'export.json')
          scripts = File.expand_path('ghidra_scripts', __dir__)
          log = BinaryAnalysis.run(argv: ['analyzeHeadless', dir, 'pwn', '-import', path, '-scriptPath', scripts, '-postScript', 'PwnExport.java', out, '-deleteProject'], timeout: opts.fetch(:timeout, 300))
          raise 'Ghidra produced no export' unless File.file?(out)

          payload = JSON.parse(File.read(out), symbolize_names: true)
          { stdout: log, stderr: '', exit: 0, engine: 'ghidra', backend: 'ghidra', status: 'ok', decompiled: payload, sha256: opts[:sha], warnings: [] }
        end
      rescue StandardError => e
        BinaryAnalysis.analyze(opts).merge(engine: 'binutils', decompiled: { functions: [], symbols: [], types: [] }, error: "Ghidra unavailable: #{e.message}")
      end
    end
  end
end
