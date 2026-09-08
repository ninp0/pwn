# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'digest'
require 'open3'
require 'tmpdir'

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

        sha = Digest::SHA256.file(path).hexdigest
        cache = File.join(Dir.home, '.pwn', 'cache', 'ghidra_headless', "#{sha}.json")
        return JSON.parse(File.read(cache), symbolize_names: true).merge(cached: true) if File.file?(cache)

        row = if PWN::Plugins::PreflightChecker.bin?(name: 'analyzeHeadless')
                run_headless(path: path, sha: sha, function: opts[:function])
              else
                PWN::Plugins::Ghidra.decompile(opts.merge(bin: path))
              end
        FileUtils.mkdir_p(File.dirname(cache))
        File.write(cache, JSON.generate(row))
        row.merge(sha256: sha, cached: false)
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
        "
        constants.sort
      end

      private_class_method def self.run_headless(opts = {})
        path = opts[:path].to_s
        Dir.mktmpdir('pwn-ghidra') do |dir|
          script = File.join(dir, 'export.py')
          out = File.join(dir, 'export.json')
          File.write(script, <<~PY)
            # @runtime PyGhidra
            import json, os
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            decomp = DecompInterface()
            decomp.openProgram(currentProgram)
            mon = ConsoleTaskMonitor()
            fns = []
            fm = currentProgram.getFunctionManager()
            it = fm.getFunctions(True)
            while it.hasNext():
                fn = it.next()
                res = decomp.decompileFunction(fn, 30, mon)
                c = res.getDecompiledFunction().getC() if res and res.getDecompiledFunction() else ''
                fns.append({'name': fn.getName(), 'entry': str(fn.getEntryPoint()), 'c': c})
            open(#{out.inspect}, 'w').write(json.dumps({'functions': fns, 'symbols': [s.getName() for s in currentProgram.getSymbolTable().getAllSymbols(True)]}))
          PY
          stdout, stderr, status = Open3.capture3(
            'analyzeHeadless', dir, 'pwn', '-import', path, '-postScript', script, '-deleteProject'
          )
          payload = File.file?(out) ? JSON.parse(File.read(out), symbolize_names: true) : {}
          { stdout: stdout, stderr: stderr, exit: status.exitstatus, engine: 'ghidra', decompiled: payload, sha256: opts[:sha] }
        end
      rescue StandardError => e
        { error: e.message, engine: 'ghidra', sha256: opts[:sha] }
      end
    end
  end
end
