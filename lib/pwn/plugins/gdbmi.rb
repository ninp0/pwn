# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # GDB machine-interface bridge: breakpoints, stepping, registers,
    # memory, backtraces, checksec. Pairs with ProcessTube for interactive
    # sessions.
    module GDBMI
      public_class_method def self.required_bins
        %w[gdb]
      end

      public_class_method def self.open(opts = {})
        binary = opts[:binary].to_s
        PWN::Plugins::ProcessTube.spawn(cmd: ['gdb', '--interpreter=mi2', '--quiet', binary].reject(&:empty?))
      end

      public_class_method def self.break(opts = {})
        loc = (opts[:location] || opts[:addr] || opts[:symbol]).to_s
        raise 'ERROR: location is required' if loc.empty?

        mi(opts.merge(cmd: "-break-insert #{loc}"))
      end

      public_class_method def self.step(opts = {})
        mi(opts.merge(cmd: (opts[:into] ? '-exec-step' : '-exec-next')))
      end

      public_class_method def self.registers(opts = {})
        mi(opts.merge(cmd: '-data-list-register-values x'))
      end

      public_class_method def self.read_memory(opts = {})
        addr = (opts[:addr] || opts[:address]).to_s
        raise 'ERROR: addr is required' if addr.empty?

        n = (opts[:length] || 64).to_i
        mi(opts.merge(cmd: "-data-read-memory-bytes #{addr} #{n}"))
      end

      public_class_method def self.backtrace(opts = {})
        mi(opts.merge(cmd: '-stack-list-frames'))
      end

      public_class_method def self.checksec(opts = {})
        PWN::Plugins::GDB.mitigations(opts)
      end

      public_class_method def self.mi(opts = {})
        cmd = opts[:cmd].to_s
        raise 'ERROR: cmd is required' if cmd.empty?

        if opts[:id]
          PWN::Plugins::ProcessTube.write_line(id: opts[:id], line: cmd)
          PWN::Plugins::ProcessTube.recvuntil(id: opts[:id], until: "\n", timeout: opts[:timeout] || 5)
        else
          PWN::Plugins::GDB.batch(opts.merge(commands: [cmd.sub(/\A-/, '')]))
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Open gdb --interpreter=mi2 via ProcessTube.
          #{self}.open(
            binary: 'optional - filesystem path of the binary to debug'
          )

          # Insert a breakpoint (MI -break-insert).
          #{self}.break(
            location: 'required - symbol or address',
            addr: 'optional - alias for location',
            symbol: 'optional - alias for location',
            id: 'optional - ProcessTube id from #open'
          )

          # Step (into when into: true, otherwise next).
          #{self}.step(
            into: 'optional - true to step into (defaults to next)',
            id: 'optional - ProcessTube id from #open'
          )

          # Read registers via MI.
          #{self}.registers(
            id: 'optional - ProcessTube id from #open'
          )

          # Read memory bytes at addr.
          #{self}.read_memory(
            addr: 'required - address to read',
            address: 'optional - alias for addr',
            length: 'optional - byte count (defaults to 64)',
            id: 'optional - ProcessTube id from #open'
          )

          # Backtrace via MI -stack-list-frames.
          #{self}.backtrace(
            id: 'optional - ProcessTube id from #open'
          )

          # checksec / mitigations via GDB.mitigations.
          #{self}.checksec(
            binary: 'optional - filesystem path of the binary'
          )

          # Send a raw MI command.
          #{self}.mi(
            cmd: 'required - MI command string',
            id: 'optional - ProcessTube id from #open',
            timeout: 'optional - seconds to wait for a reply'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
