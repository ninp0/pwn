# frozen_string_literal: true

require 'pwn/plugins/binary_analysis'

module PWN
  module Plugins
    # Read-only gadget enumeration; clobbers are conservative syntactic estimates.
    module ROP
      public_class_method def self.required_bins
        %w[ROPgadget ropper objdump]
      end

      public_class_method def self.gadgets(opts = {})
        path = File.realpath(File.expand_path(opts[:path].to_s))
        backend = opts[:backend] || %w[ROPgadget ropper].find { |name| BinaryAnalysis.available?(name: name) } || 'objdump'
        command = case backend
                  when 'ROPgadget' then ['ROPgadget', '--binary', path, '--depth', '6']
                  when 'ropper' then ['ropper', '--file', path, '--nocolor', '--inst-count', '6']
                  when 'objdump' then ['objdump', '-d', '-M', 'intel', path]
                  else raise ArgumentError, 'unsupported gadget backend'
                  end
        text = BinaryAnalysis.run(argv: command, timeout: opts.fetch(:timeout, 60))
        rows = if backend == 'objdump'
                 text.lines.filter_map do |line|
                   match = line.match(/^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(ret\w*\b.*)$/)
                   { address: match[1].to_i(16), gadget: match[2].strip } if match
                 end
               else
                 text.lines.filter_map do |line|
                   match = line.match(/^\s*(0x[0-9a-fA-F]+)\s*:\s*(.+)$/)
                   { address: match[1].to_i(16), gadget: match[2].strip.sub(/;\s*$/, '') } if match
                 end
               end
        rows.each do |row|
          # Include ALL mentioned registers, not only destinations. Unknown implicit
          # effects fail closed under preserve constraints; this is not symbolic proof.
          regs = row[:gadget].downcase.scan(/\b(?:r(?:1[0-5]|[0-9])(?:d|w|b)?|[re]?(?:ax|bx|cx|dx|si|di|sp|bp)|[abcd][lh]|[xyz]mm\d+)\b/)
          regs += %w[rsp rip] if row[:gadget].match?(/\b(?:ret|pop|push|call)\b/)
          row[:regs_clobbered] = regs.uniq
          row[:clobbers_complete] = row[:gadget].split(';').all? { |ins| ins.strip.match?(/\A(?:pop\s+[a-z0-9]+|ret(?:\s+0x[0-9a-f]+)?|nop)\z/i) }
        end
        { backend: backend, status: backend == 'objdump' ? 'degraded' : 'ok', risk_level: 'low', path: path, sha256: Digest::SHA256.file(path).hexdigest, gadgets: filter(gadgets: rows, constraints: opts[:constraints] || {}), warnings: backend == 'objdump' ? ['fallback enumerates aligned returns only, not a complete gadget search'] : ['register clobbers are conservative estimates, not symbolic verification'] }
      rescue StandardError => e
        raise if backend == 'objdump' || e.is_a?(ArgumentError)

        gadgets(opts.merge(backend: 'objdump')).tap { |result| result[:warnings] << "#{backend}: #{e.message}" }
      end

      public_class_method def self.filter(opts = {})
        constraints = opts[:constraints] || {}
        constraints = constraints.transform_keys(&:to_sym)
        allowed = %i[contains max_instructions preserve min_address max_address]
        raise ArgumentError, "unsupported constraints: #{constraints.keys - allowed}" unless (constraints.keys - allowed).empty?

        Array(opts[:gadgets]).select do |row|
          preserved = Array(constraints[:preserve]).map { |register| canonical_register(register: register) }
          clobbered = Array(row[:regs_clobbered]).map { |register| canonical_register(register: register) }
          (!constraints[:contains] || row[:gadget].include?(constraints[:contains].to_s)) &&
            (!constraints[:max_instructions] || row[:gadget].split(';').length <= Integer(constraints[:max_instructions])) &&
            (preserved.empty? || (row[:clobbers_complete] && !preserved.intersect?(clobbered))) &&
            (!constraints[:min_address] || row[:address] >= Integer(constraints[:min_address])) &&
            (!constraints[:max_address] || row[:address] <= Integer(constraints[:max_address]))
        end
      end

      private_class_method def self.canonical_register(opts = {})
        register = opts[:register]
        value = register.to_s.downcase
        families = { 'rax' => %w[rax eax ax al ah], 'rbx' => %w[rbx ebx bx bl bh], 'rcx' => %w[rcx ecx cx cl ch], 'rdx' => %w[rdx edx dx dl dh], 'rsi' => %w[rsi esi si sil], 'rdi' => %w[rdi edi di dil], 'rsp' => %w[rsp esp sp spl], 'rbp' => %w[rbp ebp bp bpl], 'rip' => %w[rip eip ip] }
        families.find { |_name, aliases| aliases.include?(value) }&.first || value.sub(/\A(r(?:[89]|1[0-5]))[dwb]\z/, '\\1')
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List expected analysis backend executables.
          #{self}.required_bins

          # Enumerate read-only gadgets and conservatively filter register constraints.
          #{self}.gadgets(
            backend: 'optional - analysis backend name; binutils forces lightweight fallback',
            constraints: 'optional - hash with contains, preserve register array, instruction and address bounds',
            path: 'required - filesystem path to the local artifact or binary',
            timeout: 'optional - positive subprocess or HTTP deadline in seconds'
          )

          # Filter already enumerated gadget records with an explicit constraint set.
          #{self}.filter(
            constraints: 'optional - hash with contains, preserve register array, instruction and address bounds',
            gadgets: 'required - array of normalized gadget records returned by enumeration'
          )

          # Display module authors.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
