# frozen_string_literal: true

require 'json'
require 'open3'

module PWN
  module Plugins
    # Disposable no-network execution; never falls back to host execution.
    module Sandbox
      public_class_method def self.run(opts = {})
        invoke(opts.merge(action: 'run'))
      end

      public_class_method def self.fuzz(opts = {})
        invoke(opts.merge(action: 'fuzz', binary: opts[:target]))
      end

      public_class_method def self.snapshot(opts = {})
        invoke(opts.merge(action: 'snapshot'))
      end

      public_class_method def self.rollback(opts = {})
        invoke(opts.merge(action: 'rollback'))
      end

      private_class_method def self.invoke(opts = {})
        require_relative 'sandbox/driver'
        PWNSandboxDriver.main(opts)
      rescue StandardError => e
        { ok: false, error: e.message, backend: opts.fetch(:backend, 'docker') }
      end
      private_class_method :invoke

      public_class_method def self.authors
        'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
      end

      public_class_method def self.help
        puts "USAGE:
          # Execute a binary in a disposable no-network environment.
          #{self}.run(
            binary: 'required - local executable fixture path',
            argv: 'optional - argument string array',
            stdin: 'optional - target input text',
            backend: 'optional - docker default or explicit bwrap',
            timeout: 'optional - execution seconds budget',
            memory_mb: 'optional - memory budget in megabytes'
          )
          # Mutate stdin seeds with deterministic bit flips.
          #{self}.fuzz(
            target: 'required - executable target path',
            corpus: 'required - directory of seed inputs',
            minutes: 'required - fuzzing time budget'
          )
          # Preserve an integrity-checked immutable input copy.
          #{self}.snapshot(binary: 'required - local executable to preserve')
          # Start a fresh environment from a verified snapshot.
          #{self}.rollback(snapshot: 'required - snapshot directory returned earlier')
          # Print the module author information.
          #{self}.authors
        "
      end
    end
  end
end
