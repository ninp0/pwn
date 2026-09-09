# frozen_string_literal: true

require 'yaml'
require 'json'
require 'json_schemer'
require 'ipaddr'
require 'uri'
require 'fileutils'
require 'time'

module PWN
  module AI
    module Agent
      # Trusted, on-disk tool declarations. Never load a manifest from tool args.
      module Manifest
        RISKS = %w[info low med high crit].freeze
        GATES = %w[auto prompt deny].freeze
        DIRECTORY = File.expand_path('../tools', __dir__).freeze

        public_class_method def self.load(opts = {})
          directory = opts[:directory] || DIRECTORY
          entries = Dir[File.join(directory, '*.yaml')].flat_map do |path|
            data = YAML.safe_load_file(path, permitted_classes: [], aliases: false)
            data.is_a?(Array) ? data : [data]
          end
          entries.each do |entry|
            raise ArgumentError, 'invalid manifest entry' unless entry.is_a?(Hash) && entry['name'].is_a?(String) && entry['description'].is_a?(String) && RISKS.include?(entry['risk_level']) && entry['params'].is_a?(Hash)
            raise ArgumentError, 'invalid manifest schema' unless JSONSchemer.valid_schema?(entry['params'])
          end
          raise ArgumentError, 'duplicate manifest tool' unless entries.map { |entry| entry['name'] }.uniq.length == entries.length

          entries.to_h { |entry| [entry['name'], entry] }
        end

        public_class_method def self.register(opts = {})
          entries = load(directory: opts[:directory] || DIRECTORY)
          entries.each_value do |entry|
            next unless entry['plugin']
            raise ArgumentError, 'plugin must be a PWN::Plugins constant' unless entry['plugin'].match?(/\APWN::Plugins::[A-Z]\w*\z/)
            raise ArgumentError, 'invalid plugin method' unless entry['method'].to_s.match?(/\A[a-z]\w*[!?]?\z/)

            declaration = entry
            Registry.register(
              name: entry['name'], toolset: 'manifest',
              schema: { name: entry['name'], description: entry['description'], parameters: JSON.parse(JSON.generate(entry['params']), symbolize_names: true) },
              handler: lambda { |args|
                plugin = declaration['plugin'].split('::').inject(Object) { |mod, name| mod.const_get(name, false) }
                method = plugin.public_method(declaration['method'])
                method.arity.zero? ? method.call : method.call(args)
              }
            )
          end
          entries
        end

        # Missing policy preserves the legacy unrestricted operator workflow.
        public_class_method def self.check(opts = {})
          path = opts[:scope_path] || File.expand_path('~/.pwn/scope.yaml')
          policy = opts[:scope_policy]
          return nil if policy.nil? && !File.exist?(path)

          policy = YAML.safe_load_file(path, permitted_classes: [], aliases: false) if policy.nil?

          policy = JSON.parse(JSON.generate(policy))
          raise ArgumentError, 'scope policy must be an object' unless policy.is_a?(Hash)
          return nil if policy['enabled'] == false

          entries = load(directory: opts[:manifest_directory] || DIRECTORY)
          declaration = entries[opts[:name]] || {}
          args = JSON.parse(JSON.generate(opts[:args]))
          fields = declaration['target_params'] || { 'hosts' => %w[target targets host hosts domain domains cidr cidrs url urls], 'ports' => %w[port ports] }
          hosts = Array(fields['hosts']).flat_map { |key| Array(args[key]) }
          ports = Array(fields['ports']).flat_map { |key| Array(args[key]) }
          outside = hosts.any? do |target|
            host = target.to_s
            if host.include?('://')
              uri = URI.parse(host)
              ports << uri.port if uri.respond_to?(:port) && uri.port
              host = uri.host.to_s
            end
            !host_allowed?(host: host, policy: policy)
          end
          outside ||= ports.any? { |port| Array(policy['allowed_ports']).none? { |allowed| port_range(value: allowed).cover?(port_range(value: port)) } }
          return deny(opts.merge(reason: 'out_of_scope')) if outside

          risk = declaration['risk_level'] || 'crit'
          gate = (policy['risk_gates'] || {}).fetch(risk, 'deny')
          return deny(opts.merge(reason: 'risk_denied')) unless GATES.include?(gate) && gate != 'deny'

          if gate == 'prompt'
            callback = opts[:approval_callback]
            request = { name: opts[:name], risk_level: risk, args: JSON.parse(JSON.generate(args)) }
            return deny(opts.merge(reason: 'approval_required')) unless callback.respond_to?(:call) && callback.call(request) == true
          end

          nil
        rescue StandardError
          deny(opts.merge(reason: 'invalid_scope_policy'))
        end

        private_class_method def self.host_allowed?(opts = {})
          host = opts[:host]
          policy = opts[:policy]
          begin
            target = IPAddr.new(host)
            return Array(policy['allowed_cidrs']).any? do |cidr|
              allowed = IPAddr.new(cidr)
              allowed.include?(target.to_range.first) && allowed.include?(target.to_range.last)
            end
          rescue IPAddr::InvalidAddressError
            return false unless host.match?(/\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.?\z/)
          end
          host = host.downcase.delete_suffix('.')
          Array(policy['allowed_domains']).any? do |domain|
            domain = domain.to_s.downcase.delete_suffix('.')
            domain.start_with?('*.') ? host.end_with?(domain.delete_prefix('*')) : host == domain
          end
        end

        private_class_method def self.port_range(opts = {})
          value = opts[:value]
          raise ArgumentError, 'invalid port' unless value.to_s.match?(/\A\d+(?:-\d+)?\z/)

          first, last = value.to_s.split('-').map(&:to_i)
          last ||= first
          raise ArgumentError, 'invalid port range' unless first >= 1 && last <= 65_535 && first <= last

          first..last
        end

        private_class_method def self.deny(opts = {})
          reason = opts[:reason]
          path = opts[:audit_path] || File.expand_path('~/.pwn/logs/scope-audit.jsonl')
          FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
          File.open(path, File::WRONLY | File::CREAT | File::APPEND, 0o600) do |file|
            file.flock(File::LOCK_EX)
            file.puts(JSON.generate(time: Time.now.utc.iso8601, tool: opts[:name], reason: reason))
          end
          { success: false, denied: reason, code: 'SCOPE_DENY' }
        rescue StandardError
          { success: false, denied: reason, code: 'SCOPE_DENY', audit_error: 'audit_write_failed' }
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Load trusted YAML tool declarations.
            #{self}.load(
              directory: 'optional - trusted manifest directory; default lib/pwn/ai/tools'
            )

            # Register whitelisted plugin methods as tools.
            #{self}.register(
              directory: 'optional - trusted manifest directory; default lib/pwn/ai/tools'
            )

            # Check declared targets and risk gates before dispatch.
            #{self}.check(
              name: 'required - registered tool name',
              args: 'required - parsed tool argument Hash',
              scope_policy: 'optional - trusted policy Hash instead of the policy file',
              scope_path: 'optional - trusted scope YAML path; default ~/.pwn/scope.yaml',
              manifest_directory: 'optional - trusted YAML manifest directory',
              approval_callback: 'optional - trusted callback returning literal true for prompt approval',
              audit_path: 'optional - trusted audit JSONL destination'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
        end
      end
    end
  end
end
