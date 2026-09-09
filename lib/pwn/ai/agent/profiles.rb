# frozen_string_literal: true

require 'timeout'
require 'socket'

module PWN
  module AI
    module Agent
      # Immutable per-request provider routing; never changes provider defaults.
      class Profiles
        PROVIDERS = %i[openai ollama anthropic grok gemini openwebui].freeze

        def initialize(profiles: {})
          raise ArgumentError, 'ai_profiles must be a mapping' unless profiles.is_a?(Hash)

          @profiles = profiles.to_h do |name, value|
            raise ArgumentError, "invalid profile #{name}" unless value.is_a?(Hash)

            [name.to_s.dup.freeze, copy(value).transform_keys(&:to_sym).freeze]
          end
        end

        def lookup(name:)
          profile = @profiles.fetch(name.to_s) { raise ArgumentError, "unknown AI profile: #{name}" }
          provider = profile[:provider].to_s.to_sym
          raise ArgumentError, "unsupported profile provider: #{provider}" unless PROVIDERS.include?(provider)

          route = { name: name.to_s, provider: provider }
          %i[model temperature system_prompt].each do |key|
            route[key] = profile[key].is_a?(String) ? profile[key].dup : profile[key] if profile.key?(key)
          end
          route
        end

        def routes(name: nil, preferred_profile: nil, engine: nil, model: nil)
          unless engine.to_s.empty? && model.to_s.empty?
            route = {}
            route[:provider] = engine.to_sym unless engine.to_s.empty?
            route[:model] = model unless model.to_s.empty?
            return [route]
          end
          selected = preferred_profile.to_s.empty? ? name : preferred_profile
          return [] if selected.to_s.empty?

          queue = [selected.to_s]
          visited = []
          result = []
          until queue.empty?
            current = queue.shift
            next if visited.include?(current)

            visited << current
            result << lookup(name: current)
            profile = @profiles.fetch(current)
            queue.concat(Array(profile[:fallback] || profile[:fallback_chain]).map(&:to_s))
          end
          result
        end

        def call(**)
          candidates = routes(**)
          raise ArgumentError, 'no profile or explicit route selected' if candidates.empty?

          candidates.each_with_index do |route, index|
            return yield(route)
          rescue StandardError => e
            raise unless unavailable?(e) && index < candidates.length - 1
          end
        end

        private

        def copy(value)
          case value
          when Hash then value.to_h { |key, item| [copy(key), copy(item)] }
          when Array then value.map { |item| copy(item) }.freeze
          when String then value.dup.freeze
          else value
          end
        end

        def unavailable?(error)
          return true if error.is_a?(Timeout::Error) || error.is_a?(SocketError) || error.is_a?(EOFError)
          return true if [Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ENETUNREACH].any? { |klass| error.is_a?(klass) }

          status = error.respond_to?(:http_code) ? error.http_code.to_i : 0
          status == 429 || status.between?(500, 599)
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Display author information.
            #{self}.authors
          "
        end
      end
    end
  end
end
