# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'

module PWN
  module AI
    module Agent
      # Request-local context accounting and pinned engagement evidence.
      class EngagementMemory
        # Explicit independent budgets keep request state out of global configuration.
        # rubocop:disable Metrics/ParameterLists
        def initialize(original_goal:, session_id:, window: 128_000, keep_last: 8, root: File.expand_path('~/.pwn/artifacts'), tool_cap: 8192)
          raise ArgumentError, 'window, keep_last and tool_cap must be positive' unless [window, keep_last, tool_cap].all? { |n| n.is_a?(Integer) && n.positive? }

          @original_goal = original_goal.to_s.dup.freeze
          @session_id = session_id.to_s
          raise ArgumentError, 'invalid session ID' unless @session_id.match?(/\A[a-zA-Z0-9_-]+\z/)

          @root = root
          @window = window
          @keep_last = keep_last
          @tool_cap = tool_cap
          @summary = ''
          @state_path = File.join(@root, @session_id, 'engagement-memory.json')
          stored = File.file?(@state_path) ? JSON.parse(File.read(@state_path)) : {}
          @notes = stored.fetch('notes', '')
          @summary = stored.fetch('summary', '')
        end

        # rubocop:enable Metrics/ParameterLists

        def compact(messages:, usage: nil)
          unless tokens(messages: messages, usage: usage) > @window * 0.75
            return messages if (@notes.empty? && @summary.empty?) || messages.any? { |m| (m[:content] || m['content']) == view }

            systems, turns = messages.partition { |m| (m[:role] || m['role']).to_s == 'system' }
            systems.reject! { |m| (m[:content] || m['content']).to_s.start_with?("ENGAGEMENT MEMORY\n") }
            return systems + [{ role: 'system', content: view }] + turns
          end

          systems, turns = messages.partition { |m| (m[:role] || m['role']).to_s == 'system' }
          cut = [turns.length - @keep_last, 0].max
          # Never orphan a tool result from its assistant tool-call envelope.
          cut -= 1 while cut.positive? && (turns[cut][:role] || turns[cut]['role']).to_s == 'tool'
          return messages if cut.zero?

          combined = [@summary, summarize(turns.first(cut))].reject(&:empty?).join("\n")
          budget = [@window, 8192].min
          @summary = combined.byteslice(-budget, budget) || combined
          @summary = @summary.force_encoding(Encoding::UTF_8).scrub('')
          save
          systems.reject! { |m| (m[:content] || m['content']).to_s.start_with?("ENGAGEMENT MEMORY\n") }
          original = turns.first(cut).find { |m| (m[:role] || m['role']).to_s == 'user' && (m[:content] || m['content']).to_s == @original_goal }
          systems + [{ role: 'system', content: view }] + (original ? [original] : []) + turns.drop(cut)
        end

        def tokens(messages:, usage: nil)
          data = usage.is_a?(Hash) ? usage.transform_keys(&:to_s) : {}
          data = data['usage'].transform_keys(&:to_s) if data['usage'].is_a?(Hash)
          count = data['prompt_tokens'] || data['input_tokens'] || data['prompt_eval_count']
          return count.to_i if count&.to_i&.positive?

          # Conservative byte-based estimate, including roles and tool envelopes.
          (JSON.generate(messages).bytesize / 3.0).ceil
        end

        def view
          "ENGAGEMENT MEMORY\nOriginal user goal (unchanged):\n#{@original_goal}\nPinned evidence / notes:\n#{@notes}\nRolling summary (excerpts):\n#{@summary}"
        end

        def edit(text:)
          @notes = text.to_s
          save
          view
        end

        def save
          FileUtils.mkdir_p(File.dirname(@state_path), mode: 0o700)
          temp = "#{@state_path}.#{SecureRandom.hex(8)}"
          File.open(temp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            file.write(JSON.generate(notes: redact(@notes), summary: redact(@summary), original_goal: redact(@original_goal)))
          end
          File.rename(temp, @state_path)
          @state_path
        ensure
          File.unlink(temp) if temp && File.exist?(temp)
        end

        def spill(content:)
          raw = content.is_a?(String) ? content : JSON.generate(content)
          return raw if raw.bytesize <= @tool_cap

          dir = File.join(@root, @session_id)
          FileUtils.mkdir_p(dir, mode: 0o700)
          path = File.join(dir, "tool-#{SecureRandom.hex(12)}.txt")
          clean = redact(raw)
          File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(clean) }
          suffix = "\n[Tool output excerpt; #{raw.bytesize} original bytes]\nRaw artifact: #{path}"
          raise ArgumentError, 'tool_cap cannot fit artifact reference' if suffix.bytesize > @tool_cap

          excerpt = clean.byteslice(0, @tool_cap - suffix.bytesize).force_encoding(Encoding::UTF_8).scrub('')
          excerpt + suffix
        end

        private

        def redact(text)
          return PWN::Redaction.redact(value: text) if defined?(PWN::Redaction)
          return PWN::Sessions.redact(text: text) if defined?(PWN::Sessions) && PWN::Sessions.respond_to?(:redact)

          text
        end

        def summarize(turns)
          turns.map do |message|
            role = message[:role] || message['role']
            text = (message[:content] || message['content'] || JSON.generate(message)).to_s
            "#{role}: #{text[0, 600]}#{' [excerpt]' if text.length > 600}"
          end.join("\n")
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
