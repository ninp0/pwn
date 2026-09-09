# frozen_string_literal: true

require 'digest'

module PWN
  # Shared write-boundary redaction. Never opens a credential store.
  module Redaction
    PATTERNS = {
      pem: /-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)/m,
      authorization: /\b(?:Proxy-)?Authorization\s*[:=]\s*(?!\[REDACTED:)[^\r\n"'\\]+/i,
      jwt: /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
      aws: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
      bearer: %r{\bBearer\s+[A-Za-z0-9._~+/=-]+}i,
      api_key: /\b(?:sk|rk|xai|xox[baprs]|ghp|gho|ghu|ghs|ghr|glpat)[-_][A-Za-z0-9_-]{16,}/,
      password: /\b(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret)\s*[:=]\s*(?!\[REDACTED:)[^\s,"'}]+/i,
      cookie: /\bSet-Cookie:\s*(?!\[REDACTED:)[^\r\n]+/i
    }.freeze
    SECRET_FIELD = /\A(?:password|passwd|secret|api[_-]?key|authorization|proxy-authorization|access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret)\z/i

    public_class_method def self.redact(opts = {})
      value = opts[:value]
      case value
      when Hash
        value.to_h do |key, item|
          clean = if key.to_s.match?(SECRET_FIELD) && !item.nil?
                    token(kind: key.to_s.downcase, value: item.to_s)
                  else
                    redact(value: item)
                  end
          [key.is_a?(String) ? redact(value: key) : key, clean]
        end
      when Array then value.map { |item| redact(value: item) }
      when String
        PATTERNS.reduce(value.dup) do |text, (kind, regex)|
          text.split(/(\[REDACTED:[^:\]]+:[0-9a-f]{8}\])/).map do |part|
            part.start_with?('[REDACTED:') ? part : part.gsub(regex) { |match| token(kind: kind, value: match) }
          end.join
        end
      else value
      end
    end

    public_class_method def self.token(opts = {})
      value = opts[:value].to_s
      return value if value.match?(/\A\[REDACTED:[^:]+:[0-9a-f]{8}\]\z/)

      "[REDACTED:#{opts[:kind]}:#{Digest::SHA256.hexdigest(value)[0, 8]}]"
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Recursively redact secret patterns before persistence.
        #{self}.redact(
          value: 'required - string or nested JSON-compatible data'
        )
        # Create a correlatable non-reversible replacement marker.
        #{self}.token(
          kind: 'required - secret type label',
          value: 'required - sensitive value to hash'
        )
        # Print the author information.
        #{self}.authors
      "
    end
  end
end
