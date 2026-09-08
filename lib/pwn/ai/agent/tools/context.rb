# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'context_attach',
  toolset: 'sessions',
  schema: {
    name: 'context_attach',
    description: 'Attach a file, hexdump, disassembly, or HTTP transcript to model context (chunked + SHA-256 store).',
    parameters: {
      type: 'object',
      properties: {
        kind: { type: 'string', description: 'file|hexdump|disasm|http' },
        path: { type: 'string' },
        offset: { type: 'integer' },
        length: { type: 'integer' },
        function: { type: 'string' },
        har_or_raw: { type: 'string' },
        session_id: { type: 'string' }
      },
      required: %w[kind]
    }
  },
  handler: lambda { |args|
    kind = (args[:kind] || args['kind']).to_s
    case kind
    when 'hexdump'
      PWN::AI::Context.attach_hexdump(path: args[:path], offset: args[:offset], length: args[:length], session_id: args[:session_id])
    when 'disasm'
      PWN::AI::Context.attach_disasm(path: args[:path], function: args[:function], session_id: args[:session_id])
    when 'http'
      PWN::AI::Context.attach_http_transcript(har_or_raw: args[:har_or_raw] || args[:path], session_id: args[:session_id])
    else
      PWN::AI::Context.attach_file(path: args[:path], session_id: args[:session_id])
    end
  }
)
