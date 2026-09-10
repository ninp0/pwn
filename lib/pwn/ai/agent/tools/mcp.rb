# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/mcp'

PWN::AI::Agent::Registry.register(
  name: 'mcp',
  toolset: 'mcp',
  schema: {
    name: 'mcp',
    description: 'Talk to local MCP servers through any PWN::AI::MCP::* client. ' \
                 'action=backends lists clients. action=use selects one. ' \
                 'connect/list_tools/call_tool/ping/status/disconnect operate on ' \
                 'that backend; session state persists across turns. ' \
                 'allow_hardware is connect-only and default false. ' \
                 'Pass tool arguments as a JSON object; keep string IDs as strings.',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          description: 'backends | use | current | connect | disconnect | ping | list_tools | call_tool | poll_until | status'
        },
        backend: { type: 'string', description: 'Snake_case PWN::AI::MCP client name from action=backends.' },
        session_id: { type: 'string', description: 'Optional session key. Defaults to the backend name.' },
        name: { type: 'string', description: 'MCP tool name for call_tool, from list_tools on the selected backend.' },
        arguments: { type: 'object', description: 'JSON object passed to tools/call. String IDs stay strings.' },
        allow_hardware: { type: 'boolean', description: 'Only for connect. Default false. Never implied.' },
        command: { type: 'string', description: 'Optional executable path for connect.' },
        timeout: { type: 'integer', description: 'Seconds for handshake, reads, or poll_until.' },
        states: { type: 'array', items: { type: 'string' }, description: 'poll_until terminal states if the backend implements it.' },
        interval: { type: 'number', description: 'Seconds between poll_until status reads.' }
      },
      required: %w[action]
    }
  },
  handler: lambda { |args|
    PWN::AI::MCP.invoke(args)
  }
)
