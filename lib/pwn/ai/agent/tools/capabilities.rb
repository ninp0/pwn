# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'capabilities',
  toolset: 'pwn',
  schema: {
    name: 'capabilities',
    description: 'Cached plugin/binary/CAP_* manifest (~/.pwn/capabilities.json) refreshed at session start.',
    parameters: {
      type: 'object',
      properties: { refresh: { type: 'boolean' } }
    }
  },
  handler: lambda { |args|
    PWN::Plugins::PreflightChecker.manifest(refresh: args[:refresh] || args['refresh'])
  }
)
