# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'recon_run',
  toolset: 'pwn',
  schema: {
    name: 'recon_run',
    description: 'Run selected recon modules against one hostname/IP, persist normalized assets with stable IDs and evidence paths, and ingest the asset model for retrieval. Scanner observations are not proven findings.',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        modules: { type: 'array', minItems: 1, items: { type: 'string', enum: %w[nmap banner tls subfinder nuclei] } },
        ports: { type: 'array', items: { type: 'integer', minimum: 1, maximum: 65_535 } },
        engagement_id: { type: 'string' },
        timeout: { type: 'number', minimum: 0, maximum: 300 },
        ingest: { type: 'boolean', default: true }
      },
      required: %w[target modules]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Recon.run({ ingest: true }.merge(args.transform_keys(&:to_sym)))
  }
)
