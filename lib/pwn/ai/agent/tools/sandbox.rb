# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/plugins/sandbox'

{
  'sandbox_run' => { method: :run, required: ['binary'], properties: { binary: { type: 'string' }, stdin: { type: 'string' } } },
  'sandbox_fuzz' => { method: :fuzz, required: %w[target corpus minutes], properties: { target: { type: 'string' }, corpus: { type: 'string' }, minutes: { type: 'number', minimum: 0.001, maximum: 60 }, seed: { type: 'integer' } } }
}.each do |name, definition|
  PWN::AI::Agent::Registry.register(
    name: name,
    toolset: 'pwn',
    schema: {
      name: name,
      description: 'Execute only in a disposable no-egress sandbox; structured crash/strace/GDB evidence. Docker default; bwrap is an explicit weaker resource-isolation option. Never host-executes on backend failure.',
      parameters: {
        type: 'object', additionalProperties: false, required: definition[:required],
        properties: definition[:properties].merge(
          argv: { type: 'array', items: { type: 'string' } },
          backend: { type: 'string', enum: %w[docker bwrap] },
          image: { type: 'string' }, timeout: { type: 'number', minimum: 0.01, maximum: 300 },
          memory_mb: { type: 'integer', minimum: 32, maximum: 4096 }
        )
      }
    },
    handler: ->(args) { PWN::Plugins::Sandbox.public_send(definition[:method], args.transform_keys(&:to_sym)) }
  )
end
