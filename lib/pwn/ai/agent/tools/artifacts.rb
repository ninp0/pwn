# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'artifacts_list',
  toolset: 'sessions',
  schema: {
    name: 'artifacts_list',
    description: 'List loot under ~/.pwn/artifacts for a session.',
    parameters: {
      type: 'object',
      properties: { session_id: { type: 'string' } }
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ArtifactRegistry.list(session_id: args[:session_id] || args['session_id'] || 'default')
  }
)
PWN::AI::Agent::Registry.register(
  name: 'artifacts_get',
  toolset: 'sessions',
  schema: {
    name: 'artifacts_get',
    description: 'Read an artifact by path (sha256 + body cap).',
    parameters: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: %w[path]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ArtifactRegistry.get(path: args[:path] || args['path'])
  }
)
PWN::AI::Agent::Registry.register(
  name: 'artifact_read',
  toolset: 'sessions',
  schema: {
    name: 'artifact_read',
    description: 'Page an artifact as text/hex/base64 from offset.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        offset: { type: 'integer' },
        length: { type: 'integer' },
        mode: { type: 'string', description: 'text|hex|base64' },
        grep: { type: 'string' },
        ref: { type: 'string' },
        sha256: { type: 'string' }
      },
      required: %w[path]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ArtifactRegistry.read_page(
      path: args[:path] || args['path'] || args[:ref] || args['ref'],
      offset: args[:offset] || args['offset'],
      length: args[:length] || args['length'],
      mode: args[:mode] || args['mode'],
      grep: args[:grep] || args['grep'],
      sha256: args[:sha256] || args['sha256']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'artifact_put',
  toolset: 'sessions',
  schema: {
    name: 'artifact_put',
    description: 'Store bytes or a file in the content-addressed artifact store.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        bytes: { type: 'string' },
        kind: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        session_id: { type: 'string' }
      }
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ArtifactRegistry.put(
      path: args[:path] || args['path'],
      bytes: args[:bytes] || args['bytes'],
      kind: args[:kind] || args['kind'],
      tags: args[:tags] || args['tags'],
      session_id: args[:session_id] || args['session_id']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'artifact_get',
  toolset: 'sessions',
  schema: {
    name: 'artifact_get',
    description: 'Fetch an artifact by sha256 or path.',
    parameters: {
      type: 'object',
      properties: { sha256: { type: 'string' }, path: { type: 'string' } }
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ArtifactRegistry.get(sha256: args[:sha256] || args['sha256'], path: args[:path] || args['path'])
  }
)
