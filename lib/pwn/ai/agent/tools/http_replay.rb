# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/plugins/mitm_proxy'

{
  'http_proxy_start' => [:start, 'Start a native intercepting HTTP proxy; HAR includes sensitive traffic. HTTPS CONNECT tunnels are opaque (metadata only). Default bind is loopback.',
                         { har_path: { type: 'string' }, host: { type: 'string' }, port: { type: 'integer' }, timeout: { type: 'number' }, rules: { type: 'array', items: { type: 'object' } } }, []],
  'http_proxy_stop' => [:stop, 'Stop a capture proxy and flush its HAR.', { proxy_id: { type: 'string' } }, %w[proxy_id]],
  'http_proxy_entries' => [:entries, 'Read captured HAR entries and their _request_id for replay.', { proxy_id: { type: 'string' } }, %w[proxy_id]],
  'http_proxy_rules' => [:rules, 'Replace literal match/replace rules: phase=request|response, field=body|url|header:NAME, match, replace. Response URL rules unsupported.',
                         { proxy_id: { type: 'string' }, rules: { type: 'array', items: { type: 'object' } } }, %w[proxy_id rules]],
  'http_replay' => [:http_replay, 'Replay a captured HTTP request with method/url/path/query/headers/body mutations. Null header values remove headers. Returns newly captured HAR entry.',
                    { proxy_id: { type: 'string' }, request_id: { type: 'string' }, mutations: { type: 'object', properties: {
                      method: { type: 'string' }, url: { type: 'string' }, path: { type: 'string' }, query: { type: 'string' }, headers: { type: 'object' }, body: { type: 'string' }
                    } } }, %w[proxy_id request_id]]
}.each do |name, (method, description, properties, required)|
  PWN::AI::Agent::Registry.register(
    name: name, toolset: 'http',
    schema: { name: name, description: description, parameters: { type: 'object', properties: properties, required: required } },
    handler: ->(args) { PWN::Plugins::MitmProxy.public_send(method, args) }
  )
end
