# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/request_runtime'

describe PWN::AI::Agent::RequestRuntime do
  include_context 'pwn tmp sandbox'

  it 'connects the loop provider call to the selected profile' do
    runtime = described_class.new(request: 'Check fixture', session_id: 'runtime', profile: 'local',
                                  profiles: { local: { provider: 'ollama', model: 'fixture-local', temperature: 0.2 } }, artifact_root: @tmp)
    previous = Thread.current[:pwn_request_runtime]
    Thread.current[:pwn_request_runtime] = runtime
    allow(PWN::AI::Agent::Loop).to receive(:publish_usage)
    allow(PWN::AI::Agent::Loop).to receive(:active_engine).and_return(:openai)
    allow(PWN::AI::OpenAI).to receive(:chat_with_tools).and_raise('profile routing was not applied')
    expect(PWN::AI::Ollama).to receive(:chat_with_tools).with(hash_including(model: 'fixture-local', temp: 0.2)).and_return(
      choices: [{ message: { role: 'assistant', content: 'verified' } }]
    )
    result = PWN::AI::Agent::Loop.send(:call_engine, messages: [{ role: 'user', content: 'Check fixture' }], tools: [])
    expect(result[:content]).to eq('verified')
  ensure
    Thread.current[:pwn_request_runtime] = previous
  end

  it 'routes a profile fallback without changing global configuration and records the response' do
    profiles = { first: { provider: 'openai', model: 'first-model', fallback: ['backup'] }, backup: { provider: 'ollama', model: 'backup-model', temperature: 0.2 } }
    runtime = described_class.new(request: 'Check fixture', session_id: 'runtime', profile: 'first', profiles: profiles, artifact_root: @tmp)
    seen = []
    response = runtime.call(messages: [{ role: 'user', content: 'Check fixture' }], tools: []) do |messages, route|
      seen << route
      expect(messages.last[:content]).to eq('Check fixture')
      raise Errno::ECONNREFUSED if route[:provider] == :openai

      { role: 'assistant', content: 'verified' }
    end
    expect(seen.map { |row| row[:model] }).to eq(%w[first-model backup-model])
    expect(response[:content]).to eq('verified')
    rows = PWN::SessionTrace.read(session_id: 'runtime')
    expect(rows.map { |row| row['event'] }).to eq(%w[request response])
    expect(rows.last['model']).to eq('backup-model')
  end

  it 'records original tool arguments and spills large output with an artifact reference' do
    runtime = described_class.new(request: 'Check fixture', session_id: 'runtime', artifact_root: @tmp, tool_cap: 1024)
    call = { id: 'call1', function: { name: 'shell', arguments: '{"command":"printf fixture"}' } }
    runtime.tool_call(call)
    compact = runtime.tool_result(call, 'x' * 9000)
    expect(compact.bytesize).to be <= 1024
    expect(compact).to include('Raw artifact:')
    rows = PWN::SessionTrace.read(session_id: 'runtime')
    expect(rows.find { |row| row['event'] == 'tool_call' }.dig('data', 'arguments', 'command')).to eq('printf fixture')
    expect(rows.last.dig('data', 'content').length).to eq(9000)
  end
end
