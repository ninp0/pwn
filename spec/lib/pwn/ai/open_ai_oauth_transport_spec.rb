# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::OpenAI do
  let(:engine) do
    {
      model: 'gpt-4o', base_uri: 'https://api.openai.com/v1', key: 'fake-api-key',
      oauth: { bearer_token: 'fake-oauth-token', account_id: 'fake-account' }
    }
  end
  let(:completed) do
    {
      id: 'resp_test', status: 'completed', usage: { input_tokens: 3, output_tokens: 2 },
      output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'Hello' }] }]
    }
  end

  def event(type, fields = {})
    "event: #{type}\ndata: #{fields.merge(type: type).to_json}\n\n"
  end

  before do
    stub_const('PWN::Env', { ai: { openai: engine } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).with(browser_type: :rest).and_return(browser: RestClient)
    allow(PWN::Plugins::TTYSpinner).to receive(:stop)
    allow(described_class).to receive(:obtain_oauth_bearer_token).and_raise('Unexpected enrollment')
    allow(described_class).to receive(:refresh_oauth_bearer_token).and_raise('Unexpected refresh')
    allow(RestClient::Request).to receive(:execute).and_raise('Unexpected HTTP request')
  end

  it 'raises exhausted subscription timeouts instead of returning a blank result' do
    allow(PWN::AI::HttpRetry).to receive(:max_attempts).and_return(1)
    allow(RestClient::Request).to receive(:execute).and_raise(RestClient::Exceptions::ReadTimeout)
    expect { described_class.chat(request: 'Hi', quiet: true) }.to raise_error(RestClient::Exceptions::ReadTimeout)
  end

  it 'rejects failed Responses events even in quiet mode' do
    allow(RestClient::Request).to receive(:execute).and_return(
      event('response.failed', response: { error: { message: 'Model unavailable' } })
    )
    expect { described_class.chat(request: 'Hi', quiet: true) }.to raise_error(RuntimeError, /Model unavailable/)
  end

  it 'routes subscription text chat to streaming Responses even for older model names' do
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to eq('https://chatgpt.com/backend-api/codex/responses')
      expect(request[:headers]).to include(authorization: 'Bearer fake-oauth-token', accept: 'text/event-stream')
      expect(request[:headers]['ChatGPT-Account-Id']).to eq('fake-account')
      body = JSON.parse(request[:payload], symbolize_names: true)
      expect(body).to include(model: 'gpt-4o', input: [{ role: 'user', content: 'Hi' }], instructions: '', store: false, stream: true)
      expect(body.keys & %i[messages temperature max_tokens max_completion_tokens max_output_tokens]).to be_empty
      event('response.completed', response: completed)
    end

    response = described_class.chat(request: 'Hi')
    expect(response[:choices].last[:content]).to eq('Hello')
    expect(response[:usage]).to eq(completed[:usage])
  end

  [
    ['error', { error: { message: 'Stream rejected' } }, /Stream rejected/],
    ['response.incomplete', { response: { incomplete_details: { reason: 'output limit' } } }, /output limit/],
    ['response.completed', { response: { status: 'failed', error: { message: 'Failed completion' } } }, /Failed completion/],
    ['response.completed', {}, /missing response/]
  ].each do |type, fields, message|
    it "rejects invalid terminal stream event #{type} #{fields}" do
      allow(RestClient::Request).to receive(:execute).and_return(event(type, fields))
      expect { described_class.chat(request: 'Hi', quiet: true) }.to raise_error(RuntimeError, message)
    end
  end

  it 'rejects streams ending without a completion rather than using partial text' do
    allow(RestClient::Request).to receive(:execute).and_return(
      "#{event('response.output_text.delta', delta: 'Partial')}data: [DONE]\n\n"
    )
    expect { described_class.chat(request: 'Hi', quiet: true) }.to raise_error(RuntimeError, /before response.completed/)
  end

  it 'preserves native tool outputs from done events when completion has only metadata' do
    reasoning = { type: 'reasoning', id: 'rs_1', encrypted_content: 'fake-encrypted-reasoning' }
    call = { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'shell', arguments: '{"cmd":"pwd"}' }
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to end_with('/codex/responses')
      body = JSON.parse(request[:payload], symbolize_names: true)
      expect(body[:instructions]).to eq('Use tools')
      expect(body[:tools].first).to include(type: 'function', name: 'shell')
      expect(body[:tool_choice]).to eq(type: 'function', name: 'shell')
      event('response.output_item.done', output_index: 1, item: call) +
        event('response.output_item.done', output_index: 0, item: reasoning) +
        event('response.completed', response: completed.except(:output))
    end
    result = described_class.chat_with_tools(
      messages: [{ role: 'system', content: 'Use tools' }, { role: 'user', content: 'Hi' }],
      tools: [{ type: 'function', function: { name: 'shell' } }],
      tool_choice: { type: 'function', function: { name: 'shell' } }
    )
    expect(result[:assistant_message][:_native_content]).to eq([reasoning, call])
    expected_calls = [{ id: 'call_1', type: 'function', function: { name: 'shell', arguments: '{"cmd":"pwd"}' } }]
    expect(result[:assistant_message][:tool_calls]).to eq(expected_calls)
  end

  it 'uses Platform when a failed OAuth refresh falls back to an API key' do
    engine[:base_uri] = 'https://chatgpt.com/backend-api/codex/'
    engine[:oauth].merge!(expires_at: 1, refresh_token: 'fake-refresh')
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to eq('https://api.openai.com/v1/chat/completions')
      expect(request[:headers][:authorization]).to eq('Bearer fake-api-key')
      expect(request[:headers]).not_to have_key('ChatGPT-Account-Id')
      expect(JSON.parse(request[:payload])).to eq('model' => 'gpt-4o', 'temperature' => 0.5, 'messages' => [])
      '{}'
    end
    described_class.send(:open_ai_rest_call,
                         rest_call: 'chat/completions', http_method: :post, non_interactive: true,
                         http_body: { model: 'gpt-4o', temperature: 0.5, messages: [] })
  end

  it 'preserves an explicitly configured HTTPS compatible proxy without duplicate slashes' do
    engine[:base_uri] = 'https://openai-proxy.example/codex/'
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to eq('https://openai-proxy.example/codex/responses')
      expect(request[:verify_ssl]).to eq(true)
      event('response.completed', response: completed)
    end
    described_class.chat(request: 'Hi')
  end

  it 'refuses to send subscription credentials to an insecure custom endpoint' do
    engine[:base_uri] = 'http://openai-proxy.example/codex'
    expect(RestClient::Request).not_to receive(:execute)
    expect { described_class.chat(request: 'Hi', quiet: true) }.to raise_error(ArgumentError, /HTTPS/)
  end

  it 'raises subscription HTTP failures instead of returning a blank answer' do
    allow(RestClient::Request).to receive(:execute).and_raise(RestClient::BadRequest)
    expect { described_class.chat(request: 'Hi') }.to raise_error(RestClient::BadRequest)
  end

  it 'does not follow subscription redirects to another auth endpoint' do
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:max_redirects]).to eq(0)
      event('response.completed', response: completed)
    end
    described_class.chat(request: 'Hi')
  end

  it 'round-trips encrypted reasoning and function items through the agent loop on a stateless tool continuation' do
    PWN::Env[:ai][:active] = :openai
    native = [
      { type: 'reasoning', id: 'rs_1', encrypted_content: 'fake-encrypted-reasoning' },
      { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'shell', arguments: '{}' }
    ]
    messages = [{ role: 'user', content: 'Hi' }]
    tools = [{ type: 'function', function: { name: 'shell' } }]
    expect(RestClient::Request).to receive(:execute).ordered do |request|
      body = JSON.parse(request[:payload], symbolize_names: true)
      expect(body[:include]).to include('reasoning.encrypted_content')
      event('response.completed', response: completed.merge(output: native))
    end
    first = described_class.chat_with_tools(messages: messages, tools: tools)
    messages += [first[:assistant_message], { role: 'tool', tool_call_id: 'call_1', content: 'ok' }]
    expect(RestClient::Request).to receive(:execute).ordered do |request|
      body = JSON.parse(request[:payload], symbolize_names: true)
      expected_input = [
        { role: 'user', content: 'Hi' }, *native,
        { type: 'function_call_output', call_id: 'call_1', output: 'ok' }
      ]
      expect(body[:input]).to eq(expected_input)
      event('response.completed', response: completed)
    end
    expect(PWN::AI::Agent::Loop.send(:call_engine, messages: messages, tools: tools)[:content]).to eq('Hello')
  end

  it 'routes a newly enrolled credential to subscription Responses immediately' do
    engine[:oauth] = { enroll: true }
    allow(described_class).to receive(:obtain_oauth_bearer_token) do |oauth|
      oauth[:account_id] = 'new-account'
      'new-fake-token'
    end
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to eq('https://chatgpt.com/backend-api/codex/responses')
      expect(request[:headers]).to include(authorization: 'Bearer new-fake-token', 'ChatGPT-Account-Id' => 'new-account')
      event('response.completed', response: completed)
    end
    described_class.chat(request: 'Hi')
  end

  it 'uses a refreshed OAuth credential even when a Platform key is configured' do
    engine[:oauth].merge!(expires_at: 1, refresh_token: 'fake-refresh')
    allow(described_class).to receive(:refresh_oauth_bearer_token).and_return('refreshed-fake-token')
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to eq('https://chatgpt.com/backend-api/codex/responses')
      expect(request[:headers][:authorization]).to eq('Bearer refreshed-fake-token')
      event('response.completed', response: completed)
    end
    described_class.chat(request: 'Hi')
  end

  it 'lists Codex models with the required client_version query parameter' do
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:method]).to eq(:get)
      expect(request[:url]).to eq('https://chatgpt.com/backend-api/codex/models')
      expect(request[:headers][:params]).to include(client_version: '1.0.0')
      expect(request[:headers][:authorization]).to eq('Bearer fake-oauth-token')
      { data: [{ id: 'gpt-5.5' }] }.to_json
    end
    models = described_class.get_models
    expect(models[:data].first[:id]).to eq('gpt-5.5')
  end

  it 'maps a Codex slug catalog onto data[].id for /model list llms' do
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:method]).to eq(:get)
      expect(request[:url]).to eq('https://chatgpt.com/backend-api/codex/models')
      { models: [{ slug: 'gpt-6-astra', display_name: 'GPT-6-Astra' }] }.to_json
    end
    models = described_class.get_models
    expect(models[:data].first[:id]).to eq('gpt-6-astra')
  end

  it 'lists Platform models without a Codex client_version query' do
    engine[:oauth] = {}
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:method]).to eq(:get)
      expect(request[:url]).to eq('https://api.openai.com/v1/models')
      params = request.dig(:headers, :params)
      expect(params).to be_nil.or(satisfy { |row| row.nil? || row[:client_version].to_s.empty? })
      { data: [{ id: 'gpt-4o' }] }.to_json
    end
    models = described_class.get_models
    expect(models[:data].first[:id]).to eq('gpt-4o')
  end

  it 'leaves API-key text chat on Chat Completions with its original parameters' do
    engine[:oauth] = {}
    expect(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to eq('https://api.openai.com/v1/chat/completions')
      expect(request[:headers]).not_to have_key('ChatGPT-Account-Id')
      body = JSON.parse(request[:payload], symbolize_names: true)
      expect(body).to include(temperature: 0.5, max_completion_tokens: 16_384)
      expect(body.keys & %i[stream store input include]).to be_empty
      { choices: [{ message: { role: 'assistant', content: 'API answer' } }] }.to_json
    end
    expect(described_class.chat(request: 'Hi', temp: 0.5)[:choices].last[:content]).to eq('API answer')
  end

  %w[gpt-4o gpt-5.5].each do |model|
    it "leaves API-key tool routing and token caps unchanged for #{model}" do
      engine[:oauth] = {}
      expect(RestClient::Request).to receive(:execute) do |request|
        body = JSON.parse(request[:payload], symbolize_names: true)
        expect(body.keys & %i[stream store include]).to be_empty
        if model == 'gpt-4o'
          expect(request[:url]).to eq('https://api.openai.com/v1/chat/completions')
          expect(body[:max_completion_tokens]).to eq(16_384)
          expect(body[:messages].first).not_to have_key(:_native_content)
          { choices: [{ message: { role: 'assistant', content: 'API answer' } }] }.to_json
        else
          expect(request[:url]).to eq('https://api.openai.com/v1/responses')
          expect(body[:max_output_tokens]).to eq(16_384)
          completed.to_json
        end
      end
      described_class.chat_with_tools(model: model, messages: [{ role: 'user', content: 'Hi', _native_content: [] }])
    end
  end

  it 'collects all completed text parts from a CRLF multiline SSE event' do
    completed[:output].first[:content] << { type: 'output_text', text: ' world' }
    payload = JSON.pretty_generate(type: 'response.completed', response: completed)
    sse = ": heartbeat\r\n\r\nevent: response.completed\r\n#{payload.lines.map { |line| "data: #{line.chomp}\r\n" }.join}\r\n"
    allow(RestClient::Request).to receive(:execute).and_return(sse)
    expect(described_class.chat(request: 'Hi')[:choices].last[:content]).to eq('Hello world')
  end

  it 'rejects a truncated final SSE frame even when its JSON is complete' do
    allow(RestClient::Request).to receive(:execute).and_return(event('response.completed', response: completed).rstrip)
    expect { described_class.chat(request: 'Hi', quiet: true) }.to raise_error(RuntimeError, /before response.completed/)
  end
end
