# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'rest-client'

describe PWN::AI::HttpRetry do
  it 'defaults timeout to 180 and max_attempts to 5' do
    expect(described_class.timeout_s).to eq(180)
    expect(described_class.timeout_s(timeout: nil)).to eq(180)
    expect(described_class.timeout_s(timeout: 60)).to eq(60)
    expect(described_class.max_attempts).to eq(5)
    expect(described_class.max_attempts(quiet: true)).to eq(1)
    expect(described_class.max_attempts(timeout: 12)).to eq(1)
    expect(described_class.max_attempts(max_attempts: 3)).to eq(3)
  end

  it 'treats gateway 504 and stream absolute timeouts as retryable' do
    expect(described_class.retryable?(error: 'ERROR: Ollama HTTP 504 for api/chat: Gateway Time-out')).to eq(true)
    expect(described_class.retryable?(error: 'ERROR: Ollama stream absolute timeout after 20s for api/chat')).to eq(true)
    expect(described_class.retryable?(error: '400 Bad Request')).to eq(false)
  end

  it 'tees emit lines into the open debug request log' do
    path = PWN::Plugins::Log.start_debug(
      tee: StringIO.new,
      path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-httpretry.log"
    )
    err = RestClient::Exceptions::ReadTimeout.new('Timed out reading data from server')
    described_class.report_event(
      label: 'openai',
      error: err,
      http_method: :post,
      rest_call: 'chat/completions',
      extra: 'timeout=180s attempt=1/5',
      quiet: true
    )
    body = File.read(path)
    expect(body).to include('[pwn-ai/openai]')
    expect(body).to include('Timed out reading data from server')
    expect(body).to include('timeout=180s')
  ensure
    PWN::Plugins::Log.stop_debug if defined?(PWN::Plugins::Log)
  end

  it 'honors Retry-After seconds and does not use sub-second fallback' do
    resp = instance_double('RestClient::Response', headers: { retry_after: '45' })
    expect(described_class.retry_after_s(response: resp, retry_count: 1)).to eq(45.0)
    expect(described_class.retry_after_s(retry_count: 1)).to be >= 2.0
    expect(described_class.retry_after_s(retry_count: 4)).to be >= 8.0
  end

  it 'treats insufficient_quota 429 bodies as non-retryable' do
    resp = instance_double('RestClient::Response', body: '{"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}')
    err = instance_double('RestClient::TooManyRequests', message: '429 Too Many Requests', response: resp)
    expect(described_class.quota_exhausted?(error: err)).to eq(true)
    expect(described_class.quota_exhausted?(error: '429 rate_limit_exceeded')).to eq(false)
  end

  it 'builds an operator billing line from credit_balance_exhausted 429 bodies' do
    resp = instance_double(
      'RestClient::Response',
      body: '{"error":{"message":"You have no credits remaining. Add credits to continue using the API at https://platform.openai.com/settings/organization/billing/.","type":"insufficient_quota","code":"credit_balance_exhausted"}}'
    )
    err = instance_double('RestClient::TooManyRequests', message: '429 Too Many Requests', response: resp)
    expect(described_class.quota_exhausted?(error: err)).to eq(true)
    msg = described_class.quota_message(error: err)
    expect(msg).to include('no credits')
    expect(msg).to include('platform.openai.com/settings/organization/billing')
    expect(msg).to include('ChatGPT')
  end

  {
    'PWN::AI::Grok' => '/opt/pwn/lib/pwn/ai/grok.rb',
    'PWN::AI::OpenAI' => '/opt/pwn/lib/pwn/ai/open_ai.rb',
    'PWN::AI::Anthropic' => '/opt/pwn/lib/pwn/ai/anthropic.rb',
    'PWN::AI::Gemini' => '/opt/pwn/lib/pwn/ai/gemini.rb',
    'PWN::AI::Ollama' => '/opt/pwn/lib/pwn/ai/ollama.rb',
    'PWN::AI::OpenWebUI' => '/opt/pwn/lib/pwn/ai/open_web_ui.rb'
  }.each do |name, path|
    it "#{name} uses HttpRetry 180s / max_attempts and retries ReadTimeout" do
      src = File.read(path)
      expect(src).to include('HttpRetry')
      expect(src).not_to match(/timeout \|\|= 900/)
      expect(src).to match(/Exceptions::Timeout/)
      expect(src).to match(/HttpRetry\.report_event/)
      expect(src).to match(/retryable\?|HTTP 50/) if name == 'PWN::AI::Ollama'
    end
  end
end
