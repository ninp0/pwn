# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'rest-client'

describe PWN::AI::OpenAI do
  describe 'OAuth enrollment persistence' do
    before do
      @oauth_home = Dir.mktmpdir('pwn-openai-oauth')
      stub_const('PWN::Env', { ai: { openai: { oauth: {} } }, driver_opts: { pwn_env_path: File.join(@oauth_home, 'pwn.yaml') } })
      allow(described_class).to receive(:sleep)
      @tokens = { access_token: 'fixture-access', refresh_token: 'fixture-refresh', expires_in: 3600 }
      allow(RestClient).to receive(:post).and_return(
        double(body: { device_auth_id: 'fixture-device', user_code: 'fixture-code', interval: 1 }.to_json),
        double(body: { authorization_code: 'fixture-auth-code', code_verifier: 'fixture-verifier' }.to_json),
        double(body: @tokens.to_json)
      )
    end

    after { FileUtils.remove_entry(@oauth_home) }

    it 'syncs a standalone enrollment into the live environment and attempts vault persistence' do
      expect(described_class).to receive(:persist_oauth_to_vault).with(oauth: hash_including(bearer_token: 'fixture-access', refresh_token: 'fixture-refresh')).and_return(true)
      expect(described_class.obtain_oauth_bearer_token).to eq('fixture-access')
      expect(PWN::Env.dig(:ai, :openai, :oauth)).to include(bearer_token: 'fixture-access', refresh_token: 'fixture-refresh')
    end

    it 'does not print bearer or refresh tokens when enrollment succeeds without a vault' do
      output = StringIO.new
      original = $stdout
      $stdout = output
      described_class.obtain_oauth_bearer_token
      expect(output.string).not_to include('fixture-access', 'fixture-refresh')
      expect(output.string).to include('session only')
    ensure
      $stdout = original
    end

    context 'with an existing encrypted vault' do
      before do
        @vault_path = PWN::Env.dig(:driver_opts, :pwn_env_path)
        @decryptor_path = File.join(@oauth_home, 'custom.decryptor')
        PWN::Env[:driver_opts][:pwn_dec_path] = @decryptor_path
        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        @vault_key = Base64.strict_encode64(cipher.random_key)
        @vault_iv = Base64.strict_encode64(cipher.random_iv)
        File.write(@decryptor_path, YAML.dump({ key: @vault_key, iv: @vault_iv }))
        File.write(@vault_path, YAML.dump({ unrelated: 'preserved', ai: { openai: { model: 'test-model', oauth: { refresh_token: 'previous-refresh' } } } }))
        PWN::Plugins::Vault.encrypt(file: @vault_path, key: @vault_key, iv: @vault_iv)
        @original_ciphertext = File.binread(@vault_path)
      end

      it 'leaves the original vault encrypted and unchanged if re-encryption fails' do
        allow(PWN::Plugins::Vault).to receive(:encrypt).and_raise(IOError, 'fixture write failure')
        expect(described_class.send(:persist_oauth_to_vault, oauth: { bearer_token: 'fixture-access' })).to be(false)
        expect(File.binread(@vault_path)).to eq(@original_ciphertext)
        expect(Dir.children(@oauth_home)).to match_array(%w[pwn.yaml custom.decryptor])
      end

      it 'does not expose vault contents through persistence exception messages' do
        allow(PWN::Plugins::Vault).to receive(:encrypt).and_raise(IOError, 'fixture-access in parser context')
        expect do
          described_class.send(:persist_oauth_to_vault, oauth: { bearer_token: 'fixture-access' })
        end.to output(/vault persistence failed.*IOError/).to_stderr
        expect do
          described_class.send(:persist_oauth_to_vault, oauth: { bearer_token: 'fixture-access' })
        end.not_to output(/fixture-access/).to_stderr
      end

      it 'persists enrollment with the same decryptor, restrictive permissions and unrelated settings intact' do
        decryptor_before = File.binread(@decryptor_path)
        oauth = { account_id: 'fixture-account' }
        described_class.obtain_oauth_bearer_token(oauth)
        expect(PWN::Plugins::Vault.file_encrypted?(file: @vault_path)).to be(true)
        expect(File.stat(@vault_path).mode & 0o777).to eq(0o600)
        expect(File.binread(@decryptor_path)).to eq(decryptor_before)
        persisted = PWN::Plugins::Vault.dump(file: @vault_path, key: @vault_key, iv: @vault_iv)
        expect(persisted[:unrelated]).to eq('preserved')
        expect(persisted.dig(:ai, :openai, :model)).to eq('test-model')
        expect(persisted.dig(:ai, :openai, :oauth)).to include(oauth)
        expect(persisted.dig(:ai, :openai, :oauth, :expires_at)).to be > Time.now.to_i
        expect(Dir.children(@oauth_home)).to match_array(%w[pwn.yaml custom.decryptor])
      end

      it 'persists rotated refresh credentials as well as first enrollment' do
        allow(RestClient).to receive(:post).and_return(double(body: { access_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_in: 3600 }.to_json))
        expect(described_class.refresh_oauth_bearer_token(refresh_token: 'previous-refresh')).to eq('rotated-access')
        persisted = PWN::Plugins::Vault.dump(file: @vault_path, key: @vault_key, iv: @vault_iv)
        expect(persisted.dig(:ai, :openai, :oauth)).to include(bearer_token: 'rotated-access', refresh_token: 'rotated-refresh')
        expect(PWN::Env.dig(:ai, :openai, :oauth)).to include(bearer_token: 'rotated-access', refresh_token: 'rotated-refresh')
      end
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::OpenAI
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::OpenAI
    expect(help_response).to respond_to :help
  end

  it 'chat_with_tools sanitizes messages via Loop.openai_wire_messages' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/openai_wire_messages/)
  end

  it 'does not expose get_plan_usage' do
    expect(described_class).not_to respond_to(:get_plan_usage)
  end

  it 'open_ai_rest_call swallows ReadTimeout quietly without ERROR: print' do
    src = File.read(described_class.method(:chat).source_location.first)
    expect(src).to match(/RestClient::Exceptions::Timeout/)
    expect(src).to match(/quiet: opts\[:quiet\]/)
    timeout_rescue = src[/rescue RestClient::Exceptions::Timeout.*?rescue RestClient::ExceptionWithResponse/m]
    expect(timeout_rescue).not_to match(/puts "ERROR:/)
  end

  it 'chat_with_tools honors PromptCache when prompt_cache is on' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to include('PromptCache.openai_messages')
    expect(src).to include('prompt_cache_key')
    expect(src).to include('enabled?(engine: :openai)')
  end

  it 'treats gpt-5 family as reasoning models' do
    expect(described_class.send(:reasoning_model?, model: 'gpt-5.5')).to eq(true)
    expect(described_class.send(:reasoning_model?, model: 'gpt-5-mini')).to eq(true)
    expect(described_class.send(:reasoning_model?, model: 'gpt-6-astra')).to eq(true)
    expect(described_class.send(:reasoning_model?, model: 'gpt-4o')).to eq(false)
  end

  it 'routes gpt-6-astra and gpt-5.4+ tool calls to responses, gpt-4o to chat/completions' do
    tools = [{ type: 'function', function: { name: 'shell' } }]
    expect(described_class.api_endpoint(model: 'gpt-6-astra', tools: tools)).to eq('responses')
    expect(described_class.api_endpoint(model: 'gpt-5.5', tools: tools)).to eq('responses')
    expect(described_class.api_endpoint(model: 'gpt-5.6-terra', tools: tools)).to eq('responses')
    expect(described_class.api_endpoint(model: 'gpt-4o', tools: tools)).to eq('chat/completions')
    expect(described_class.api_endpoint(model: 'gpt-5-mini', tools: tools)).to eq('chat/completions')
  end

  it 'converts chat tools and messages into Responses function items' do
    tools = [{
      type: 'function',
      function: { name: 'shell', description: 'run', parameters: { type: 'object', properties: {} } }
    }]
    msgs = [
      { role: 'system', content: 'sys' },
      { role: 'user', content: 'hi' },
      { role: 'assistant', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'shell', arguments: '{}' } }] },
      { role: 'tool', tool_call_id: 'c1', content: 'ok' }
    ]
    body = described_class.send(:responses_http_body, model: 'gpt-6-astra', messages: msgs, tools: tools, max_tokens: 128)
    expect(body[:model]).to eq('gpt-6-astra')
    expect(body[:instructions]).to include('sys')
    expect(body[:tools].first[:name]).to eq('shell')
    expect(body[:tools].first).not_to have_key(:function)
    expect(body[:input]).to include(hash_including(type: 'function_call_output', call_id: 'c1'))
    expect(body).not_to have_key(:messages)
    expect(body).not_to have_key(:reasoning_effort)
    expect(body[:max_output_tokens]).to eq(128)
  end

  it 'parses Responses function_call output into Loop assistant_message tool_calls' do
    raw = {
      output_text: '',
      output: [
        { type: 'function_call', call_id: 'c1', name: 'shell', arguments: '{"cmd":"id"}' },
        { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '' }] }
      ]
    }
    out = described_class.send(:parse_responses, raw: raw)
    msg = out[:assistant_message]
    expect(msg[:tool_calls].first[:id]).to eq('c1')
    expect(msg[:tool_calls].first[:function][:name]).to eq('shell')
    expect(msg[:_native_content]).to eq(raw[:output])
  end

  it 'caps chat_with_tools completion tokens and does not retry quota 429s' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to include('max_completion_tokens')
    rest = File.read(described_class.method(:chat).source_location.first)
    expect(rest).to include('quota_exhausted?')
  end
end
