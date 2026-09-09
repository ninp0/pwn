# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'Authenticated credential envelopes' do
  it 'uses an injected OS keyring key, rejects tampering and never creates a file-based key' do
    vault = PWN::Plugins::Vault
    keyring = lambda { |id|
      raise 'wrong key id' unless id == 'test-key'

      'k' * 32
    }
    opts = { credentials: { token: 'fixture-only' }, keyring: keyring, key_id: 'test-key' }
    a = vault.seal_credentials(opts)
    b = vault.seal_credentials(opts)
    expect(a['iv']).not_to eq(b['iv'])
    expect(vault.open_credentials(envelope: a, keyring: keyring)).to eq('token' => 'fixture-only')
    a['ct'] = Base64.strict_encode64('tampered')
    expect { vault.open_credentials(envelope: a, keyring: keyring) }.to raise_error(ArgumentError, /authentication/)
    expect { vault.seal_credentials(credentials: {}) }.to raise_error(ArgumentError, /passphrase/)
  end

  it 'reads legacy CBC vault fixtures in memory without ever writing plaintext to disk' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'legacy')
      cipher = OpenSSL::Cipher.new('aes-256-cbc')
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      bytes = Base64.strict_encode64(cipher.update("api_key: fixture-only\n") + cipher.final)
      File.write(path, bytes)
      expect(File).not_to receive(:write)
      expect(PWN::Plugins::Vault.dump(file: path, key: Base64.strict_encode64(key), iv: Base64.strict_encode64(iv))).to eq(api_key: 'fixture-only')
      expect(File.read(path)).to eq(bytes)
    end
  end

  it 'round trips credentials in a YAML temp artifact using a passphrase without plaintext or adjacent keys' do
    vault = PWN::Plugins::Vault
    credentials = { 'api_key' => 'fixture-credential-only' }
    envelope = vault.seal_credentials(credentials: credentials, passphrase: 'fixture passphrase')
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'pwn.yaml')
      File.write(path, YAML.dump('ai' => { 'credentials' => envelope }))
      expect(File.read(path)).not_to include('fixture-credential-only', 'fixture passphrase')
      parsed = YAML.safe_load_file(path)['ai']['credentials']
      expect(vault.open_credentials(envelope: parsed, passphrase: 'fixture passphrase')).to eq(credentials)
      expect(parsed['cipher']).to eq('aes-256-gcm')
      expect(Dir.children(dir)).to eq(['pwn.yaml'])
      expect { vault.open_credentials(envelope: parsed, passphrase: 'incorrect') }.to raise_error(ArgumentError, /authentication/)
    end
  end
end
