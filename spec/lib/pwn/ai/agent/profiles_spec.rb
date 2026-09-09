# frozen_string_literal: true

require 'spec_helper'
require 'timeout'
require 'pwn/ai/agent/profiles'

RSpec.describe 'PWN::AI::Agent::Profiles' do
  it 'snapshots configuration and accepts every dispatch provider without swallowing programming errors' do
    config = { p: { provider: 'openwebui', model: +'Exact', fallback: ['backup'] }, backup: { provider: 'grok' } }
    profiles = PWN::AI::Agent::Profiles.new(profiles: config)
    config[:p][:model].replace('changed')
    expect(profiles.lookup(name: 'p')[:model]).to eq('Exact')
    PWN::AI::Agent::Loop::ENGINE_MODS.each_key do |provider|
      expect(PWN::AI::Agent::Profiles.new(profiles: { p: { provider: provider } }).lookup(name: 'p')[:provider]).to eq(provider)
    end
    seen = []
    expect do
      profiles.call(name: 'p') do |route|
        seen << route
        raise ArgumentError, 'bad payload'
      end
    end.to raise_error(ArgumentError, 'bad payload')
    expect(seen.length).to eq(1)
    expect { profiles.lookup(name: 'unknown') }.to raise_error(ArgumentError)
    expect(profiles.routes).to eq([])
    outputs = %i[grok ollama].map do |engine|
      Thread.new { profiles.routes(name: 'p', engine: engine, model: "#{engine}/Exact") }
    end.map(&:value)
    expect(outputs.map { |routes| routes.first[:provider] }).to eq(%i[grok ollama])
  end
  it 'routes preferred profiles and falls back without mutating config or persona thread state' do
    config = { 'local' => { 'provider' => 'ollama', 'model' => 'Code/Exact:Tag', 'temperature' => 0.2, 'system_prompt' => 'code', 'fallback' => ['remote'] }, 'remote' => { provider: 'openai', model: 'remote', fallback: ['local'] } }
    snapshot = Marshal.dump(config)
    profiles = PWN::AI::Agent::Profiles.new(profiles: config)
    seen = []
    response = profiles.call(name: 'remote', preferred_profile: 'local') do |route|
      seen << route
      raise Timeout::Error, 'offline' if route[:provider] == :ollama

      'ok'
    end
    expect(response).to eq('ok')
    expect(seen.map { |r| r[:provider] }).to eq(%i[ollama openai])
    expect(seen.first).to include(model: 'Code/Exact:Tag', temperature: 0.2, system_prompt: 'code')
    expect(Marshal.dump(config)).to eq(snapshot)
    expect(profiles.routes(name: 'local', engine: :grok, model: 'Persona/Exact')).to eq([{ provider: :grok, model: 'Persona/Exact' }])
    expect(profiles.routes(name: 'local', engine: :grok)).to eq([{ provider: :grok }])
  end
end
