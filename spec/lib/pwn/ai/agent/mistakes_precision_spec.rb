# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'Mistake error-class precision' do
  let(:mistakes) { PWN::AI::Agent::Mistakes }
  let(:errors) do
    ['permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock',
     'Error response from daemon: pull access denied for private/image, repository does not exist',
     'docker inspect: template parsing error: unexpected token']
  end

  it 'prioritizes permission, registry and template classes over generic daemon text' do
    expect(errors.map { |e| mistakes.error_class(error: e) }).to eq(%w[socket_perm docker_registry_auth parse_error])
    expect(errors.map { |e| mistakes.signature(tool: 'shell', error: e) }.uniq.length).to eq(3)
  end

  it 'rejects generic resolutions for classified errors and excludes legacy bad fixes from context' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(dir, 'mistakes.json'))
      stub_const('PWN::Memory::MEMORY_FILE', File.join(dir, 'memory.json'))
      stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(dir, 'preferences.jsonl'))
      row = mistakes.record(tool: 'shell', error: errors[1])
      expect { mistakes.resolve(signature: row[:signature], fix: 'Path missing or command failed. ls/test -e the parent first.') }.to raise_error(ArgumentError, /generic/)
      row.merge!(resolved: true, fix: 'Path missing or command failed. ls/test -e the parent first.')
      mistakes.save(store: { row[:signature].to_sym => row })
      expect(mistakes.to_context).not_to include('Path missing or command failed')
    end
  end

  it 'records successful hint sessions separately from failure sessions for conservative skill promotion' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(dir, 'mistakes.json'))
      row = mistakes.record(tool: 'shell', error: errors[1], session_id: 'failed')
      mistakes.note_hint_outcome(signature: row[:signature], helped: true, session_id: 'passed')
      result = mistakes.note_hint_outcome(signature: row[:signature], helped: true, session_id: 'passed')
      expect(result[:verified_sessions]).to eq(['passed'])
      expect(result[:last_verified]).not_to be_nil
      result = mistakes.note_hint_outcome(signature: row[:signature], helped: false, session_id: 'passed')
      expect(result[:verified_sessions]).to eq([])
    end
  end

  it 'never auto-resolves specific docker failures with generic nonzero/path or raw-socket fixes' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(dir, 'mistakes.json'))
      stub_const('PWN::Memory::MEMORY_FILE', File.join(dir, 'memory.json'))
      stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(dir, 'preferences.jsonl'))
      errors.each do |error|
        row = mistakes.record(tool: 'shell', error: error, shape: 'nonzero_exit')
        expect(mistakes.extinguish!(signature: row[:signature], force: true)[:resolved]).to be(false)
        expect(mistakes.correction_hint(tool: 'shell', error: error)).not_to match(/Path missing|CAP_NET_RAW|open_sockraw/)
      end
    end
  end
end
