# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools swarm' do
  before(:all) { PWN::AI::Agent::Registry.discover(force: true) }

  %w[agent_list agent_spawn agent_ask agent_debate agent_broadcast swarm_bus swarm_list].each do |tool|
    it "registers the #{tool} tool" do
      expect(PWN::AI::Agent::Registry.lookup(name: tool)).not_to be_nil
    end
  end

  it 'exposes the swarm toolset in the registry' do
    expect(PWN::AI::Agent::Registry.toolsets).to include('swarm')
  end

  it 'exposes and forwards the optional model when spawning a persona' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'agent_spawn')
    expect(entry.schema.dig(:parameters, :properties, :model, :type)).to eq('string')
    expect(entry.schema.dig(:parameters, :required)).not_to include('model')
    expect(PWN::AI::Agent::Swarm).to receive(:spawn).with(hash_including(engine: 'openwebui', model: 'Exact/Model:Tag'))
    entry.handler.call(name: 'reviewer', role: 'Review', engine: 'openwebui', model: 'Exact/Model:Tag')
  end

  it 'includes the configured model in the persona listing' do
    allow(PWN::AI::Agent::Swarm).to receive(:personas).and_return(reviewer: { engine: :openai, model: 'Exact/Model:Tag' })
    result = PWN::AI::Agent::Registry.lookup(name: 'agent_list').handler.call({})
    expect(result.first).to include(engine: :openai, model: 'Exact/Model:Tag')
  end
end
