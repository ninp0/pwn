# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe 'Sandbox isolation' do
  it 'registers runnable sandbox tools' do
    require 'pwn/ai/agent/tools/sandbox'
    entry = PWN::AI::Agent::Registry.lookup(name: 'sandbox_run')
    expect(entry.schema[:parameters][:required]).to include('binary')
    result = entry.handler.call('binary' => '/bin/true', 'backend' => 'not-a-backend')
    expect(result[:ok]).to eq(false)
    expect(PWN::AI::Agent::Registry.lookup(name: 'sandbox_fuzz')).not_to be_nil
  end
  it 'fails closed for an unavailable backend without executing the target' do
    require 'pwn/plugins/sandbox'
    result = PWN::Plugins::Sandbox.run(binary: '/bin/true', backend: 'not-a-backend')
    expect(result[:ok]).to eq(false)
    expect(result[:error]).to include('backend')
  end
end
