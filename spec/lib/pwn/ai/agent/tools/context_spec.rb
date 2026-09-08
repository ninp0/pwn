# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools context' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/context.rb'
  end

  it 'registers the context_attach tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'context_attach')).not_to be_nil
  end
end
