# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools capabilities' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/capabilities.rb'
  end

  it 'registers the capabilities tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'capabilities')).not_to be_nil
  end
end
