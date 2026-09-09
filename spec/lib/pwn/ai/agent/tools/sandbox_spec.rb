# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/tools/sandbox'

describe 'Sandbox agent registrations' do
  it 'dispatches both registered sandbox methods' do
    %w[sandbox_run sandbox_fuzz].each do |name|
      entry = PWN::AI::Agent::Registry.lookup(name: name)
      expect(entry).not_to be_nil
      expect(entry.schema[:parameters][:type]).to eq('object')
      expect(entry.handler.call(binary: '/bin/true', target: '/bin/true', corpus: '/nonexistent', backend: 'absent')[:ok]).to eq(false)
    end
  end
end
