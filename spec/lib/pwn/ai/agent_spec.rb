# frozen_string_literal: true

require 'spec_helper'

describe Pwn::AI::Agent do
  it 'should return data for help method' do
    help_response = Pwn::AI::Agent.help
    expect(help_response).not_to be_nil
  end
end
