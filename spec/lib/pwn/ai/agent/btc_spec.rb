# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::BTC do
  it 'analyze method should exist' do
    analyze_response = PWN::AI::Agent::BTC
    expect(analyze_response).to respond_to :analyze
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::BTC
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::BTC
    expect(help_response).to respond_to :help
  end
end
