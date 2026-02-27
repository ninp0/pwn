# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Assembly do
  it 'scan method should exist' do
    scan_response = PWN::AI::Agent::Assembly
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Assembly
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Assembly
    expect(help_response).to respond_to :help
  end
end
