# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::SAST do
  it 'scan method should exist' do
    scan_response = PWN::AI::Agent::SAST
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::SAST
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::SAST
    expect(help_response).to respond_to :help
  end
end
