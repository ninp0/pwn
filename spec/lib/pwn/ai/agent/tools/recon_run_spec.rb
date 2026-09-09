# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'recon_run tool' do
  it 'registers the normalized pipeline and passes string-key parameters without losing ingestion controls' do
    PWN::AI::Agent::Registry.discover(force: true)
    entry = PWN::AI::Agent::Registry.lookup(name: 'recon_run')
    expect(entry).not_to be_nil
    expect(entry.schema[:parameters][:required]).to include('target', 'modules')
    expect(PWN::Plugins::Recon).to receive(:run).with({ target: '127.0.0.1', modules: ['banner'], ingest: true }).and_return(assets: [])
    expect(entry.handler.call('target' => '127.0.0.1', 'modules' => ['banner'])).to eq(assets: [])
  end
end
