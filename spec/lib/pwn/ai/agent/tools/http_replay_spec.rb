# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'HTTP replay tools' do
  before { PWN::AI::Agent::Registry.discover }

  it 'registers callable proxy lifecycle, capture and replay tools' do
    %w[http_proxy_start http_proxy_stop http_proxy_entries http_proxy_rules http_replay].each do |name|
      expect(PWN::AI::Agent::Registry.lookup(name: name)).not_to be_nil
    end
    Dir.mktmpdir do |dir|
      proxy = PWN::AI::Agent::Registry.lookup(name: 'http_proxy_start')[:handler].call(har_path: File.join(dir, 'tool.har'))
      entries = PWN::AI::Agent::Registry.lookup(name: 'http_proxy_entries')[:handler].call(proxy_id: proxy[:id])
      expect(entries).to eq([])
      expect { PWN::AI::Agent::Registry.lookup(name: 'http_replay')[:handler].call(proxy_id: proxy[:id], request_id: 'missing') }.to raise_error(ArgumentError, /unknown request_id/)
      stopped = PWN::AI::Agent::Registry.lookup(name: 'http_proxy_stop')[:handler].call(proxy_id: proxy[:id])
      expect(stopped[:stopped]).to be(true)
    end
  end
end
