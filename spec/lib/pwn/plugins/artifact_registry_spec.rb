# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::ArtifactRegistry do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'lists artifacts for a session id' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', dir)
      src = File.join(dir, 'loot.txt')
      File.write(src, 'x')
      described_class.register(session_id: 'sess1', path: src, kind: 'loot')
      rows = described_class.list(session_id: 'sess1')
      expect(rows.first[:kind]).to eq('loot')
    end
  end

  it 'greps an artifact by regex' do
    Dir.mktmpdir do |dir|
      src = File.join(dir, 'dump.txt')
      File.write(src, "nop\ncall system\nret\n")
      hits = described_class.read_page(path: src, grep: 'call.*system')
      expect(hits[:matches].first[:text]).to include('call system')
    end
  end

  it 'round-trips put then get by sha256' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'art'))
      stored = described_class.put(bytes: 'pcap-bytes', kind: 'pcap', tags: ['net'])
      got = described_class.get(sha256: stored[:sha256])
      expect(got[:body]).to include('pcap-bytes')
      expect(stored[:tags]).to include('net')
    end
  end
end
