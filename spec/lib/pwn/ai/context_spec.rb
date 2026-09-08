# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Context do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'attaches a file with sha256 and chunks' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      path = File.join(dir, 'note.md')
      File.write(path, 'hello world ' * 20)
      row = described_class.attach_file(path: path, session_id: 's1')
      expect(row[:sha256]).to match(/\A[0-9a-f]{64}\z/)
      expect(row[:chunks]).not_to be_empty
      expect(File.file?(row[:path])).to be true
    end
  end

  it 'attaches a hexdump slice' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      path = File.join(dir, 'blob.bin')
      File.binwrite(path, "\x7fELF#{0.chr * 64}")
      row = described_class.attach_hexdump(path: path, offset: 0, length: 16)
      expect(row[:kind]).to eq('hexdump')
      expect(row[:sha256]).not_to be_empty
    end
  end

  it 'attaches an HTTP transcript string' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      row = described_class.attach_http_transcript(har_or_raw: '{"log":{"entries":[]}}')
      expect(row[:kind]).to eq('http_transcript')
    end
  end
end
