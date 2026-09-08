# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::AI::Agent::Engagement do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'blocks out-of-scope IPs when a CIDR engagement is active' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Engagement::ROOT', File.join(dir, '.pwn', 'engagements'))
      stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(dir, '.pwn', 'engagements', 'active'))
      described_class.open(name: 'lab', scope_cidrs: ['10.0.0.0/24'])
      deny = described_class.deny_if_out_of_scope(command: 'scan 8.8.8.8')
      expect(deny[:error]).to include('8.8.8.8')
      expect(described_class.in_scope?(ip: '10.0.0.5')).to eq(true)
    end
  end

  it 'enforces ~/.pwn/roe.yaml allow/deny when present' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      FileUtils.mkdir_p(File.join(dir, '.pwn'))
      File.write(File.join(dir, '.pwn', 'roe.yaml'), "targets_allow:\n  - 10.0.0.0/8\ntargets_deny:\n  - evil.example\ntechniques_deny:\n  - dos\n")
      expect(described_class.in_scope?(host: '10.1.2.3')).to eq(true)
      expect(described_class.in_scope?(host: 'evil.example')).to eq(false)
      deny = described_class.deny_if_out_of_scope(command: 'launch dos flood')
      expect(deny[:code]).to eq('ROE_DENY')
    end
  end
end
