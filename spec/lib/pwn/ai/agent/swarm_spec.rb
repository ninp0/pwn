# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Swarm do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Swarm
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Swarm
    expect(help_response).to respond_to :help
  end

  it 'exposes the core orchestration API' do
    %i[personas spawn retire create list ask debate broadcast bus_append bus_tail
       pack_specialist child_inbox child_honesty view_graph claim honesty_unmet].each do |m|
      expect(PWN::AI::Agent::Swarm).to respond_to m
    end
  end

  it 'normalizes personas loaded from AGENTS_FILE without raising' do
    expect { PWN::AI::Agent::Swarm.personas }.not_to raise_error
  end

  it 'enforces the recursion depth guard' do
    Thread.current[:pwn_swarm_depth] = 999
    expect do
      PWN::AI::Agent::Swarm.ask(name: PWN::AI::Agent::Swarm.personas.keys.first || :__none, request: 'x')
    end.to raise_error(StandardError)
  ensure
    Thread.current[:pwn_swarm_depth] = nil
  end

  it 'text_only / empty toolsets strip tools so a reviewer cannot open browsers' do
    src = File.read(described_class.method(:ask).source_location.first)
    expect(src).to match(/text_only/)
    expect(src).to match(/core_only:\s*empty_tools/)
  end

  it 'maps several ports and returns a merged result set' do
    rows = described_class.map_targets(targets: '127.0.0.1', ports: '1,9,22,80')
    expect(rows.length).to eq(4)
    expect(rows.map { |r| r[:port] }.uniq.length).to eq(4)
  end

  it 'allows only one live claim per unit' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      a = described_class.claim(unit: '10.0.0.5:recon', agent_id: 'a', ttl: 60, engagement_id: 'lab')
      b = described_class.claim(unit: '10.0.0.5:recon', agent_id: 'b', ttl: 60, engagement_id: 'lab')
      expect(a[:ok]).to eq(true)
      expect(b[:ok]).to eq(false)
    end
  end

  it 'packs specialists to at most three skills and strips swarm unless orchestrator' do
    packed = described_class.pack_specialist(name: 'xss', skills: %w[xss sqli ssrf auth], toolsets: %w[pwn swarm terminal])
    expect(packed[:skills].length).to eq(3)
    expect(packed[:toolsets]).not_to include('swarm')
    orch = described_class.pack_specialist(name: 'lead', skills: %w[recon], toolsets: %w[swarm pwn], orchestrator: true)
    expect(orch[:toolsets]).to include('swarm')
  end

  it 'spills long bus rows to the artifact store and keeps a short content plus ref' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'art'))
      s = described_class.create(topic: 'bus')
      body = 'P' * 800
      row = described_class.bus_append(swarm_id: s[:swarm_id], from: :red, content: body)
      expect(row[:content].bytesize).to be <= 400
      expect(row[:sha256]).to match(/\A[0-9a-f]{64}\z/)
      expect(row[:ref].to_s).not_to be_empty
    end
  end

  it 'refuses ask when the work unit is already claimed' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      stub_const('PWN::AI::Agent::Swarm::AGENTS_FILE', File.join(dir, 'agents.yml'))
      described_class.spawn(name: 'red', role: 'recon')
      described_class.claim(unit: '10.0.0.5:recon', agent_id: 'other', ttl: 600, engagement_id: 'lab')
      out = described_class.ask(name: 'red', request: 'recon 10.0.0.5', unit: '10.0.0.5:recon', engagement_id: 'lab')
      expect(out[:ok]).to eq(false)
      expect(out[:error]).to eq('claim_held')
    end
  end

  it 'child inbox lists finding ids from Findings, not reply prose' do
    allow(PWN::Plugins::Findings).to receive(:report).and_return(
      [{ id: 'deadbeef', session_id: 'sess-1', title: 'xss' }]
    )
    allow(PWN::Plugins::ArtifactRegistry).to receive(:list).and_return([])
    box = described_class.child_inbox(session_id: 'sess-1', name: 'red')
    expect(box[:finding_ids]).to eq(['deadbeef'])
  end

  it 'flags child honesty gap when pwn toolset filed nothing' do
    allow(described_class).to receive(:child_inbox).and_return(finding_ids: [], artifact_shas: [], coverage: [])
    h = described_class.child_honesty(name: 'xss', toolsets: %w[pwn], session_id: 's')
    expect(h[:gap]).to eq('child_filed_nothing')
  end

  it 'view_graph lists personas and live claims' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      s = described_class.create(topic: 'g')
      File.write(File.join(dir, 'swarm', s[:swarm_id], 'personas.json'), JSON.generate('red' => 'sess'))
      described_class.claim(unit: 'h1:recon', agent_id: 'red', ttl: 60, engagement_id: s[:swarm_id])
      g = described_class.view_graph(swarm_id: s[:swarm_id])
      expect(g[:agents].map { |a| a[:name] }).to include('red')
      expect(g[:claims].any? { |c| c[:unit] == 'h1:recon' }).to eq(true)
    end
  end

  it 'stores ephemeral personas under the swarm dir, not the host agents.yml' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      stub_const('PWN::AI::Agent::Swarm::AGENTS_FILE', File.join(dir, 'agents.yml'))
      s = described_class.create(topic: 'eph')
      described_class.spawn(name: 'xss', role: 'xss only', swarm_id: s[:swarm_id], ephemeral: true)
      expect(File).not_to exist(File.join(dir, 'agents.yml'))
      expect(described_class.personas(swarm_id: s[:swarm_id]).keys.map(&:to_s)).to include('xss')
    end
  end

  it 'broadcast fans out with threads' do
    src = File.read(described_class.method(:broadcast).source_location.first)
    expect(src).to match(/Thread\.new/)
  end

  it 'ask passes nested: true so nested Loop.run does not write the RN footer' do
    src = File.read(described_class.method(:ask).source_location.first)
    expect(src).to match(/nested:\s*true/)
  end

  it 'migrate_personas empties stock escalator tools and adds pwn to scribe' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'agents.yml')
      File.write(path, <<~YML)
        ---
        red:
          role: keep
          engine: grok
          toolsets: [terminal, pwn]
          max_iters: 25
        scribe:
          role: report
          engine: grok
          toolsets: [memory, skills, learning, sessions]
          max_iters: 10
        escalator:
          role: hint
          engine: grok
          toolsets: [terminal, pwn, memory]
          max_iters: 8
      YML
      out = described_class.migrate_personas(path: path)
      expect(out[:changed]).to eq(true)
      expect(out[:patched]).to include('escalator', 'scribe')
      again = described_class.migrate_personas(path: path)
      expect(again[:changed]).to eq(false)
      loaded = described_class.send(:load_personas_file, path: path)
      expect(loaded[:escalator][:toolsets]).to eq([])
      expect(loaded[:scribe][:toolsets]).to include('pwn')
      expect(loaded[:red][:engine]).to eq(:grok)
      expect(loaded[:red][:toolsets]).to eq(%w[terminal pwn])
    end
  end
end
