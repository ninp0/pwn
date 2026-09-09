# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/skill_consolidation'
require 'tmpdir'

RSpec.describe PWN::AI::Agent::SkillConsolidation do
  it 'promotes only recent independently verified fixes and quarantines stale or conflicting feedback' do
    content = "# SOP\nUse TLS.\n\n## RL feedback\n- [stable] Check certificate.\n- [conflict] Use TLS.\n- [conflict] Never use TLS.\n- [stale] Use old endpoint.\n- [unverified] Guess endpoint.\n"
    evidence = {
      'stable' => { resolved: true, verified_sessions: %w[s1 s2 s3], last_verified: '2026-09-08' },
      'stale' => { resolved: true, verified_sessions: %w[s1 s2 s3], last_verified: '2020-01-01' }
    }
    result = described_class.consolidate(content: content, evidence: evidence, now: Time.utc(2026, 9, 8))
    expect(result[:promoted]).to eq(['stable'])
    expect(result[:review].map { |r| r[:reason] }).to include('conflicting feedback', 'stale verification')
    expect(result[:content]).to include("## Verified procedures\n- [stable] Check certificate.")
    expect(result[:content]).to include("# SOP\nUse TLS.")
    expect(result[:content]).to include('Guess endpoint.')
    expect(described_class.consolidate(content: result[:content], evidence: evidence, now: Time.utc(2026, 9, 8))[:content]).to eq(result[:content])
  end

  it 'previews by default and applies only to the exact unchanged fixture with confirmation' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'SKILL.md')
      original = "# Fixture\n\n## RL feedback\n- [a] Check.\n- [b] Check.\n"
      File.write(path, original)
      proposal = described_class.consolidate_file(path: path)
      expect(File.read(path)).to eq(original)
      expect { described_class.consolidate_file(path: path, dry_run: false) }.to raise_error(ArgumentError)
      expect { described_class.consolidate_file(path: path, dry_run: false, confirm: true, expected_sha256: 'stale') }.to raise_error(ArgumentError)
      applied = described_class.consolidate_file(path: path, dry_run: false, confirm: true, expected_sha256: proposal[:source_sha256])
      expect(applied[:written]).to be(true)
      expect(File.read(path)).to eq(applied[:content])
      expect(File.read(applied[:backup_path])).to eq(original)
    end
  end

  it 'deduplicates dated RL entries and flags explicit negation against the SOP without deleting prose' do
    content = "# SOP\nUse TLS.\n\n## RL feedback\n- [a] [2026-09-01] Check headers.\n- [b] [2026-09-02] Check headers.\n- [c] Never use TLS.\n"
    result = described_class.consolidate(content: content, now: Time.utc(2026, 9, 8))
    expect(result[:deduplicated]).to eq(1)
    expect(result[:review].map { |r| r[:reason] }).to include('contradicts SOP')
    expect(result[:content]).to include("# SOP\nUse TLS.")
  end

  it 'retires a promoted managed procedure when its verification becomes stale' do
    evidence = { 'a' => { resolved: true, verified_sessions: %w[one two three], last_verified: '2026-01-01' } }
    initial = described_class.consolidate(content: "# SOP\nUnmanaged line.\n\n## RL feedback\n- [a] Managed procedure.\n", evidence: evidence, now: Time.utc(2026, 1, 2))
    later = described_class.consolidate(content: initial[:content], evidence: evidence, now: Time.utc(2026, 9, 8))
    expect(later[:review].map { |row| row[:id] }).to eq(['a'])
    expect(later[:content]).not_to include("## Verified procedures\n- [a]")
    expect(later[:content]).to include('Unmanaged line.')
  end

  it 'deduplicates feedback without changing SOP prose and version stamps idempotently' do
    content = "---\nname: fixture\ndescription: Test\n---\n# Procedure\nKeep this exact SOP.\n\n## RL feedback\n- [fix:a] Use fixture.\n- [fix:b] Use fixture.\n"
    result = described_class.consolidate(content: content)
    expect(result[:content].scan('Use fixture.').length).to eq(1)
    expect(result[:content]).to include('Keep this exact SOP.')
    expect(result[:version]).to match(/\A[0-9a-f]{12}\z/)
    expect(described_class.consolidate(content: result[:content])[:content]).to eq(result[:content])
  end
end
