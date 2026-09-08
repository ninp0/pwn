# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Policy do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'learns a better Q for a rewarded action than a punished one' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset

    allow(described_class).to receive(:enabled?).and_return(true)
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:agent] ||= {}
    PWN::Env[:ai][:agent][:policy] = true

    described_class.begin_episode(
      session_id: 'spec_win',
      request: 'inventory host tools',
      kind: :autonomous_goal,
      engine: :ollama
    )
    4.times { described_class.observe_step(action: 'shell', ok: true, session_id: 'spec_win') }
    described_class.finish(session_id: 'spec_win', score: 0.95, verdict: :solved)

    described_class.begin_episode(
      session_id: 'spec_lose',
      request: 'inventory host tools',
      kind: :autonomous_goal,
      engine: :ollama
    )
    4.times { described_class.observe_step(action: 'extro_rf_tune', ok: false, session_id: 'spec_lose') }
    described_class.finish(session_id: 'spec_lose', score: 0.05, verdict: :wrong)

    s = described_class.current_state
    # reopen a comparable state
    described_class.begin_episode(
      session_id: 'spec_query',
      request: 'inventory host tools',
      kind: :autonomous_goal,
      engine: :ollama
    )
    s = described_class.current_state
    q_shell = described_class.q(state: s, action: 'shell')
    q_rf    = described_class.q(state: s, action: 'extro_rf_tune')
    expect(q_shell).to be > q_rf

    rec = described_class.recommend(actions: %w[shell extro_rf_tune], epsilon: 0.0)
    expect(rec[:action]).to eq 'shell'

    ev = described_class.evaluate(limit: 10)
    expect(ev[:n]).to eq 2
    expect(ev[:mean_return]).not_to be_nil

    st = described_class.stats
    expect(st[:n_episodes]).to be >= 2
    expect(st[:n_updates]).to be >= 4
    expect(described_class.to_context).to include('POLICY')
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end
  it 'quality bin sees plan and usable result' do
    open_s = described_class.state(
      kind: :autonomous_goal,
      request: 'fix the reward judge',
      engine: :grok,
      ts_state: { plan: %w[inspect tighten verify], plan_idx: 0 }
    )
    done_s = described_class.state(
      kind: :autonomous_goal,
      request: 'fix the reward judge',
      engine: :grok,
      ts_state: {
        plan: %w[inspect tighten verify],
        plan_idx: 2,
        evidence_blob: 'inspected reward.rb patched judge 12 examples, 0 failures'
      },
      final: 'The cheap ORM now grades the last tools and usable result.',
      score: 0.82
    )
    expect(open_s).to include('|pl')
    expect(open_s).to include('un|')
    expect(done_s).to include('|ph')
    expect(done_s).to include('uy|')
    expect(open_s).not_to eq(done_s)
  end

  it 'quality bin is not high while English tasks remain even if plan_idx is last' do
    last_but_open = described_class.state(
      kind: :autonomous_goal,
      request: 'fix the reward judge',
      engine: :grok,
      ts_state: { plan: %w[inspect tighten verify], plan_idx: 2 }
    )
    expect(last_but_open).to include('|p')
    expect(last_but_open).not_to include('|ph')
  end

  it 'observe_step credits English-task progress above bare tool-ok hygiene' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:agent] ||= {}
    PWN::Env[:ai][:agent][:policy] = true

    ts = {
      plan: ['locate the source', 'fix the truncation bug', 'run rspec to verify'],
      plan_idx: 0,
      evidence_blob: ''
    }
    described_class.begin_episode(
      session_id: 'en_credit',
      request: 'locate then fix',
      kind: :autonomous_goal,
      engine: :grok,
      ts_state: ts
    )
    grind = described_class.observe_step(
      action: 'shell', ok: true, session_id: 'en_credit', ts_state: ts
    )
    poc = "/tmp/pwn-policy-#{Process.pid}.poc"
    File.write(poc, 'poc')
    Thread.current[:pwn_loop_deliverables] = {
      paths: [],
      min_seconds: 0,
      skills: [],
      proofs: [poc],
      hosts: [],
      techniques: []
    }
    advance = described_class.observe_step(
      action: 'shell', ok: true, session_id: 'en_credit', ts_state: ts
    )
    expect(advance[:reward].to_f).to eq(0.0)
    expect(grind[:reward].to_f).to eq(0.0)
  ensure
    FileUtils.rm_f(poc) if defined?(poc)
    Thread.current[:pwn_loop_deliverables] = nil
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'warmup! meets the episode budget so greedy suggestions appear' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    described_class::COLD_EPISODES.times do |i|
      sid = "warm_budget_#{i}"
      described_class.begin_episode(session_id: sid, request: 'uname', kind: :question, engine: :grok)
      described_class.observe_step(action: 'shell', ok: true, session_id: sid)
      described_class.finish(session_id: sid, score: 0.8, verdict: :solved)
    end
    tab = described_class.load
    tab[:returns] = tab[:returns].first(2)
    tab[:warmed_at] = nil
    described_class.save(table: tab)
    expect(described_class.cold?).to be true
    described_class.warmup!(limit: 20)
    expect(described_class.episode_budget_met?).to be true
    expect(described_class.to_context).not_to include('omit greedy suggestion')
    expect(described_class.to_context).to include('suggest=')
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'warmup! replays stored trajectories into Q' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    described_class.begin_episode(session_id: 'w1', request: 'uname', kind: :autonomous_goal, engine: :grok)
    described_class.observe_step(action: 'shell', ok: true, session_id: 'w1')
    described_class.finish(session_id: 'w1', score: 0.9, verdict: :solved)
    tab = described_class.load
    tab[:q] = {}
    tab[:visits] = {}
    tab[:warmed_at] = nil
    described_class.save(table: tab)
    r = described_class.warmup!(limit: 10)
    expect(r[:td_updates].to_i).to be >= 1
    expect(described_class.stats[:n_updates].to_i).to be >= 1
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'drops the omit-greedy banner once the episode budget is met' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:agent] ||= {}
    PWN::Env[:ai][:agent][:policy] = true
    described_class::COLD_EPISODES.times do |i|
      sid = "budget_#{i}"
      described_class.begin_episode(session_id: sid, request: 'uname', kind: :question, engine: :grok)
      described_class.observe_step(action: 'shell', ok: true, session_id: sid)
      described_class.finish(session_id: sid, score: 0.8, verdict: :solved)
    end
    ctx = described_class.to_context
    expect(ctx).to include('POLICY')
    expect(ctx).not_to include('omit greedy suggestion')
    expect(described_class.cold?).to be false
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  describe 'episode handoff' do
    it 'detach_episode! snapshots and clears current_episode' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
      stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
      described_class.reset
      allow(described_class).to receive(:enabled?).and_return(true)
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:policy] = true
      described_class.begin_episode(session_id: 'detach1', request: 'uname', kind: :question, engine: :grok)
      expect(described_class.current_episode).to be_a(Hash)
      ep = described_class.detach_episode!
      expect(ep[:session_id]).to eq('detach1')
      expect(described_class.current_episode).to be_nil
      described_class.attach_episode!(episode: ep)
      expect(described_class.current_episode[:session_id]).to eq('detach1')
    ensure
      described_class.attach_episode!(episode: nil)
      described_class.reset
      FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
    end
  end

  it 'observe_step does not pay per successful tool call' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:agent] ||= {}
    PWN::Env[:ai][:agent][:policy] = true
    described_class.begin_episode(session_id: 'p0_step', request: 'scan', kind: :autonomous_goal, engine: :grok)
    first = described_class.observe_step(action: 'shell', ok: true, session_id: 'p0_step')
    expect(first[:reward].to_f).to eq(0.0)
    8.times { described_class.observe_step(action: 'shell', ok: true, session_id: 'p0_step') }
    extra = described_class.observe_step(action: 'shell', ok: true, session_id: 'p0_step')
    expect(extra[:reward].to_f).to be_within(0.001).of(-0.01)
    fin = described_class.finish(session_id: 'p0_step', score: 0.9, confidence: 1.0, verdict: :solved)
    expect(fin[:score].to_f).to eq(0.9)
    expect(fin[:return]).not_to be_nil
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end
end

describe PWN::AI::Agent::Policy do
  describe 'outcome-gated contextual learning' do
    around do |example|
      Dir.mktmpdir do |tmp|
        @policy_dir = tmp
        example.run
      ensure
        described_class.attach_episode!(episode: nil)
      end
    end

    before do
      stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(@policy_dir, 'policy.json'))
      stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(@policy_dir, 'policy_traj.jsonl'))
      allow(described_class).to receive(:enabled?).and_return(true)
    end

    it 'does not train or count an unjudged episode even when step costs accrue' do
      described_class.begin_episode(request: 'inspect host')
      10.times { described_class.observe_step(action: 'shell', ok: true) }
      report = described_class.finish(score: nil, proxy_ok: true)

      expect(report).to include(td_updates: 0, pg_updates: 0, return: nil)
      expect(described_class.load).to include(q: {}, h: {}, visits: {}, returns: [])
      expect(described_class.current_episode).to be_nil
      expect(described_class.trajectories.first).to include(score: nil, return: nil)
      (described_class::COLD_EPISODES - 1).times do
        described_class.begin_episode(request: 'inspect host')
        described_class.finish(score: nil)
      end
      expect(described_class.warmup!).to include(td_updates: 0, replayed: 0)
      expect(described_class.stats[:n_episodes]).to eq(0)
      expect(described_class.evaluate[:n]).to eq(0)
      expect(described_class.episode_budget_met?).to be(false)
    end

    it 'backs off sparse, missing, or mismatched context to broad scores' do
      described_class.begin_episode(request: 'inspect')
      described_class.observe_step(action: 'file', operation: 'read', ok: true)
      state = described_class.current_state
      context = described_class.current_context_state
      table = described_class.load
      table[:q][state.to_sym] = { alpha: 0.5, beta: 0.0 }
      table[:visits][state.to_sym] = { alpha: 5, beta: 5 }
      table[:q][context.to_sym] = { alpha: -1.0, beta: 1.0 }
      table[:visits][context.to_sym] = { alpha: 2, beta: 2 }
      described_class.save(table: table)
      options = { state: state, actions: %w[alpha beta], epsilon: 0.0 }

      expect(described_class.recommend(options)[:action]).to eq('alpha')
      expect(described_class.advantage(state: state, action: 'beta', context_state: context)).to eq(described_class.advantage(state: state, action: 'beta'))
      table[:visits][context.to_sym] = { alpha: 3, beta: 3 }
      described_class.save(table: table)
      expect(described_class.recommend(options)[:action]).to eq('beta')
      expect(described_class.recommend(options.merge(context_state: nil))[:action]).to eq('alpha')
      other_state = described_class.state(request: 'scan')
      expect(described_class.recommend(options.merge(state: other_state, context_state: context))[:action]).to eq('alpha')
    end

    it 'replays contextual values without manufacturing extra contextual samples' do
      described_class.begin_episode(request: 'inspect')
      described_class.observe_step(action: 'file', args: { action: 'read', path: '/not-stored' }, ok: true)
      context = described_class.current_context_state
      described_class.observe_step(action: 'shell', ok: true)
      described_class.finish(score: 1.0)
      table = described_class.load
      table[:q] = {}
      table[:visits] = {}
      described_class.save(table: table)

      2.times do
        described_class.warmup!
        expect(described_class.q(state: context, action: 'shell')).to be_positive
        expect(described_class.load[:visits].dig(context.to_sym, :shell)).to eq(1)
      end
    end

    it 'records only bounded action features while retaining the complete original request in memory' do
      request = "inspect #{'private-request ' * 30}"
      args = { action: 'read', path: '/private/credential-location', token: 'private-token', 'private-key-name' => { nested: 'private-value' } }
      described_class.begin_episode(request: request)
      step = described_class.observe_step(action: 'file', args: args, result_type: :enoent, ok: false)

      expect(step[:action_context]).to eq(
        operation: 'read',
        arguments: { shape: 'object', size: 'few', features: %w[operation:string other:object other:string path:string] },
        result_type: 'enoent'
      )
      expect(described_class.current_episode[:request]).to eq(request)
      expect(args[:token]).to eq('private-token')
      described_class.finish(score: 0.0)
      persisted = File.read(described_class::TRAJECTORY_FILE) + File.read(described_class::POLICY_FILE)
      expect(persisted).not_to include('private-', '/private/')
      expect(described_class.trajectories.first[:request_family]).to eq('misc')

      described_class.begin_episode(request: 'inspect')
      unknown = described_class.observe_step(action: 'file', operation: 'private-operation', args: 'private-argument', result_type: 'private-result', ok: true)
      expect(unknown[:action_context]).to include(operation: 'other', result_type: 'other')
      expect(unknown[:action_context][:arguments]).to eq(shape: 'string')
    end
  end

  it 'terminal reward is judge score scaled by confidence, not step hygiene' do
    expect(described_class.send(:terminal_reward, score: 1.0, confidence: 0.5)).to be_within(0.01).of(0.5)
    expect(described_class.send(:terminal_reward, score: 0.0, confidence: 1.0)).to be_within(0.01).of(-1.0)
  end
end
