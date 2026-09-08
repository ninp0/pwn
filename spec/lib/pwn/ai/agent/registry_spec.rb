# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Registry do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Registry
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Registry
    expect(help_response).to respond_to :help
  end

  it 'CORE_TOOLS is recall-then-act including skills_recall before pwn_eval' do
    expect(described_class.const_defined?(:ACT_PREFERENCE)).to eq false
    expect(described_class::CORE_TOOLS).to eq(
      %w[memory_recall session_recall skills_recall pwn_eval shell mistakes_record mistakes_resolve learning_note_outcome memory_remember skills_update]
    )
    expect(described_class::DEFAULT_PREFERENCE).to eq(described_class::CORE_TOOLS)
    expect(described_class::DEFAULT_PREFERENCE).not_to include('sessions_view')
    expect(described_class::CORE_TOOLS.index('memory_recall')).to be < described_class::CORE_TOOLS.index('session_recall')
    expect(described_class::CORE_TOOLS.index('session_recall')).to be < described_class::CORE_TOOLS.index('skills_recall')
    expect(described_class::CORE_TOOLS.index('skills_recall')).to be < described_class::CORE_TOOLS.index('pwn_eval')
    expect(described_class::CORE_TOOLS.index('pwn_eval')).to be < described_class::CORE_TOOLS.index('shell')
  end

  it 'preference_order is DEFAULT_PREFERENCE — kind/intent do not change it' do
    expect(described_class.preference_order).to eq(described_class::DEFAULT_PREFERENCE)
    expect(described_class.preference_order.first(5)).to eq(%w[memory_recall session_recall skills_recall pwn_eval shell])
    expect(described_class.preference_order(kind: :question)).to eq(described_class::DEFAULT_PREFERENCE)
    expect(described_class.preference_order(intent: :recall)).to eq(described_class::DEFAULT_PREFERENCE)
  end

  it 'preference_order still honors explicit empty list and Env override' do
    expect(described_class.preference_order(order: [])).to eq([])
    expect(described_class.preference_order(preference: %w[shell])).to eq(%w[shell])
  end

  it 'definitions(core_only: true) ships CORE_TOOLS, not the full ~85 schema set' do
    described_class.discover
    names = described_class.definitions(core_only: true).map { |t| t.dig(:function, :name) }
    expect(names).to eq(described_class::CORE_TOOLS)
    expect(names).not_to include('sessions_view')
    expect(names.length).to eq(described_class::CORE_TOOLS.length)
  end

  it 'applies observed shell and Ruby prerequisites to the existing core tools' do
    described_class.discover
    context = { environment: :local, capabilities: { shell: false, ruby: false } }
    names = described_class.definitions(core_only: true, trusted_context: context).map { |tool| tool.dig(:function, :name) }
    expect(names).not_to include('shell', 'pwn_eval')
    expect(names).to include('memory_recall')
  end

  describe 'contextual policy routing' do
    let(:policy) { PWN::AI::Agent::Policy }
    let(:entries) do
      %w[alpha beta].map do |name|
        described_class::Entry.new(name: name, toolset: 'test', schema: { description: 'inspect' })
      end
    end

    around do |example|
      Dir.mktmpdir do |tmp|
        @policy_dir = tmp
        example.run
      ensure
        policy.attach_episode!(episode: nil)
      end
    end

    before do
      stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(@policy_dir, 'policy.json'))
      stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(@policy_dir, 'policy_traj.jsonl'))
      allow(policy).to receive(:enabled?).and_return(true)
      allow(policy).to receive(:cold?).and_return(true)
      allow(policy).to receive(:warm?).and_return(false)
      allow(PWN::AI::Agent::Metrics).to receive_messages(advantage: 0.0, ucb: 0.0, prm_advantage: 0.0, prm_n: 0, proxy_trust: 1.0)
    end

    it 'excludes observed missing prerequisites from rank and definitions despite learned history or core pinning' do
      original = described_class.instance_variable_get(:@entries)
      described_class.instance_variable_set(:@entries, {})
      allow(described_class).to receive(:eager_load!)
      described_class.register(name: 'shell', toolset: 'test', schema: { name: 'shell', description: 'inspect' }, handler: ->(_) {}, prerequisites: [:shell])
      described_class.register(name: 'beta', toolset: 'test', schema: { name: 'beta', description: 'inspect' }, handler: ->(_) {}, prerequisites: [:network])
      context = { environment: :local, capabilities: { shell: false }, missing_prerequisites: [:network] }
      allow(PWN::AI::Agent::Metrics).to receive_messages(advantage: 100.0, ucb: 100.0)

      expect(described_class.rank(query: 'inspect', trusted_context: context)).to eq([])
      expect(described_class.rank(query: '', trusted_context: context)).to eq([])
      expect(described_class.definitions(core_only: true, trusted_context: context)).to eq([])
      expect(described_class.definitions(relevance: 'inspect', trusted_context: context)).to eq([])
      policy.begin_episode(request: 'inspect', trusted_context: context)
      expect(described_class.rank(query: 'inspect')).to eq([])
      expect(policy.recommend(actions: %w[shell beta], epsilon: 1.0)[:action]).to be_nil
    ensure
      described_class.instance_variable_set(:@entries, original)
    end

    it 'preserves live decision state when trusted observations accompany a schema refresh' do
      context = { environment: :local, verification_state: :failed, failure_category: :timeout }
      policy.begin_episode(request: 'inspect', engine: :grok, kind: :question, trusted_context: context)
      state = policy.current_state
      5.times { policy.update_q!(transition: { state: state, action: 'beta', reward: 1.0, terminal: true }) }
      expect(described_class.rank(query: 'inspect', entries: entries, preference: [], trusted_context: context).map(&:name)).to eq(%w[beta alpha])
    end

    it 'ignores environment-blind success metrics when trusted observations scope policy history' do
      context = { environment: :local }
      state = policy.state(request: 'inspect', trusted_context: context)
      5.times { policy.update_q!(transition: { state: state, action: 'alpha', reward: 1.0, terminal: true }) }
      allow(PWN::AI::Agent::Metrics).to receive(:advantage).with(name: 'beta').and_return(100.0)
      expect(described_class.rank(query: 'inspect', entries: entries, preference: [], trusted_context: context).map(&:name)).to eq(%w[alpha beta])
    end

    it 'does not transfer tool success across incompatible observed environments' do
      local = { environment: :local, capabilities: { shell: true } }
      remote = { environment: :remote, capabilities: { shell: true } }
      local_state = policy.state(request: 'inspect', trusted_context: local)
      remote_state = policy.state(request: 'inspect', trusted_context: remote)
      5.times do
        policy.update_q!(transition: { state: local_state, action: 'beta', reward: 1.0, terminal: true })
        policy.update_q!(transition: { state: remote_state, action: 'alpha', reward: 1.0, terminal: true })
      end

      expect(described_class.rank(query: 'inspect', entries: entries, preference: [], trusted_context: local).map(&:name)).to eq(%w[beta alpha])
      expect(described_class.rank(query: 'inspect', entries: entries, preference: [], trusted_context: remote).map(&:name)).to eq(%w[alpha beta])
    end

    {
      operations: [{ operation: 'read' }, { operation: 'search' }],
      argument_features: [{ args: { path: '/not-stored' } }, { args: { query: 'not-stored' } }],
      result_types: [{ result_type: :enoent, ok: false }, { result_type: :timeout, ok: false }],
      observed_failures: [{ trusted_context: { failure_category: :timeout } }, { trusted_context: { failure_category: :auth_required } }],
      observed_verification: [{ trusted_context: { verification_state: :passed } }, { trusted_context: { verification_state: :failed } }],
      observed_capabilities: [{ trusted_context: { capabilities: { network: true } } }, { trusted_context: { capabilities: { network: false } } }]
    }.each do |feature, contexts|
      it "learns opposite next-tool rankings from sanitized previous #{feature}" do
        3.times do
          contexts.each_with_index do |context, index|
            %w[alpha beta].each do |action|
              policy.begin_episode(request: 'inspect')
              policy.observe_step({ action: 'file', operation: 'read', ok: true }.merge(context))
              step = policy.observe_step(action: action, ok: true)
              score = index.zero? == (action == 'alpha') ? 1.0 : 0.0
              policy.finish(score: score, attribution: { source: :independent_verifier, verified_action_ids: [step[:action_id]] })
            end
          end
        end

        contexts.each_with_index do |context, index|
          policy.begin_episode(request: 'inspect')
          observation = { action: 'file', operation: 'read', ok: true }.merge(context)
          observation[:args] = context[:args].transform_values { 'different-value' } if context[:args]
          policy.observe_step(observation)
          ranked = described_class.rank(query: 'inspect', entries: entries, preference: []).map(&:name)
          expected = index.zero? ? %w[alpha beta] : %w[beta alpha]
          expect(ranked).to eq(expected)
          expect(policy.recommend(actions: %w[alpha beta], epsilon: 0.0)[:action]).to eq(expected.first)
        end

        lexical = described_class::Entry.new(name: 'lexical', toolset: 'test', schema: { description: 'inspect priority' })
        expect(described_class.rank(query: 'inspect priority', entries: entries + [lexical], preference: []).first.name).to eq('lexical')
      end
    end
  end

  it 'pins pentest and RE tools when the request is offensive-security work' do
    described_class.discover(force: true)
    defs = described_class.definitions(
      relevance: 'penetration testing and reverse engineering fitness'
    )
    names = defs.map { |d| d.dig(:function, :name) || d.dig('function', 'name') }
    %w[binary_triage job_run exploitdev finding_record fuzz_campaign pty_open].each do |n|
      expect(names).to include(n)
    end
  end
end
