# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::TurnFinalizer do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  describe 'user-path depth' do
    after { described_class.leave_user_path! while described_class.user_path? }

    it 'tracks enter/leave and only defers on the user-visible path' do
      expect(described_class.user_path?).to be false
      expect(described_class.should_defer?).to be false

      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = true
      expect(described_class.user_path?).to be true
      expect(described_class.should_defer?).to be true

      described_class.leave_user_path!
      expect(described_class.user_path?).to be false
      expect(described_class.should_defer?).to be false
    end

    it 'does not defer when defer_introspect is false' do
      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = false
      expect(described_class.should_defer?).to be false
    end
  end

  describe '.defer' do
    it 'returns immediately and runs Learning.auto_introspect off-thread' do
      seen = Queue.new
      allow(PWN::AI::Agent::Learning).to receive(:auto_introspect) do |opts|
        packed = [Thread.current.object_id, opts[:session_id], opts[:inline]]
        seen << packed
        { deferred_ran: true }
      end

      started = Thread.current.object_id
      result = described_class.defer(
        session_id: 'tf_spec',
        request: 'uname',
        final: 'Linux',
        plan: ['probe host']
      )
      expect(result[:deferred]).to be true
      expect(result[:session_id]).to eq('tf_spec')

      described_class.join_all!(timeout: 5)
      tid, sid, inline = seen.pop
      expect(sid).to eq('tf_spec')
      expect(inline).to be true
      expect(tid).not_to eq(started)
    end

    it 'detaches the live Policy episode so maybe_finish_policy is a no-op' do
      allow(PWN::AI::Agent::Policy).to receive(:detach_episode!).and_return({ session_id: 'ep1', steps: [] })
      attached = []
      allow(PWN::AI::Agent::Policy).to receive(:attach_episode!) do |opts|
        attached << opts[:episode]
        opts[:episode]
      end
      allow(PWN::AI::Agent::Policy).to receive(:current_episode).and_return(nil)
      allow(PWN::AI::Agent::Learning).to receive(:auto_introspect).and_return({})

      described_class.defer(session_id: 'tf_pol', request: 'x', final: 'y')
      described_class.join_all!(timeout: 5)
      expect(PWN::AI::Agent::Policy).to have_received(:detach_episode!)
      expect(attached.first).to be_a(Hash)
      expect(attached.first[:session_id]).to eq('ep1')
    end
  end

  describe 'Learning.auto_introspect gate' do
    it 'defers when Loop is on the user path' do
      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = true
      PWN::Env[:ai][:agent][:auto_introspect] = true
      allow(described_class).to receive(:defer).and_return({ deferred: true })

      out = PWN::AI::Agent::Learning.auto_introspect(
        session_id: 'tf_gate',
        request: 'hi',
        final: 'ack'
      )
      expect(out[:deferred]).to be true
      expect(described_class).to have_received(:defer)
    ensure
      described_class.leave_user_path! while described_class.user_path?
    end
  end

  describe 'output path literals' do
    it 'does not interpret words inside earlier filenames as new instructions' do
      expect(described_class.output_paths(request: 'Write /tmp/read.md and /tmp/answer.md')).to eq(['/tmp/read.md', '/tmp/answer.md'])
    end

    it 'preserves extensionless and quoted destination literals without inventing filenames' do
      expect(described_class.output_paths(request: 'Write the result to /tmp/answer')).to eq(['/tmp/answer'])
      expect(described_class.output_paths(request: 'Save to "~/My Reports/answer.md"')).to eq([File.expand_path('~/My Reports/answer.md')])
      expect(described_class.output_paths(request: 'Use /tmp/source.md to write the report to ./result.md')).to eq([File.expand_path('./result.md')])
    end

    it 'distinguishes source paths from output destinations and expands relative paths' do
      request = 'Read /tmp/source.md and save the summary to ~/answer.md; also write ./out/result.json.'
      expected = [File.expand_path('~/answer.md'), File.expand_path('./out/result.json')]
      expect(described_class.output_paths(request: request)).to eq(expected)
      expect(described_class.output_paths(request: 'Read /tmp/source.md and explain it.')).to eq([])
      expect(described_class.output_paths(request: 'Output: result.txt')).to eq([File.expand_path('result.txt')])
    end
  end

  it 'requires a current-turn write even when a file is newly present and readable' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'answer.md')
      File.write(path, 'preexisting answer')
      messages = [{ role: 'tool', content: { success: true, effect: 'read', result: { path: path } }.to_json }]
      result = described_class.arbitrate(request: "Write #{path}", messages: messages)
      expect(result[:complete]).to be false
      expect(result[:unmet]).to include(criterion: 'write_missing', detail: path)
    end
  end

  it 'accepts only observed successful writes with host stat and head-tail readback' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'answer.md')
      before = described_class.artifact_snapshot(paths: [path])
      File.write(path, "first\nlast\n")
      observations = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
      messages = [{ role: 'tool', artifact_observations: observations, content: '{"success":true}' }]
      result = described_class.arbitrate(request: "Read /tmp/input.md and write #{path}", messages: messages)
      expect(result[:complete]).to be true
      expect(result[:ledger][path]).to include(write: true, read: true)
      expect(observations[path][:stat][:size]).to eq(File.size(path))
      expect(observations[path][:head]).to include('first')
      expect(observations[path][:tail]).to include('last')
      stale = described_class.observe_artifacts(paths: [path], before: described_class.artifact_snapshot(paths: [path]), effect: :write, success: true)
      expect(stale).to eq({})
      expect(described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: false)).to eq({})
      forged = [{ role: 'tool', content: { success: true, effect: 'write', result: { path: path, passed: true } }.to_json }]
      expect(described_class.arbitrate(request: "write #{path}", messages: forged)[:complete]).to be false
    end
  end

  it 'finalizes write-then-readback and names unmet without readback' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'out.pdf')
      before = described_class.artifact_snapshot(paths: [path])
      File.write(path, 'pdf')
      observed = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
      msgs = [
        { role: 'tool', artifact_observations: observed, content: { success: true, result: { path: path }, effect: 'write' }.to_json },
        { role: 'tool', content: { success: true, result: { stdout: path }, effect: 'read' }.to_json }
      ]
      row = described_class.arbitrate(request: "store #{path}", messages: msgs, paths: [path])
      expect(row[:complete]).to eq(true)
      expect(row[:unmet]).to eq([])
      write_only = [{ role: 'tool', content: { success: true, result: { path: path }, effect: 'write' }.to_json }]
      nag = described_class.arbitrate(request: "store #{path}", messages: write_only, paths: [path])
      expect(nag[:complete]).to eq(false)
      expect(nag[:unmet].map { |u| u[:criterion] }).to include('readback_missing')
    end
  end
end
