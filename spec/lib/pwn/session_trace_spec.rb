# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'pwn/session_trace'

RSpec.describe 'Session trace' do
  it 'renders recorded events without executing tools and rejects traversal and symlinks' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Sessions::SESSIONS_DIR', dir)
      expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
      PWN::SessionTrace.append(session_id: 'fixture', event: 'tool_call', data: { name: 'shell', command: 'do-not-execute' })
      io = StringIO.new
      rows = PWN::SessionTrace.replay(session_id: 'fixture', io: io)
      expect(rows.size).to eq(1)
      expect(io.string).to include('tool_call', 'do-not-execute')
      expect { PWN::SessionTrace.append(session_id: '../escape', event: 'request') }.to raise_error(ArgumentError, /session id/)
      File.symlink(dir, File.join(dir, 'linked'))
      expect { PWN::SessionTrace.replay(session_id: 'linked', io: io) }.to raise_error(ArgumentError, /Symlink/)
    end
  end

  it 'reruns shell and Ruby fixture calls only inside a fresh isolated environment' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Sessions::SESSIONS_DIR', dir)
      host = File.join(dir, 'host-marker')
      File.write(host, 'host-safe')
      calls = [
        { name: 'shell', arguments: { command: "test ! -e #{host}; printf sandbox-only > marker; cat marker" } },
        { name: 'pwn_eval', arguments: { code: "File.read('marker')" } }
      ]
      calls.each { |call| PWN::SessionTrace.append(session_id: 'run', event: 'tool_call', data: call) }
      expect { PWN::SessionTrace.rerun(session_id: 'run') }.to raise_error(ArgumentError, /isolated environment/)
      result = PWN::SessionTrace.rerun(session_id: 'run', environment: :bubblewrap)
      expect(result[:results].map { |r| r['stdout'].strip }).to eq(%w[sandbox-only sandbox-only])
      expect(result[:results].map { |r| r['exit_status'] }).to eq([0, 0])
      expect(File.read(host)).to eq('host-safe')
      expect(File.exist?(File.join(dir, 'marker'))).to be(false)
      expect(PWN::SessionTrace.rerun(session_id: 'run', environment: :bubblewrap)[:run_id]).not_to eq(result[:run_id])
    end
  end

  it 'enforces an isolated rerun deadline without falling back to host tools' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Sessions::SESSIONS_DIR', dir)
      PWN::SessionTrace.append(session_id: 'deadline', event: 'tool_call', data: { name: 'shell', arguments: { command: 'sleep 0.2' } })
      expect { PWN::SessionTrace.rerun(session_id: 'deadline', environment: :bubblewrap, timeout: 0.01) }.to raise_error(RuntimeError, /deadline/)
    end
  end

  it 'fails closed on unsupported, redacted or unavailable rerun environments' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Sessions::SESSIONS_DIR', dir)
      PWN::SessionTrace.append(session_id: 'unsupported', event: 'tool_call', data: { name: 'host_tool', arguments: {} })
      expect { PWN::SessionTrace.rerun(session_id: 'unsupported', environment: :bubblewrap) }.to raise_error(ArgumentError, /Unsupported/)
      PWN::SessionTrace.append(session_id: 'secret', event: 'tool_call', data: { name: 'shell', arguments: { command: 'echo ASIAABCDEFGHIJKLMNOP' } })
      expect { PWN::SessionTrace.rerun(session_id: 'secret', environment: :bubblewrap) }.to raise_error(ArgumentError, /Redacted/)
    end
  end

  it 'writes sanitized ordered request/response/tool_call/tool_result JSONL with model params and optional seed' do
    expect(defined?(PWN::SessionTrace)).to be_truthy
    Dir.mktmpdir do |dir|
      stub_const('PWN::Sessions::SESSIONS_DIR', dir)
      %w[request response tool_call tool_result].each do |event|
        PWN::SessionTrace.append(session_id: 'fixture', event: event, data: { id: 'call-1', text: 'ASIAABCDEFGHIJKLMNOP' }, model: 'fixture-model', params: { temperature: 0 }, seed: 123)
      end
      path = File.join(dir, 'fixture', 'trace.jsonl')
      raw = File.read(path)
      rows = raw.lines.map { |line| JSON.parse(line) }
      expect(raw).not_to include('ASIAABCDEFGHIJKLMNOP')
      expect(rows.map { |r| r['event'] }).to eq(%w[request response tool_call tool_result])
      expect(rows.map { |r| r['monotonic_ns'] }).to eq(rows.map { |r| r['monotonic_ns'] }.sort.uniq)
      expect(rows.last).to include('model' => 'fixture-model', 'params' => { 'temperature' => 0 }, 'seed' => 123)
      expect(File.stat(path).mode & 0o777).to eq(0o600)
    end
  end
end
