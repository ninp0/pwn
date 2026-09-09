# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'pwn/ai/agent/engagement_memory'

RSpec.describe 'PWN::AI::Agent::EngagementMemory' do
  it 'persists edited notes, preserves the goal, and spills exact raw bytes with a bounded UTF8 excerpt' do
    Dir.mktmpdir do |root|
      opts = { original_goal: 'Original', session_id: 's1', root: root }
      memory = PWN::AI::Agent::EngagementMemory.new(**opts)
      memory.edit(text: 'Pinned host: 127.0.0.1')
      memory.save
      restored = PWN::AI::Agent::EngagementMemory.new(**opts)
      expect(restored.view).to include('Original', 'Pinned host: 127.0.0.1')
      raw = '💡' * 4096
      result = restored.spill(content: raw)
      expect(result.bytesize).to be <= 8192
      expect(result.valid_encoding?).to be true
      path = result[/Raw artifact: (.+)/, 1]
      expect(File.binread(path)).to eq(raw.b)
      expect(File.stat(path).mode & 0o777).to eq(0o600)
      expect(restored.spill(content: 'small')).to eq('small')
    end
  end
  it 'injects persisted pinned memory below budget and redacts secrets before persistence' do
    Dir.mktmpdir do |root|
      opts = { original_goal: 'Goal', session_id: 's', root: root }
      memory = PWN::AI::Agent::EngagementMemory.new(**opts)
      memory.edit(text: 'password=do-not-store')
      path = memory.save
      expect(File.read(path)).not_to include('do-not-store')
      restored = PWN::AI::Agent::EngagementMemory.new(**opts)
      messages = [{ role: 'user', content: 'Goal' }]
      result = restored.compact(messages: messages)
      expect(result.map { |m| m[:content] }.join).to include('ENGAGEMENT MEMORY')
      expect(result.last).to eq(messages.last)
    end
  end

  it 'bounds repeated summaries, preserves pinned edits and retains tool pairs' do
    Dir.mktmpdir do |root|
      memory = PWN::AI::Agent::EngagementMemory.new(original_goal: 'Goal', session_id: 's', root: root, window: 1000, keep_last: 1)
      memory.edit(text: 'Never lose this pinned note')
      messages = [{ role: 'user', content: 'Goal' }]
      30.times do
        messages += [{ role: 'assistant', content: 'evidence ' * 100 }, { role: 'user', content: 'continue' }]
        messages = memory.compact(messages: messages, usage: { input_tokens: 900 })
      end
      expect(memory.view.bytesize).to be < 3000
      expect(memory.view).to include('Never lose this pinned note', 'Goal')
      call = { role: 'assistant', tool_calls: [{ id: 'a', function: { name: 'shell' } }] }
      result = { role: 'tool', tool_call_id: 'a', content: 'out' }
      compacted = memory.compact(messages: [{ role: 'user', content: 'Goal' }, call, result], usage: { input_tokens: 900 })
      expect(compacted.last(2)).to eq([call, result])
      expect(memory.tokens(messages: [], usage: { 'usage' => { 'prompt_tokens' => 44 } })).to eq(44)
      expect(memory.tokens(messages: [{ content: 'test' }])).to be > 0
      expect(memory.compact(messages: messages, usage: { input_tokens: 750 }).last).to eq(messages.last)
    end
  end

  it 'summarizes oldest messages over 75 percent while retaining the goal and recent turns verbatim' do
    Dir.mktmpdir do |root|
      memory = PWN::AI::Agent::EngagementMemory.new(original_goal: 'Audit /tmp/input', session_id: 'test', root: root, window: 100, keep_last: 2)
      messages = [{ role: 'system', content: 'rules' }, { role: 'user', content: 'Audit /tmp/input' }, { role: 'assistant', content: 'old evidence ' * 100 }, { role: 'user', content: 'continue' }, { role: 'assistant', content: 'recent' }]
      result = memory.compact(messages: messages, usage: { input_tokens: 76 })
      expect(result.last(2)).to eq(messages.last(2))
      expect(result.first).to eq(messages.first)
      expect(result).to include(messages[1])
      expect(memory.view).to include('Audit /tmp/input', 'old evidence')
      expect(result.map { |m| m[:content] }.join).to include('ENGAGEMENT MEMORY')
    end
  end
end
