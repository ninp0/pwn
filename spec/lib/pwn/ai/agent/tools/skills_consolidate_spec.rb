# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'skills_consolidate tool' do
  it 'previews an installed fixture without writing or inventing verification evidence' do
    PWN::AI::Agent::Registry.discover
    tool = PWN::AI::Agent::Registry.lookup(name: 'skills_consolidate')
    expect(tool).not_to be_nil
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'SKILL.md')
      original = "# SOP\n\n## RL feedback\n- [a] Safe fixture.\n- [b] Safe fixture.\n"
      File.write(path, original)
      stub_const('PWN::Skills', { fixture: { path: path } })
      result = tool[:handler].call(name: 'fixture')
      expect(result[:deduplicated]).to eq(1)
      expect(result[:promoted]).to eq([])
      expect(File.read(path)).to eq(original)
    end
  end
end
