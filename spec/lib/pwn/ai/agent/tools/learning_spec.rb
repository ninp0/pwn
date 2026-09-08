# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools learning' do
  it 'registers the learning_note_outcome tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_note_outcome')).not_to be_nil
  end

  [true, false].each do |reported_success|
    it "stores a model claim of success=#{reported_success} as an unverified note" do
      Dir.mktmpdir do |dir|
        stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(dir, 'learning.jsonl'))
        PWN::AI::Agent::Registry.discover(force: true)
        tool = PWN::AI::Agent::Registry.lookup(name: 'learning_note_outcome')
        expect(PWN::AI::Agent::Learning).not_to receive(:promote_process_lesson)
        expect(PWN::AI::Agent::Curriculum).not_to receive(:calibrate)

        entry = tool[:handler].call(task: 'Run the regression suite', success: reported_success,
                                    details: 'Claimed test result without an independent verifier.', tags: ['tests'])

        expect(entry).to include(success: nil, status: 'unverified', verdict: :unknown,
                                 score: nil, training_score: nil, judge_source: 'self_report')
        expect(entry[:details]).to include("reported_success=#{reported_success}", 'Claimed test result without an independent verifier.')
        expect(entry[:tags]).to include('tests', 'unknown')
        saved = PWN::AI::Agent::Learning.outcomes
        expect(saved.length).to eq(1)
        expect(saved.first[:details]).to eq(entry[:details])
        expect(PWN::AI::Agent::Learning.outcomes(success: true)).to be_empty
        expect(PWN::AI::Agent::Learning.outcomes(success: false)).to be_empty
      end
    end
  end

  it 'registers the learning_reflect tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_reflect')).not_to be_nil
  end

  it 'registers the learning_distill_skill tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_distill_skill')).not_to be_nil
  end

  it 'registers the learning_stats tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_stats')).not_to be_nil
  end

  it 'exposes the learning toolset in the registry' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.toolsets).to include('learning')
  end
end
