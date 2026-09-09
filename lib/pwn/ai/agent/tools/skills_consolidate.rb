# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/skill_consolidation'

PWN::AI::Agent::Registry.register(
  name: 'skills_consolidate', toolset: 'skills',
  schema: {
    name: 'skills_consolidate',
    description: 'Preview on-demand skill hygiene: deduplicate RL notes, quarantine conflicting/stale feedback, version stamp. Does not infer successful verification from failure counts. Apply requires dry_run:false, confirm:true and preview source_sha256.',
    parameters: { type: 'object', properties: {
      name: { type: 'string' }, dry_run: { type: 'boolean', default: true }, confirm: { type: 'boolean' }, expected_sha256: { type: 'string' }
    }, required: %w[name] }
  },
  handler: lambda { |args|
    key = args.fetch(:name).to_s
    meta = PWN::Skills[key.to_sym] || PWN::Skills[key] if defined?(PWN::Skills)
    raise ArgumentError, 'unknown installed skill' unless meta && meta[:path]

    # Successful sessions must be recorded explicitly by verification, not by
    # mistakes_record (which records failed sessions). No model-supplied proof.
    evidence = if defined?(PWN::AI::Agent::Mistakes)
                 PWN::AI::Agent::Mistakes.load.values.to_h do |row|
                   [row[:signature].to_s, { resolved: row[:resolved], regressed: row[:regressed],
                                            verified_sessions: row[:verified_sessions], last_verified: row[:last_verified] }]
                 end
               else
                 {}
               end
    result = PWN::AI::Agent::SkillConsolidation.consolidate_file(args.merge(path: meta[:path], evidence: evidence))
    PWN::Config.load_skills(pwn_skills_path: PWN::Config.pwn_skills_path) if result[:written] && defined?(PWN::Config)
    result.merge(name: key)
  }
)
