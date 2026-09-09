---
name: pwn-ai-agent-skillconsolidation
description: Drive PWN::AI::Agent::SkillConsolidation from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::SkillConsolidation
  source: pwn/ai/agent/skill_consolidation.rb
---

# PWN::AI::Agent::SkillConsolidation

Conservative, deterministic SOP hygiene. Content proposals are pure; writes require an explicit path and optimistic-concurrency digest.

## When to use

Call `PWN::AI::Agent::SkillConsolidation` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/skill_consolidation.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::SkillConsolidation.help
PWN::AI::Agent::SkillConsolidation.consolidate(opts)
```

## Public methods

- `consolidate`
- `consolidate_file`
- `authors`
- `help`

## Source

`pwn/ai/agent/skill_consolidation.rb`

## Verification

`PWN::AI::Agent::SkillConsolidation.respond_to?(:consolidate)` after the
module is loaded. Read the source for parameter names.
