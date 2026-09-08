---
name: pwn-ai-agent-policyevaluation
description: Drive PWN::AI::Agent::PolicyEvaluation from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::PolicyEvaluation
  source: pwn/ai/agent/policy_evaluation.rb
---

# PWN::AI::Agent::PolicyEvaluation

Opt-in, fixed local held-out evaluation. Never loaded by the online loop.

## When to use

Call `PWN::AI::Agent::PolicyEvaluation` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/policy_evaluation.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::PolicyEvaluation.help
PWN::AI::Agent::PolicyEvaluation.evaluate(opts)
```

## Public methods

- `evaluate`
- `authors`
- `promote`
- `rollback`
- `help`

## Source

`pwn/ai/agent/policy_evaluation.rb`

## Verification

`PWN::AI::Agent::PolicyEvaluation.respond_to?(:evaluate)` after the
module is loaded. Read the source for parameter names.
