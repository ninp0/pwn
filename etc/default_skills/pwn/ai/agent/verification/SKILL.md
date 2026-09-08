---
name: pwn-ai-agent-verification
description: Drive PWN::AI::Agent::Verification from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Verification
  source: pwn/ai/agent/verification.rb
---

# PWN::AI::Agent::Verification

Explicit host-owned acceptance checks, not a model-facing tool.

## When to use

Call `PWN::AI::Agent::Verification` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/verification.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Verification.help
PWN::AI::Agent::Verification.run(opts)
```

## Public methods

- `run`
- `snapshot`
- `authors`
- `help`

## Source

`pwn/ai/agent/verification.rb`

## Verification

`PWN::AI::Agent::Verification.respond_to?(:run)` after the
module is loaded. Read the source for parameter names.
