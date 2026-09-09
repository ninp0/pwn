---
name: pwn-ai-agent
description: Drive PWN::AI::Agent from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent
  source: pwn/ai/agent/profiles.rb
---

# PWN::AI::Agent

Public API for PWN::AI::Agent.

## When to use

Call `PWN::AI::Agent` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/profiles.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent.help
PWN::AI::Agent.help(opts)
```

## Public methods

- `authors`
- `help`

## Source

`pwn/ai/agent/profiles.rb`

## Verification

`PWN::AI::Agent.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
