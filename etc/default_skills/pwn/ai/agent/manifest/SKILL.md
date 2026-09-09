---
name: pwn-ai-agent-manifest
description: Drive PWN::AI::Agent::Manifest from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Manifest
  source: pwn/ai/agent/manifest.rb
---

# PWN::AI::Agent::Manifest

Trusted, on-disk tool declarations. Never load a manifest from tool args.

## When to use

Call `PWN::AI::Agent::Manifest` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/manifest.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Manifest.help
PWN::AI::Agent::Manifest.load(opts)
```

## Public methods

- `load`
- `register`
- `check`
- `authors`
- `help`

## Source

`pwn/ai/agent/manifest.rb`

## Verification

`PWN::AI::Agent::Manifest.respond_to?(:load)` after the
module is loaded. Read the source for parameter names.
