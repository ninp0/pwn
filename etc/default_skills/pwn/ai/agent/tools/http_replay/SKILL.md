---
name: pwn-ai-agent-tools-httpreplay
description: Drive PWN::Ai::Agent::Tools::HttpReplay from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::HttpReplay
  source: pwn/ai/agent/tools/http_replay.rb
---

# PWN::Ai::Agent::Tools::HttpReplay

Public API for PWN::Ai::Agent::Tools::HttpReplay.

## When to use

Call `PWN::Ai::Agent::Tools::HttpReplay` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/http_replay.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::HttpReplay.help
PWN::Ai::Agent::Tools::HttpReplay.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## Source

`pwn/ai/agent/tools/http_replay.rb`

## Verification

`PWN::Ai::Agent::Tools::HttpReplay.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
