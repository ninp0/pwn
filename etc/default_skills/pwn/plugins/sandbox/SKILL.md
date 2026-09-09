---
name: pwn-plugins-sandbox
description: Drive PWN::Plugins::Sandbox from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Sandbox
  source: pwn/plugins/sandbox.rb
---

# PWN::Plugins::Sandbox

Disposable no-network execution; never falls back to host execution.

## When to use

Call `PWN::Plugins::Sandbox` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/sandbox.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Sandbox.help
PWN::Plugins::Sandbox.run(opts)
```

## Public methods

- `run`
- `fuzz`
- `snapshot`
- `rollback`
- `authors`
- `help`

## Source

`pwn/plugins/sandbox.rb`

## Verification

`PWN::Plugins::Sandbox.respond_to?(:run)` after the
module is loaded. Read the source for parameter names.
