---
name: pwn-plugins-ghidraheadless
description: Drive PWN::Plugins::GhidraHeadless from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::GhidraHeadless
  source: pwn/plugins/ghidra_headless.rb
---

# PWN::Plugins::GhidraHeadless

analyzeHeadless wrapper that exports decompiled C plus the symbol table as JSON, cached by binary SHA-256.

## When to use

Call `PWN::Plugins::GhidraHeadless` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ghidra_headless.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::GhidraHeadless.help
PWN::Plugins::GhidraHeadless.required_bins(opts)
```

## Public methods

- `required_bins`
- `analyze`
- `decompile`
- `authors`
- `help`

## Source

`pwn/plugins/ghidra_headless.rb`

## Verification

`PWN::Plugins::GhidraHeadless.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
