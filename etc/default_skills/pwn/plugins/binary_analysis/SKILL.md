---
name: pwn-plugins-binaryanalysis
description: Drive PWN::Plugins::BinaryAnalysis from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BinaryAnalysis
  source: pwn/plugins/binary_analysis.rb
---

# PWN::Plugins::BinaryAnalysis

Bounded, argv-only read-only backend shared by normalized analysis adapters.

## When to use

Call `PWN::Plugins::BinaryAnalysis` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/binary_analysis.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BinaryAnalysis.help
PWN::Plugins::BinaryAnalysis.available(opts)
```

## Public methods

- `available`
- `run`
- `analyze`
- `authors`
- `help`
- `available?`

## Source

`pwn/plugins/binary_analysis.rb`

## Verification

`PWN::Plugins::BinaryAnalysis.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
