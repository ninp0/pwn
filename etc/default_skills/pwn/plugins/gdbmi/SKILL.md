---
name: pwn-plugins-gdbmi
description: Drive PWN::Plugins::GDBMI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::GDBMI
  source: pwn/plugins/gdbmi.rb
---

# PWN::Plugins::GDBMI

GDB machine-interface bridge: breakpoints, stepping, registers, memory, backtraces, checksec. Pairs with ProcessTube for interactive sessions.

## When to use

Call `PWN::Plugins::GDBMI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/gdbmi.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::GDBMI.help
PWN::Plugins::GDBMI.required_bins(opts)
```

## Public methods

- `required_bins`
- `open`
- `break`
- `step`
- `registers`
- `read_memory`
- `backtrace`
- `checksec`
- `mi`
- `authors`
- `help`

## Source

`pwn/plugins/gdbmi.rb`

## Verification

`PWN::Plugins::GDBMI.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
