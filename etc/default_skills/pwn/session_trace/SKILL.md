---
name: pwn-sessiontrace
description: Drive PWN::SessionTrace from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SessionTrace
  source: pwn/session_trace.rb
---

# PWN::SessionTrace

Recorded, redacted evidence, not a promise of deterministic LLM output.

## When to use

Call `PWN::SessionTrace` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/session_trace.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SessionTrace.help
PWN::SessionTrace.append(opts)
```

## Public methods

- `append`
- `replay`
- `read`
- `rerun`
- `authors`
- `help`

## Source

`pwn/session_trace.rb`

## Verification

`PWN::SessionTrace.respond_to?(:append)` after the
module is loaded. Read the source for parameter names.
