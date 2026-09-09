---
name: pwn-ffi-dspnative
description: Drive PWN::FFI::DSPNative from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::DSPNative
  source: pwn/ffi/dsp_native.rb
---

# PWN::FFI::DSPNative

Optional bundled double-precision packed IQ kernels. Explicit build only; no runtime compiler, search-path loading, or shared temporary cache.

## When to use

Call `PWN::FFI::DSPNative` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/dsp_native.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::DSPNative.help
PWN::FFI::DSPNative.available(opts)
```

## Public methods

- `available`
- `process_iq`
- `cfft_mag`
- `authors`
- `help`
- `available?`
- `load_error`

## Source

`pwn/ffi/dsp_native.rb`

## Verification

`PWN::FFI::DSPNative.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
