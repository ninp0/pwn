---
name: pwn-sdr-decoder-lte
description: Drive PWN::SDR::Decoder::LTE from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::LTE
  source: pwn/sdr/decoder/lte.rb
---

# PWN::SDR::Decoder::LTE

LTE PSS observations (.detect) and optional native PBCH MIB (.decode). PBCH: acquired or caller-aligned SF0, 1.92Msps, FDD, normal CP, 2 ports. No SIB/traffic decoding or live-RF validation.

## When to use

Call `PWN::SDR::Decoder::LTE` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/lte.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::LTE.help
PWN::SDR::Decoder::LTE.sss_indices(opts)
```

## Public methods

- `sss_indices`
- `mseq`
- `cseq`
- `decode`
- `detect`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/lte.rb`

## Verification

`PWN::SDR::Decoder::LTE.respond_to?(:sss_indices)` after the
module is loaded. Read the source for parameter names.
