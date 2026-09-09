---
name: pwn-sdr-decoder-p25
description: Drive PWN::SDR::Decoder::P25 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::P25
  source: pwn/sdr/decoder/p25.rb
---

# PWN::SDR::Decoder::P25

APCO Project 25 Phase-1 (C4FM) true-air decoder. I/Q → PWN::FFI::Liquid.freq_demod (or DSP.fm_demod_iq) → resample to 48 kHz → 4-level slice at 4800 sym/s → dibits → hunt the 24-symbol Frame Sync (0x5575F5FF77FF) → recover the 64-bit NID (12-bit NAC + 4-bit DUID + BCH(63,16,23) parity). Emits {nac:, duid:, duid_name:} from legacy acquisition (DemodIQ). The public .decode uses PacketIQ: BCH-checked one-to-three-block TSDU, trellis/CRC and group grants. Unconfirmed rate-1/2 packet data also supported; no voice or Phase 2.

## When to use

Call `PWN::SDR::Decoder::P25` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/p25.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::P25.help
PWN::SDR::Decoder::P25.parse(opts)
```

## Public methods

- `parse`
- `decode`
- `detect`
- `parse_line`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sdr/decoder/p25.rb`

## Verification

`PWN::SDR::Decoder::P25.respond_to?(:parse)` after the
module is loaded. Read the source for parameter names.
