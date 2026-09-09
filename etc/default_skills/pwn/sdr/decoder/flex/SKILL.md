---
name: pwn-sdr-decoder-flex
description: Drive PWN::SDR::Decoder::Flex from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Flex
  source: pwn/sdr/decoder/flex.rb
---

# PWN::SDR::Decoder::Flex

Pure-Ruby FLEX™ pager decoder. FLEX is Motorola's synchronous paging protocol running at 1600 or 3200 symbols/s in 2- or 4-level FSK. GQRX's NBFM discriminator audio (48 kHz UDP tap) is fed into a per-sample PLL symbol clock, 4-level quantised, and driven through the Sync-1 → FIW → Sync-2 → 11-block state machine. All four interleaved phases (A/B/C/D) are de-interleaved into 88 × 32-bit BCH(31,21)+parity codewords, error corrected, and walked (BIW → address → vector → message words) to recover short capcode + alphanumeric / numeric / binary payloads. Plain alpha fragments have fragment checksums and whole-message signatures, with bounded per-stream ordered reassembly. Long-address phases, secure payloads, and enhanced symbolic character modes remain unsupported. Numeric/binary message-level integrity is not implemented. The symbol/framing implementation follows multimon-ng demod_flex.c. Offline specs cover Sync-1/FIW and a protected short-address alpha frame. These fixtures do not establish all-mode live-air parity. No `multimon-ng`, no `sox` — 100 % Ruby.

## When to use

Call `PWN::SDR::Decoder::Flex` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/flex.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Flex.help
PWN::SDR::Decoder::Flex.sync_check(opts)
```

## Public methods

- `sync_check`
- `popcnt`
- `even_parity`
- `bch_syn`
- `bch_fix`
- `emit_phase`
- `alpha_decode`
- `numeric_decode`
- `hex_decode`
- `detect`
- `decode`
- `authors`
- `help`
- `even_parity?`

## Source

`pwn/sdr/decoder/flex.rb`

## Verification

`PWN::SDR::Decoder::Flex.respond_to?(:sync_check)` after the
module is loaded. Read the source for parameter names.
