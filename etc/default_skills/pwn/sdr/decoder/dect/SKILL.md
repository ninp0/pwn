---
name: pwn-sdr-decoder-dect
description: Drive PWN::SDR::Decoder::DECT from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::DECT
  source: pwn/sdr/decoder/dect.rb
---

# PWN::SDR::Decoder::DECT

DECT P00 control and P32 B-field descrambling, ETSI EN 300 175-3 sections 6.2/7.1. https://www.etsi.org/deliver/etsi_EN/300100_300199/30017503/02.08.01_60/en_30017503v020801p.pdf 1.152 Mbit/s GFSK, 24-slot / 10 ms TDMA. Continuous Ruby FM/NRZ symbol recovery → hunt 32-bit S-field (16-bit preamble + 16-bit sync 0xE98A FP / 0x1675 PP) → A-field (64 bits: 8-bit header + 40-bit tail + 16-bit R-CRC) → RFPI extraction on Nt/Qt tails. Emits {rfpi:, role:, slot_est:, crc_ok:}.

## When to use

Call `PWN::SDR::Decoder::DECT` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/dect.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::DECT.help
PWN::SDR::Decoder::DECT.parse_b_field(opts)
```

## Public methods

- `parse_b_field`
- `decode`
- `detect`
- `parse_line`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sdr/decoder/dect.rb`

## Verification

`PWN::SDR::Decoder::DECT.respond_to?(:parse_b_field)` after the
module is loaded. Read the source for parameter names.
