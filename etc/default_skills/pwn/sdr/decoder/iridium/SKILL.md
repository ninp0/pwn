---
name: pwn-sdr-decoder-iridium
description: Drive PWN::SDR::Decoder::Iridium from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Iridium
  source: pwn/sdr/decoder/iridium.rb
---

# PWN::SDR::Decoder::Iridium

IRA protocol decoding from pre-synchronized symbol IQ, plus separate wideband energy observations (.detect). General raw-IQ acquisition and non-IRA message families are not implemented. See the independent RF vectors and BSD protocol-source notice in spec/fixtures/sdr/iridium/.

## When to use

Call `PWN::SDR::Decoder::Iridium` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/iridium.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Iridium.help
PWN::SDR::Decoder::Iridium.decode_ring_alert(opts)
```

## Public methods

- `decode_ring_alert`
- `decode`
- `detect`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/iridium.rb`

## Verification

`PWN::SDR::Decoder::Iridium.respond_to?(:decode_ring_alert)` after the
module is loaded. Read the source for parameter names.
