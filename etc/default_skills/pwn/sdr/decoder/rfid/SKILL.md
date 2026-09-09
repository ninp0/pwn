---
name: pwn-sdr-decoder-rfid
description: Drive PWN::SDR::Decoder::RFID from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::RFID
  source: pwn/sdr/decoder/rfid.rb
---

# PWN::SDR::Decoder::RFID

Protocol frames via .decode; energy observations only via .detect.

## When to use

Call `PWN::SDR::Decoder::RFID` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/rfid.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::RFID.help
PWN::SDR::Decoder::RFID.parse_frame(opts)
```

## Public methods

- `parse_frame`
- `decode`
- `detect`
- `parse_line`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sdr/decoder/rfid.rb`

## Verification

`PWN::SDR::Decoder::RFID.respond_to?(:parse_frame)` after the
module is loaded. Read the source for parameter names.
