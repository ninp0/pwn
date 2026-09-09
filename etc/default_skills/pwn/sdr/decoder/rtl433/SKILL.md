---
name: pwn-sdr-decoder-rtl433
description: Drive PWN::SDR::Decoder::RTL433 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::RTL433
  source: pwn/sdr/decoder/rtl433.rb
---

# PWN::SDR::Decoder::RTL433

Protocol frames via .decode; energy observations only via .detect.

## When to use

Call `PWN::SDR::Decoder::RTL433` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/rtl433.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::RTL433.help
PWN::SDR::Decoder::RTL433.parse_frame(opts)
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

`pwn/sdr/decoder/rtl433.rb`

## Verification

`PWN::SDR::Decoder::RTL433.respond_to?(:parse_frame)` after the
module is loaded. Read the source for parameter names.
