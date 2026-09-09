---
name: pwn-sdr-decoder-wifi
description: Drive PWN::SDR::Decoder::WiFi from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::WiFi
  source: pwn/sdr/decoder/wifi.rb
---

# PWN::SDR::Decoder::WiFi

Protocol frames via .decode; energy observations only via .detect.

## When to use

Call `PWN::SDR::Decoder::WiFi` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/wifi.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::WiFi.help
PWN::SDR::Decoder::WiFi.parse_frame(opts)
```

## Public methods

- `parse_frame`
- `decode`
- `detect`
- `plcp_crc`
- `parse_line`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sdr/decoder/wifi.rb`

## Verification

`PWN::SDR::Decoder::WiFi.respond_to?(:parse_frame)` after the
module is loaded. Read the source for parameter names.
