---
name: pwn-sdr-decoder-gsm
description: Drive PWN::SDR::Decoder::GSM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::GSM
  source: pwn/sdr/decoder/gsm.rb
---

# PWN::SDR::Decoder::GSM

GSM SCH IQ/channel-bit decoding (.decode) and FCCH observations (.detect). Channelized GMSK IQ is synchronized and differentially demodulated before convolutional/CRC10 verification and BSIC/frame-number extraction. Multipath equalization, BCCH/CCCH and traffic decoding are unsupported.

## When to use

Call `PWN::SDR::Decoder::GSM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/gsm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::GSM.help
PWN::SDR::Decoder::GSM.viterbi_decode(opts)
```

## Public methods

- `viterbi_decode`
- `decode_sch`
- `parity`
- `decode`
- `detect`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/gsm.rb`

## Verification

`PWN::SDR::Decoder::GSM.respond_to?(:viterbi_decode)` after the
module is loaded. Read the source for parameter names.
