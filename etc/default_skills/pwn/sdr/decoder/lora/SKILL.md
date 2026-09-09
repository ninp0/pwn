---
name: pwn-sdr-decoder-lora
description: Drive PWN::SDR::Decoder::LoRa from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::LoRa
  source: pwn/sdr/decoder/lora.rb
---

# PWN::SDR::Decoder::LoRa

LoRa (Semtech CSS) raw PHY payload decoder and separate detector. .decode supports SF7-12, CR4/5..4/8, explicit/implicit headers, optional payload CRC, LDRO and normal/inverted IQ at sample_rate >= BW. Raw payload bytes only: no LoRaWAN decryption or clock-drift tracking. The following preamble-only description applies to .detect. I/Q resampled so fs = BW (default 125 kHz), one complex sample per chirp step. For each SF ∈ 7..12: dechirp with a reference down-chirp (DSP.cmul + PWN::FFI::FFTW.cfft), find ≥6 consecutive symbols whose FFT-argmax bin is identical (preamble), then read the two sync-word symbols and two SFD down-chirps. Emits {sf:, bw_hz:, sync_word:, preamble_len:, cfo_bins:}. This is preamble/sync metadata only, not LoRa payload decoding.

## When to use

Call `PWN::SDR::Decoder::LoRa` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/lora.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::LoRa.help
PWN::SDR::Decoder::LoRa.decode(opts)
```

## Public methods

- `decode`
- `detect`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/lora.rb`

## Verification

`PWN::SDR::Decoder::LoRa.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
