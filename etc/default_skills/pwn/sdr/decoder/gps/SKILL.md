---
name: pwn-sdr-decoder-gps
description: Drive PWN::SDR::Decoder::GPS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::GPS
  source: pwn/sdr/decoder/gps.rb
---

# PWN::SDR::Decoder::GPS

GPS L1 C/A acquisition (.detect) and optional native IQ/LNAV decoding. LNAV framing/parity does not imply ephemeris assembly or PVT. Parallel-code-phase search: 1 ms of I/Q resampled to 2.046 Msps (2 samp/chip), FFT-correlated (via PWN::FFI::FFTW.cfft) against each PRN 1..32 Gold code across ±5 kHz Doppler in 500 Hz steps. Emits {prn:, doppler_hz:, code_phase_chips:, cn0_db_hz:} for every satellite whose peak/next-peak ratio clears threshold — the same cold-start acquisition every GNSS receiver runs, no gnss-sdr binary.

## When to use

Call `PWN::SDR::Decoder::GPS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/gps.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::GPS.help
PWN::SDR::Decoder::GPS.parse_packet(opts)
```

## Public methods

- `parse_packet`
- `decode`
- `decode_subframe`
- `decode_monitor`
- `detect`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/gps.rb`

## Verification

`PWN::SDR::Decoder::GPS.respond_to?(:parse_packet)` after the
module is loaded. Read the source for parameter names.
