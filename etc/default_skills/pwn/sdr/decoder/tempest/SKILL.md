---
name: pwn-sdr-decoder-tempest
description: Drive PWN::SDR::Decoder::Tempest from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Tempest
  source: pwn/sdr/decoder/tempest.rb
---

# PWN::SDR::Decoder::Tempest

Pure-Ruby TEMPEST / Van Eck raster decoder. Recovers a greyscale candidate raster from AM on a display pixel-clock harmonic captured as I/Q (RTL-SDR, HackRF, Pluto, Soapy, or a .cu8/.cs16 file). Magnitude envelope is resampled to one sample per pixel, packed into H×V lines using a VESA timing, and written as Netpbm P5 PGM. No TempestSDR / GNU Radio dependency. Assumes known timing and frame origin; no automatic sync acquisition, drift tracking, or proof that the raster is a monitor image. Sample-and-hold interpolation cannot recover pixel detail absent from the capture bandwidth.

## When to use

Call `PWN::SDR::Decoder::Tempest` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/tempest.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Tempest.help
PWN::SDR::Decoder::Tempest.modes(opts)
```

## Public methods

- `modes`
- `resolve_timing`
- `reconstruct`
- `detect`
- `decode`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/tempest.rb`

## Verification

`PWN::SDR::Decoder::Tempest.respond_to?(:modes)` after the
module is loaded. Read the source for parameter names.
