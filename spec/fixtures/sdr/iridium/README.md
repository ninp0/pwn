# Iridium IRA independent receive vectors

## Scope (not a wideband receiver)

The three fixtures contain **over-air, already synchronized complex symbols**,
not synthesized modulation and not raw wideband SDR samples. The dataset's
modified gr-iridium front end has already performed channel selection, carrier
and timing recovery and symbol-rate decimation. `Iridium.decode` therefore only
accepts `mode: :ira_symbols_iq`, exactly 25,000 complex samples/s, and an explicit
file/readable IO. Default `:iq` still raises. No native gr-iridium bridge, RF
acquisition, LCW, messaging, broadcast control, ITL, voice, RS6/RS8 or user-data
reassembly is implemented. This is **partial protocol coverage**, not completion
of the requested general IQ decoder.

Supported: exact downlink access word, differential QPSK/Gray decision,
three-way IRA header and two-way page deinterleaving, extended BCH(32,21)
(polynomial 1207) bounded-distance correction of up to two bits per word,
including parity, satellite/beam IDs, signed XYZ (4 km units), geocentric
latitude/longitude, radius, interval, broadcast slot, downlink subband, and
42-bit paging records. An END page or twelve valid pages is required. Padding
and samples following a complete message are not payload. Unsupported or
uncorrectable bursts produce no decoded callback; direct `decode_ring_alert`
raises. Higher-weight errors can alias valid codewords; FEC is not authentication.
Nonempty paging parsing is implemented but has not been verified against an
independent nonempty-page capture. All three selected captures have zero pages.

## Dataset provenance and license

Oligeri, Gabriele; Sciancalepore, Savio (2022), *Physical layer data acquisition
of IRIDIUM satellites broadcast messages*, Mendeley Data, V2.
DOI: https://doi.org/10.17632/xcxspv8c2r.2
Dataset: https://data.mendeley.com/datasets/xcxspv8c2r/2
Article: https://pmc.ncbi.nlm.nih.gov/articles/PMC9868370/
License: **CC BY 4.0**, https://creativecommons.org/licenses/by/4.0/ .
These excerpts are redistributed with attribution under that license. Changes
are extraction of three rows and numeric conversion/scaling as described below.
No endorsement by the authors is implied.

Archive `dataset.zip`, file ID `7d39bf61-d67a-4327-b76d-ec7a61e6cd01`:
- Published archive size: 4674824309 bytes.
- Publisher-provided SHA256: `60b1001686067eb351d1e369a05360449e707062012432091460b09632b369e5`.
- URL: https://data.mendeley.com/public-files/datasets/xcxspv8c2r/files/7d39bf61-d67a-4327-b76d-ec7a61e6cd01/file_downloaded
- Member: `1109-0910_20_parsed.txt`, one-indexed rows **5, 19, 43**.
- Only HTTP ranges 0–1048575 and the last 65536 bytes were fetched. 7z can
  decompress the prefix of this Deflate64 ZIP. It correctly reports unexpected
  EOF/data error for the incomplete archive. The selected rows precede that
  boundary and are complete; **the full archive checksum was not verified**.
- `source-rows.tsv` preserves those three complete source rows. Individual row
  and derived artifact hashes are in `vectors.json` and checked by tests.

Each row's final tab-separated column is a sequence of `(real+imagj)` complex
numbers. Parse each component strictly, including signed scientific exponents;
never use a greedy `[+-0-9.e]+` expression followed by permissive `to_f`.
`*.cf32` preserves those values as interleaved little-endian IEEE float32.
`*.cs16` scales the original decimal values by the per-row `cs16_scale` recorded
in the manifest, rounds to the nearest integer, then packs signed little-endian
16-bit I/Q. This positive gain/quantization permits use of Base's existing cs16
reader; it does not synthesize symbols or alter the expected message. No
resampling, timing correction, invented carrier, or noise was added.

Dataset `dataset_beam: 0` distinguishes satellite-position records; it is **not**
the beam bits on the air. The actual BCH-decoded beam values in rows 19 and 43
are 41 and 20. Keep both metadata fields instead of silently replacing the
publisher's values. Latitude/longitude/satellite expectations come directly
from the published row; actual beam and XYZ expectations are cross-checked
with the independent decoder below.

## Independent protocol reference

https://github.com/muccc/iridium-toolkit at commit
`88881243cf5f60f1e9625ab1bee7853a791c4285`, `bitsparser.py`:
- Lines 20–33: access word and BCH polynomials.
- Lines 1189–1273: FEC and parity.
- Lines 1553–1663: IRA fields and page termination.
- Lines 1985–1996: dibit deinterleavers.

Copyright Sec & schneider, BSD-2-Clause per upstream README. See
`TOOLKIT-LICENSE.txt` for retained notice. The Ruby implementation uses these
published layouts; no upstream Python code runs in production or specs.

For the research-only cross-check, quantize each complex phase into quadrant
`round(atan2(Q,I)/(pi/2)-0.5) mod 4`, differential-decode successive quadrants
(starting reference zero), map differences through `00,01,11,10`, and prepend
RWA metadata (RWA is canonical dibit order; RAW reverses each dibit).
Then run the external reference:

```
iridium-parser.py -o line /tmp/iridium-verified.bits
```

The exact observed output is retained as each vector's `reference`. All three
were IRA, zero corrected words (`-e000`), and `{OK}`; row 19 additionally has
`FILL=11`. This cross-check was rerun after strict scientific-number parsing.
The bundled fixture tests need only Ruby, not this external reference tool.

## Local replay

```
bundle exec rspec spec/lib/pwn/sdr/decoder/iridium_spec.rb
```

```
PWN::SDR::Decoder::Iridium.decode(
  mode: :ira_symbols_iq, source: :file,
  file: 'spec/fixtures/sdr/iridium/ira-row-5.cs16',
  iq_format: :cs16, sample_rate: 25_000,
  interactive: false, log_file: false
)
```

This produces satellite 109, beam 23, XYZ `[1110, 1000, 555]`, latitude
20.3790556935 degrees and longitude 42.0157178564 degrees, after actual
framing/FEC checks. Streaming tests prove a decoded callback before pipe EOF
with 7-byte chunks. They do not prove raw-radio acquisition or realtime
wideband operation.
