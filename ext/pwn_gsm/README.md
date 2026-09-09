# Optional GSM SCH search accelerator

Build explicitly from the repository root (C99 compiler, Ruby and bundled FFI):

```sh
ruby ext/pwn_dsp/build.rb
ruby ext/pwn_gsm/build.rb
PWN_GSM_REQUIRE_NATIVE=1 bundle exec rspec spec/lib/pwn/sdr/decoder/gsm_spec.rb
bundle exec ruby -Ilib ext/pwn_gsm/benchmark.rb
```

No compilation, downloads or Python execution occurs during decoder startup or
tests. `GSM.decode(native: false, ...)` forces Ruby SCH search; missing/unloadable
`libpwn_gsm` automatically falls back to Ruby. `SCHDemodIQ#backend` reports the
selected scanner. Shared DSP acceleration is controlled separately by
`PWN::SDR::Decoder::DSP.native` and has its own Ruby fallback.

The C99 helper only searches discriminator samples for plausible SCH training.
It batches the sample-by-sample, 63-symbol correlation loop without allocating
Ruby arrays for every sample. Conservative boundary tolerances retain ambiguous
candidates for Ruby. Original Ruby candidate decoding, tail checks, Viterbi,
CRC10, fields, callbacks and streaming carry remain authoritative. No additional
protocols or multipath equalization are implemented.

## Measured end-to-end replay

`benchmark-results.json` records an actual run on this host (Ruby 4.0.6), using
the shared native DSP backend, default 16384-byte reads, 1,000,000 complex input
samples and 20 verified SCH callbacks. The benchmark includes file reading,
format conversion, FM, complete SCH search, Viterbi/CRC, JSONL formatting/output
to StringIO and synchronous callbacks. It places the independently GNU Radio
modulated fixture once per 50,000 samples with deterministic low-level noise
between bursts (approximately one burst per ten TDMA frames).

* Ruby SCH scanner: 33,040 samples/s, 30.266 seconds.
* Native SCH scanner: 3,131,377 samples/s, 0.319 seconds.
* Required input rate: 1,083,333 samples/s; this offline workload exceeds it.

This is not a live-radio or disk/network throughput guarantee, nor a claim
about expensive user callbacks, pathological false-candidate density, logging
filesystem latency, multipath or arbitrary channel conditions. Pure Ruby is
functional but does not meet realtime on this host. The native scanner and
shared native DSP were both loaded for the measured fast path.

## Optional independent fixture regeneration

`fixtures/generate.py` is a retained **third-party GNU Radio Python-binding
integration**, not a runtime/test helper. GNU Radio 3.10.12.0 supplies independent
GMSK pulse shaping and modulation. It is never invoked by PWN or its test suite.
From the repository root:

```sh
/usr/bin/python3 ext/pwn_gsm/fixtures/generate.py
```

The output directory is explicitly resolved to `spec/fixtures/sdr/gsm/`, not the
script directory or current working directory. The fixture README there pins
the independent libosmocore SCH codeword and GNU Radio source provenance; the
JSON manifest records SHA-256 hashes. These are synthesized regression stimuli,
not RF captures. Moving the generator preserves that provenance while keeping
all first-party runtime/tests Python-independent.
