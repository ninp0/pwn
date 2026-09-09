# Native RDS MPX backend

`RDS.decode(backend: :redsea, executable: '/path/to/redsea', freq_obj: {}, file: 'fm-mpx.flac', interactive: false)` runs **redsea's actual C++/liquid-dsp 57 kHz demodulator and group decoder**. It does not interpret GQRX metadata as decoded RF. Default `backend: :gqrx` preserves the historical metadata API; use `:redsea` explicitly for native decoding.

Build optional redsea 1.3.1 pinned to `7555c9f6259d50718697ee8c9f218ea012c6892c`:

```
ruby ext/pwn_rds/build.rb
REDSEA=/opt/pwn/ext/pwn_rds/build/redsea bundle exec ruby -Ilib ext/pwn_rds/verify.rb
REDSEA=/opt/pwn/ext/pwn_rds/build/redsea bundle exec ruby -Ilib ext/pwn_rds/stream_verify.rb
```

Requires git, Meson/Ninja, C++17, liquid-dsp, libsndfile, nlohmann-json headers. Meson is an external build tool, not a first-party Python implementation or runtime shim. No backend is installed or built automatically during decode or ordinary RSpec. No RF device is selected. Sources are exclusively a supplied containerized FM-MPX file (FLAC/WAV) or raw mono s16le MPX IO via `source:` with `sample_rate:` (default 192000; accepts 128000..384000). This is **not speaker audio** and not a complex-IQ frontend. Source IO ownership transfers to the runner and is closed on exit.

The subprocess uses `--no-fec --show-raw`. Only groups with all four intact syndrome-checked blocks are emitted. Partial groups are dropped rather than relabeled verified. Decoded fields are retained in `backend_fields`; transport output is bounded, backend errors propagate, and stop/deadline terminates the process and feeder. No RDS2 guarantee is made.

Verification used upstream's real 0.7-second MPX fixture (see fixture README). The file path emitted a complete 14A group, PI 6201, PTY Serious classical, other-network PI 6204. Raw s16le pipe replay emitted complete 0A before pipe EOF and proved cancellation with a blocked source. The short file replay took 0.0691 s including process startup on the tested host. This is a short offline measurement, **not a sustained realtime or RF reception guarantee**. File and raw PCM paths acquire differently on this short/noisy recording (different intact groups); both preserve expected PI/PTY.
