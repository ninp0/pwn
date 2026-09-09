# Optional packed DSP helper

Build explicitly from the repository/gem root:

```sh
ruby ext/pwn_dsp/build.rb
PWN_TEST_DSP_NATIVE=1 bundle exec rspec spec/lib/pwn/ffi/dsp_native_spec.rb spec/lib/pwn/sdr/decoder/dsp_native_spec.rb
bundle exec ruby -Ilib ext/pwn_dsp/benchmark.rb
```

Requires a C99 compiler and libm only. The build writes a private temporary file
inside this bundled directory and atomically renames the completed library. No
compiler runs during require or gem installation. No user-supplied library path,
current-directory library lookup, executable download, or shared compile cache.
Restart Ruby after building. The binary is intentionally ignored by git; ship
source/build support, not a host-specific shared object.

`PWN::FFI::DSPNative.available?` reports availability and `load_error` explains
an unavailable helper. `PWN::SDR::Decoder::DSP.process_iq` returns
`{ samples: [...], backend: :native }` or explicitly degraded `backend: :ruby`.
An unavailable/failed helper leaves processing functional but not guaranteed
realtime. `native: false` forces the Ruby path. The existing unpack, magnitude,
FM and power-of-two FFT methods use the helper when available.

```ruby
state = {} # one per stream; do not share concurrently or across formats
result = PWN::SDR::Decoder::DSP.process_iq(
  data: chunk, format: :cu8, operation: :fm, state: state, kf: 1.0
)
```

Formats: `:cu8`, `:cs16le`, or packed host-native doubles `:f64`. Operations:
`:unpack` (interleaved IQ), `:mag` (I²+Q²), `:fm` (phase radians times `kf`).
Pass the same state hash for every chunk. It retains incomplete bytes and the
last complete IQ pair. Empty chunks do not erase state; incomplete final bytes
remain in `state[:remainder]`. FM emits no synthetic first sample: without prior
state N IQ pairs produce N-1 outputs; subsequent chunks produce N. Changing
operation preserves last IQ, but changing encoding requires a new state.

The old Liquid FM substitution emitted N samples and used a different scaling
convention; DSP now preserves its documented Ruby discriminator contract.
VOLK's Array-to-float magnitude path was slower than Ruby on this host and lost
double precision; DSP uses the bundled double kernel or Ruby instead.
Power-of-two FFT fallback is now O(N log N) Ruby and no longer silently truncates
requested transforms to 512 bins. Non-power-of-two sizes use existing FFTW or
an exact, slower O(N²) Ruby DFT. Existing FFTW uses single precision; the bundled
helper and Ruby path use double precision.

## Measured kernel throughput

Actual run: Ruby 4.0.6, Linux x86_64, Intel Core i7-8665U. One warmup, then five
wall-clock repetitions; median below. IQ kernels use 1,048,576 complex samples;
FFT512 batches 128 transforms and FFT4096 batches 32. FFI copies, Ruby result
allocation and GC are included. Raw repetitions and rate comparisons are in
`benchmark-results.json`; no acquisition, channelizer, protocol decoder,
queueing, or end-to-end pipeline is included.

| Kernel | Ruby MS/s | Native MS/s |
|---|---:|---:|
| Existing cu8 unpack API | 2.90 | 21.60 |
| Existing magnitude Array API | 5.94 | 12.15 |
| Existing FM Array API | 2.95 | 7.82 |
| FFT magnitude, 512 | 0.22 | 10.49 |
| FFT magnitude, 4096 | 0.10 | 10.25 |
| Packed cu8 unpack | 2.99 | 22.96 |
| Packed cu8 → magnitude | 1.74 | 38.32 |
| Packed cu8 → FM | 1.09 | 13.57 |

All measured native kernels exceeded 2.4 MS/s individually. At 10 MS/s, packed
FM and the FFT kernels exceeded the target, but the existing Array FM API did
not. At 20 MS/s only cu8 unpack and packed magnitude exceeded the target. These
are measured kernel-only comparisons, not realtime guarantees for a full
pipeline. Prefer the packed operation when only magnitude or FM is needed: it
avoids constructing and then repacking an intermediate IQ Array.

Before changes, existing native VOLK magnitude measured roughly 0.287 s for
1,048,576 IQ pairs versus Ruby 0.164 s; cu8 unpack remained Ruby (~0.337 s), and
Liquid FM had the incompatible output contract. Original Ruby 512 DFT measured
~0.130 s per transform. Existing FFTW through its Array wrapper measured about
1.67 MS/s for a 4096 transform in the initial benchmark, motivating the bundled
FFT/magnitude loop. Timing varies with workload and host frequency scaling.
