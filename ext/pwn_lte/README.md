# Optional native LTE PBCH bridge

Scope: LTE downlink **FDD, normal cyclic prefix, two transmit ports**, central
six PRBs at **1.92 Msps**. Two explicit offline modes are supported:

- `:pbch_sf0_iq`: caller-known PCI and consecutive, separately extracted
  1920-complex-sample (1 ms) SF0 blocks.
- `:pbch_iq`: continuous IQ, native PSS/SSS search over all three N_ID_2
  sequences, recovered PCI and SF0 timing, fractional CFO estimation/correction,
  then the same CRC-checked PBCH MIB decoder. No caller PCI or alignment needed.

No CFO tracking loop, integer-subcarrier CFO search, 40 ms soft combining,
SIB/traffic decoding, TDD, extended CP, other antenna configurations or hardware
access is implemented. `.detect` remains PSS observation only; default `.decode`
requires an explicit mode. Do not infer complete LTE support from this fixture.
Acquisition uses 5 ms windows with 1 ms overlap, bounded carry, and absolute
`timing_sample` positions relative to the source. Duplicate overlapping SF0 hits
are suppressed. At EOF, a remaining complete SF0 can decode; a partial SF0
never gets padded or emitted. Failed synchronization or PBCH CRC produces no
success frame. Fractional CFO values are estimates, not calibrated measurements.

The C bridge calls srsRAN OFDM FFT, downlink reference-signal channel estimation,
PBCH equalization/demapping, convolutional FEC and CRC16. Ruby handles stream
chunking, explicit source validation and structured output using the shared
runner. Native structs never cross FFI. A missing backend raises LoadError;
no runtime compilation, download, shell wrapper or synthetic-success fallback.

## Explicit build (verified on Linux)

The optional bridge links AGPL-3.0-or-later srsRAN_4G; corresponding upstream
source/license obligations apply when distributing linked binaries. The C
bridge is also AGPL-3.0-or-later. Do not ship a binary without its corresponding
source and license. The repository fixture directory includes the upstream
license. No third-party source tree or binary is bundled in this directory.

Tested upstream revision: `6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16`.
Prerequisites include C/C++ compiler, CMake, FFTW3 float development files,
mbedTLS, Boost program_options and SCTP development files. The SCTP dependency
is required by upstream configuration even when building only the PHY target.

```sh
git clone https://github.com/srsran/srsRAN_4G.git /tmp/pwn-srsran-iq
git -C /tmp/pwn-srsran-iq checkout 6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16
cmake -S /tmp/pwn-srsran-iq -B /tmp/pwn-srsran-iq/build \
  -DENABLE_GUI=OFF -DENABLE_UHD=OFF -DENABLE_BLADERF=OFF \
  -DENABLE_SOAPYSDR=OFF -DENABLE_ZEROMQ=OFF -DENABLE_RF_PLUGINS=OFF \
  -DENABLE_SRSUE=OFF -DENABLE_SRSENB=OFF -DENABLE_SRSEPC=OFF \
  -DENABLE_WERROR=OFF
cmake --build /tmp/pwn-srsran-iq/build --target srsran_phy -j4
ruby ext/pwn_lte/build.rb /tmp/pwn-srsran-iq
PWN_TEST_LTE_NATIVE=1 bundle exec rspec spec/lib/pwn/sdr/decoder/lte_spec.rb
```

A cached missing SCTP path during configuration was resolved after installing
`libsctp-dev` by explicitly setting
`-DSCTP_LIBRARIES=/usr/lib/x86_64-linux-gnu/libsctp.so` (Linux amd64-specific).
The bridge build uses `--no-undefined` and links libstdc++ because the native
PHY archive contains C++ objects. The tested upstream build uses native CPU
ISA optimization; rebuild for the deployment CPU rather than copying its .so.

Native tests are registered when the local .so exists, or forced by
`PWN_TEST_LTE_NATIVE=1`. Forced runs fail if the backend is absent; they do not
skip. Default source-only tests cover source/mode guards and fixture integrity.

## Independent upstream fixture

`spec/fixtures/sdr/lte/signal.1.92M.dat` is copied verbatim from
`lib/src/phy/phch/test/signal.1.92M.dat` at the revision above.
SHA-256: `d658e615c10c8e65b8c190d7cf2592237fd430411936b4d82c7b30c008c1ab21`.
Source URL:
https://github.com/srsran/srsRAN_4G/blob/6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16/lib/src/phy/phch/test/signal.1.92M.dat

Upstream `pbch_file_test.c` independently declares PCI 150, two ports,
SFN offset zero and payload bits corresponding to `681c00`; executing its
`pbch_file_test -i .../signal.1.92M.dat` confirmed those values. The capture's
RF provenance is not documented here; treat it as an independent upstream
interoperability fixture, not a newly collected/live RF test.

The regression extracts the **first 15360 bytes** (one CF32LE subframe),
quantizes each scalar with `(value * 16000).round` into CS16LE and passes it
through `LTE.decode` and the actual shared IQ runner. The shared runner does
not currently accept CF32, so the example declares `iq_format: :cs16`.
Expected fields: MIB `681c00`, PRB 50, SFN high eight bits shifted left two =
28, PHICH normal/resource 1, two ports. `pci_source: caller` explicitly avoids
claiming recovered PCI. This is not a PSS-only or already-demodulated-bit test.

A pipe test observes the CRC-verified MIB before writer EOF with irregular
997-byte reads. Wrong PCI and zero-energy samples produce no frames; partial
subframes raise rather than padding. No physical radio is selected by tests.

## Acquisition regression and performance

The same pinned upstream IQ also exercises `:pbch_iq` without a PCI or timing
hint, after 137 leading zero samples. It recovers PCI 150, SF0 start 137 and
CRC-verified MIB `681c00`. A second test prefixes 8501 samples to cross the
search-window overlap, applies a deterministic +1200 Hz frequency shift to the
upstream waveform, and observes the same MIB before pipe EOF with 997-byte reads.
The original capture estimates approximately -500 Hz CFO, so shifted acquisition
estimates approximately +700 Hz. These shifts are regression transformations,
not additional independent captures. Zero energy, seeded white noise, incomplete
SF0 and PSS/SSS with PBCH removed produce no decoded output.

Run `bundle exec ruby ext/pwn_lte/benchmark.rb` for measured acquisition plus
PBCH throughput and shared-runner throughput; saved measurements are in
`benchmark-results.json`. This is offline replay of one strong upstream cell,
not live-radio or general LTE performance proof. Planning, Ruby allocation,
window overlap, repeated search and stream lifecycle overhead are included as
specified by each benchmark. No persistent native tracking state is maintained.
