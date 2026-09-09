# GPS L1 C/A native IQ verification

`GPS.decode(mode: :iq, source: :file, file: ..., sample_rate: 4_000_000,
iq_format: :cs16)` runs the optional **native GNSS-SDR executable** (tested
0.0.21), not Python and not the acquisition-only `.detect` implementation.
On Debian/Kali, `sudo apt-get install gnss-sdr` installs the packaged executable
and its dependencies; the earlier source configure failure at Matio/HDF5 is not
required for this path. GNSS-SDR is separately distributed under GPL-3.0-or-later:
https://github.com/gnss-sdr/gnss-sdr . No upstream implementation is vendored here.
Source-build instructions: https://gnss-sdr.org/docs/tutorials/installation/ .

## Actual external capture

- Publisher/tutorial: https://gnss-sdr.org/my-first-fix/
- Capture: https://sourceforge.net/projects/gnss-sdr/files/data/2013_04_04_GNSS_SIGNAL_at_CTTC_SPAIN.tar.gz/download
- Working mirror: https://onboardcloud.dl.sourceforge.net/project/gnss-sdr/data/2013_04_04_GNSS_SIGNAL_at_CTTC_SPAIN.tar.gz
- Real CTTC Spain reception, 2013-04-04; interleaved signed 16-bit IQ,
  4,000,000 complex samples/s, GPS L1 C/A, baseband.
- Tested raw prefix: 625853440 bytes; SHA-256
  `57a926c42063dbd143bdb6b5e6ddc4dbe4bceb984a1e1d1fba89a30e7c09a541`.
  The prefix was initially extracted from the first 450000000 archive bytes;
  incomplete extraction correctly reported EOF. The download was subsequently
  completed, `gzip -t` passed, and re-reading the same prefix from the complete
  archive produced the identical SHA-256 above. Complete downloaded archive
  SHA-256: `d5b926aefe7462ca4211bcae2129591a810fa4960a214f35d056a883aa2af3ff`.
  The complete tar entry declares 1600000000 raw bytes. These are locally
  verified hashes, not a claimed comparison with a publisher-supplied hash.
  IQ is not redistributed in the repository.
- `cttc-lnav.json` is an actual monitor packet and its decoded output captured
  from this IQ by GNSS-SDR 0.0.21. PRN 20, subframe 3, next TOW 368628 seconds.
  GNSS-SDR's separate monitor timestamp was 368628000 ms, agreeing with the
  independently rechecked HOW field. The expected payload is an observed
  regression result, **not an independently published publisher payload**.

The monitor contains 300 parity-bearing bits but its 24 data bits per word have
already been D30* de-inverted by GNSS-SDR. `decode_monitor` restores transmitted
inversion using the preceding word's parity bits before `decode_subframe`
rechecks all ten word parities. `.decode(mode: :lnav_bits)` continues to accept
transmitted parity-bearing bits; it has not been redefined to mean monitor bits.

## Reproduce

Download/extract the publisher archive outside the repository, then run:

```sh
PWN_GPS_IQ_FIXTURE=/absolute/path/to/2013_04_04_GNSS_SIGNAL_at_CTTC_SPAIN.dat \
  bundle exec rspec spec/lib/pwn/sdr/decoder/gps_spec.rb
```

The optional real-IQ example checks Linux `/proc/<receiver-pid>/fdinfo` at the
first callback: the actual input descriptor's read position must be strictly
less than the IQ file size. It also verifies native process cleanup after stop.
The default suite tests the saved monitor, inversion, corrupted parity, malformed
protobuf, absent native executable, failed native process, and explicit source
validation without RF hardware or a native runtime requirement.

## Exact scope and limitations

- Actual acquisition, carrier/code tracking, bit synchronization, LNAV framing
  and native parity check occur inside GNSS-SDR; Ruby independently rechecks
  parity and exposes header fields plus all 240 data bits as hex.
- Supported input: regular **files only**, :cs16/:cs8/:cf32, native-endian,
  2–25 Msps. Only 4 Msps :cs16 has external IQ interoperability evidence here.
  No automatic RF selection, pipe/socket/live source, SBAS, CNAV, L2/L5, or
  application-level ephemeris/PVT assembly is claimed.
- Returns a result Hash with total `frame_count`, up to the first 1000 `frames`,
  `decoded`, and `reason` (:eof/:stopped/:duration). All accepted frames reach
  `on_frame` and optional JSONL `output`. LNAV bit mode retains its Array return.
- Native monitor delivery uses a bounded kernel loopback UDP receive queue,
  not a lossless backpressure protocol. Slow callbacks can lose monitor packets.
  Stop/deadline checks are cooperative between synchronous callbacks/output;
  a blocked callback is not independently interrupted. This is not equivalent
  to Base's separately supervised realtime runner.
- IQ mode does not implement Base interactive/queue_size/log_file controls.
  Diagnostics/native PVT side products are confined to a temporary workspace
  and removed, including on failure. Missing backend raises LoadError; failed
  backend raises IOError; no navigation output is never called successful decode.
