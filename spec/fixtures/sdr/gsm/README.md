# GSM SCH IQ regression vectors

These are **synthesized regression stimuli, not over-the-air captures**. The
receiver is implemented in Ruby; Python/GNU Radio is only an optional offline
fixture-regeneration dependency, not a decoder runtime dependency.

The optional [`ext/pwn_gsm/fixtures/generate.py`](../../../../ext/pwn_gsm/fixtures/generate.py)
uses GNU Radio **3.10.12.0** `digital.gmsk_mod`
(BT=0.3, 4 samples/symbol). Its independent Gaussian pulse shaping and continuous
phase modulator operate on GSM differentially precoded bits (TS 45.004 §2.3).
The fixed 64-bit SCH training sequence follows TS 45.002 §5.2.5. Both fixtures
have a 17-sample zero lead-in, 0.73-radian starting phase and +6000 Hz carrier
offset. IQ is interleaved signed little-endian 16-bit at 1083333.333333 Hz.

The 78-bit known SCH codeword and expected `03 03 01 00` decoded bytes are
published in libosmocore `tests/coding/coding_test.ok`, lines 50–53, pinned at:
https://github.com/osmocom/libosmocore/blob/2a26b47cb6c6590fde8cb953f1caeaf498d5568b/tests/coding/coding_test.ok

GNU Radio modulator reference:
https://github.com/gnuradio/gnuradio/blob/v3.10.12.0/gr-digital/python/digital/gmsk.py

`bad-crc.cs16` replaces the coded data with zeros while retaining valid GMSK and
training, so rejection exercises channel integrity rather than missing signal.
`vectors.json` records fixture SHA-256 hashes. Regenerate with:

```
/usr/bin/python3 ext/pwn_gsm/fixtures/generate.py
```

Tests never execute this script or import Python. It is retained outside `spec/`
solely for the third-party GNU Radio Python modulation binding (independent of
PWN's receiver), not a first-party runtime/helper implementation. Its output
path is always `spec/fixtures/sdr/gsm/` relative to the repository, independent
of the caller's working directory.

Tests cover file input, unaligned byte chunks, single-sample streaming, an open
pipe callback before EOF, additive noise, corrupt CRC, pure noise/tones and
truncation. They do not establish live-radio reception, multipath equalization,
or real-time throughput. Current SCH reception requires channelized IQ at four
or more samples/symbol. BCCH, CCCH, and traffic are not implemented.
