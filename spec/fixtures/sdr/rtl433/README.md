# Acurite 609TXC independent RF fixture

`acurite_th_609_001.cu8` and its `.json` reference output are copied byte-for-byte from:

https://github.com/merbanan/rtl_433_tests/tree/a09649ae2b50d86600bd916e291acc4239a51e08/tests/acurite/Acurite_609A1TX

Capture format: unsigned interleaved 8-bit IQ, 250000 complex samples/second.
SHA-256 of the CU8 file: `8bb09845f733df26affe056d6a8f9b981d3f47de348e5faaa68f97a928cb37db`.
Upstream identifies it as an actual Acurite 609A1TX capture, 26.2 C and 76% humidity.
Reference output contains six packets, ID 202, battery_ok 1, status 2.
Attribution: rtl_433_tests contributors. No claim of authorship or newly assigned license is made here.

Protocol reference: https://github.com/merbanan/rtl_433/blob/master/src/devices/acurite.c
(`acurite_th_decode` and `acurite_th`). PPM gap 1000/2000 us, row gap 3000 us,
reset 10000 us; five MSB-first octets, additive checksum, signed 12-bit temperature.
This is a native Ruby implementation of this one device protocol, not a wrapper or a
claim of parity with rtl_433's full catalogue. The default normalized envelope
threshold is 0.5; other capture gains may need `threshold:` adjustment.

# Other independent references in the matching specs

RFID: https://www.priority1design.com.au/em4100_protocol.html contains the literal
64-bit EM4100 example used in `rfid_spec.rb` (version 06, identifier 001259E3).
The IQ test waveform is generated from those published bits and is NOT a recorded
RF capture. Supported: ASK Manchester RF/64, RF/32 and RF/16 with configured carrier
and threshold. No HF/UHF, PSK, biphase, EPC Gen2, ISO14443 or ISO15693 decoding.

WiFi: IEEE P802.11b/D3.1 section 18.2.3.6 supplies the independent PLCP CRC vector:
https://www.ieee802.org/11/Documents/DocumentArchives/1999_docs/90845b_p80211b-draft3.1.pdf
Sections 18.2.3/18.2.4 describe long SYNC, SFD, CRC16 and self-synchronizing scrambling.
WiFi IQ fixtures are synthetic standards-derived regression signals, NOT independent
over-air interoperability proof. Supported PHY: long-preamble 1 Mbps DBPSK/Barker,
11/22/44 MHz centred IQ. No CCK, DQPSK, OFDM, short preambles, resampling,
equalization or sample-clock drift correction. MAC support includes legacy control
subtypes 10-15, management/data headers, WDS/QoS offsets, beacon/probe information
elements, and plaintext unfragmented LLC/SNAP. Other bodies are preserved as hex;
there is no decryption, A-MSDU dissection, BlockAck or
application-layer decoding. The new ordered plaintext data-fragment reassembler
retains up to 64 flows/2304 bytes each for one second of capture time. Protected
frames and aggregates remain opaque. This Ruby reference demodulator streams incrementally
but has no real-time-throughput guarantee at WiFi sample rates.

The default IQ `.decode` entry points refuse unsupported modes. `.detect` is
energy-only, never protocol evidence. RFID additionally accepts explicit FDX-B
PM3 amplitude traces; see `../rfid/README.md`.

# Native rtl_433 catalogue replay

`RTL433.decode(mode: :native, file: PATH, sample_rate: 250000)` runs the real
installed ELF rtl_433 process with configuration disabled (`-c 0`) and an explicit
file (`-r cu8:PATH`). No automatic radio selection or Python adapter. CU8, CS16
and CF32 are accepted with explicit format. CU8 uses original captures; CS16 and
CF32 were additionally exercised via deterministic conversion of the Toyota IQ
capture, each yielding its one native TPMS frame.
`protocols: [88]` selects positive native IDs; otherwise upstream's enabled
catalogue is used (disabled-by-default devices need explicit IDs). Output retains
upstream fields and `mic`, puts the native ID in `device_protocol`, and labels
missing integrity as `not-reported`, not authentication. This finite replay mode
supports JSONL output/callbacks/logging and cancellation/deadline cleanup; it is
not the shared live IQ runner. Missing executables raise; no detector fallback.

Installed package: Kali rtl-433 26.07-1; binary `-V` reports 25.12 (2025-12-12).
Three independent captures were exercised through the public native API:
Acurite OOK (6 frames), WH31 FSK (2), Toyota TPMS FSK (1), all matching upstream
JSON fields. This proves those fixtures, not every catalogue protocol.

Additional captures/references copied unchanged from rtl_433_tests commit
`a09649ae2b50d86600bd916e291acc4239a51e08`, all at 250000 samples/sec:

- `wh31.cu8`/`.json`: `tests/EcoWitt-WH40/WH31_433.92M_250k.{cu8,json}`
  CU8 SHA256 `bda1b7edb49f1f10c8b28925d3ad25daca315afe358af2dc027914863a896600`
  JSON SHA256 `4ba597e94b30572a8776db6a767a5c43c55463a06f614e4448de00e72f7033f8`
- `toyota.cu8`/`.json`: `tests/Toyota_TPMS/02/0d5aee3_g007_433.92M_250k.{cu8,json}`
  CU8 SHA256 `5837b36d265d7d30476fe15cee31afee45b9dfe02fd0fd9eee74279ba28cff73`
  JSON SHA256 `690c3d368f7395eb4528297282a8af8fbc5b6998dd7959b3e300408156d3c217`

Native WiFi candidate researched: https://github.com/bastibl/gr-ieee802-11
(maint-3.10, C++ GNU Radio a/g/p PHY). GNU Radio 3.10.12 is installed, but this
OOT library is not; no supported distro package was found. A C++ flowgraph and
independent fixture validation are still needed. No unexercised wrapper or new
OFDM support claim was added; WiFi PHY remains the named DSSS mode above.
