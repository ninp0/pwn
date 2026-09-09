# Independent RDS MPX fixture

`mpx-testfile-yksi.flac` is the unmodified upstream redsea test recording:
https://media.githubusercontent.com/media/windytan/redsea/7555c9f6259d50718697ee8c9f218ea012c6892c/test/resources/mpx-testfile-yksi.flac

SHA-256: `c92b9c72f132e37cbe253a19a6ae17c52f17f5318672c391ce7f3b9657320eb1`

Mono 192000 Hz 16-bit FLAC; 134400 samples, duration 0.7 s. Upstream's independently published expectations (`test/components-mpx.cc`, same revision) are PI `0x6201`, programme type `Serious classical`. Upstream's license is included. No synthetic RF provenance is claimed.

Real replay with redsea 1.3.1 `--no-fec --show-raw --file` yielded one complete group: `6201 E1C3 4D00 6204` (14A); partial groups are suppressed by PWN. Raw s16le conversion through SoX and the native stdin path yields intact `6201 01DF 0A14 5349` (0A) before EOF. The short noisy fixture can acquire differently under float/container and raw-PCM paths; do not treat every group count as universal with different DSP versions.
