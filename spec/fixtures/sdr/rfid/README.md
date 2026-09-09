# FDX-B native offline demodulation fixtures

Copied unchanged from RfidResearchGroup/proxmark3 commit
`9ec11eda2ada04b25b0f7ad57b34af7d644a17c5`:

- `fdxb_animal.pm3`: `traces/lf_ATA5577_fdxb_animal.pm3`
  SHA256 `8e9a71fa8efa63f8a388bf444293949ac6156e2d1005075f715fcc36af26641c`
- `fdxb_extended.pm3`: `traces/lf_ATA5577_fdxb_extended.pm3`
  SHA256 `f5104fad598828359f240e3523f8bfd94b3327faf3f7fe5d7589c70353acda09`

Source: https://github.com/RfidResearchGroup/proxmark3/tree/9ec11eda2ada04b25b0f7ad57b34af7d644a17c5/traces
Attribution: upstream contributors; upstream GPL-3.0 project. These are upstream
ATA5577 test-tag amplitude traces, not independent ISO certification or raw IQ.

Native executable installed and exercised: Kali `proxmark3` package
4.21611-0kali1, ELF C client, version reports v4.21611-suspect/389522379.
No Python runtime, serial port, RF acquisition or transmission is involved.

Reproduce: `proxmark3 --incognito -c 'data load -f PATH; lf fdxb demod'`.
Both traces yield CRC-valid ISO11784/11785 FDX-B identity 999-000000112233.
Animal trace: CRC DC48, animal true/data block false.
Extended trace: CRC 4198, animal false/data block true (extension 0x16A).
These expectations were independently observed with the native upstream decoder;
only the core identity/flags are currently surfaced by the Ruby API.

Ruby entry: `RFID.decode(mode: :fdxb_pm3, file: PATH, output: IO)`.
Explicit `.pm3` signed-integer amplitude traces only; no sample-rate conversion,
SDR IQ demodulation, HF/UHF support, encrypted tag parsing or arbitrary commands.
The default EM4100 IQ decoder remains unchanged. Native replay is finite, not a
shared Base streaming source. Missing executable raises rather than faking output.
