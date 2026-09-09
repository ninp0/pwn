"""Offline regression stimuli, not RF captures. Requires GNU Radio 3.10.12.
SCH codeword: libosmocore tests/coding/coding_test.ok (03 03 01 00).
GSM differential precoding: 3GPP TS 45.004 section 2.3; BT=0.3.
GNU Radio digital.gmsk_mod supplies independent pulse shaping/modulation.
Optional third-party GNU Radio Python binding; never called by runtime/tests.
Run from any directory: /usr/bin/python3 /opt/pwn/ext/pwn_gsm/fixtures/generate.py.
Outputs are explicitly rooted at the repository's spec/fixtures/sdr/gsm/.
"""
from pathlib import Path
import hashlib
import json
import math
import struct
from gnuradio import blocks, digital, gr

coded = list(map(int, '111001110011000011100111001100001101001111000000000011010000011010110111111100'))
training = list(map(int, '1011100101100010000001000000111100101101010001010111011000011011'))
root = Path(__file__).resolve().parents[3] / 'spec' / 'fixtures' / 'sdr' / 'gsm'
root.mkdir(parents=True, exist_ok=True)
metadata = {}
for name, data in [('sch', coded), ('bad-crc', [0] * 78)]:
    bits = [0] * 40 + [0] * 3 + data[:39] + training + data[39:] + [0] * 3 + [0] * 40
    previous = 0
    precoded = []
    for bit in bits:
        precoded.append(1 ^ bit ^ previous)
        previous = bit
    tb = gr.top_block()
    src = blocks.vector_source_b(precoded, False)
    mod = digital.gmsk_mod(samples_per_symbol=4, bt=0.3, do_unpack=False)
    sink = blocks.vector_sink_c()
    tb.connect(src, mod, sink)
    tb.run()
    # Nonzero starting phase, non-symbol-aligned lead-in, and +6 kHz CFO.
    rate = 3250000 / 3
    iq = [0j] * 17 + [x * complex(math.cos(0.73 + 2 * math.pi * 6000 * i / rate), math.sin(0.73 + 2 * math.pi * 6000 * i / rate)) for i, x in enumerate(sink.data())]
    raw = b''.join(struct.pack('<hh', round(x.real * 24000), round(x.imag * 24000)) for x in iq)
    path = root / (name + '.cs16')
    path.write_bytes(raw)
    metadata[path.name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'samples': len(iq)}
(root / 'vectors.json').write_text(json.dumps({'generator': 'GNU Radio ' + gr.version(), 'sample_rate': rate, 'freq_offset_hz': 6000, 'payload_hex': '03030100', 'files': metadata}, indent=2) + '\n')
