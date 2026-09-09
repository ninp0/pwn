# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::Flex do
  it 'validates the alpha fragment checksum and skips the first-fragment signature' do
    # Synthetic words independently calculated from TI SPRA193 sections 2.4/2.4.1:
    # signature=~(H+I)&127=0x6E; checksum=~(0x18+0x6E+0x64+0x12)&1023=0x303.
    data = [0x807, 0x807B, 0x81D0, 0x1B03, 0x12646E] + Array.new(83, 0)
    frames = []
    described_class.emit_phase(words: data.map { |w| flex_word(w) }) { |f| frames << f }
    expect(frames.map { |f| f[:type_payload] }).to eq(['HI'])
    # Valid BCH does not make a bad fragment checksum valid.
    data[4] ^= 0x80
    frames = []
    described_class.emit_phase(words: data.map { |w| flex_word(w) }) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'rejects a bad whole-message signature even with valid BCH and fragment checksum' do
    # Change signature only, then compensate the fragment checksum (TI SPRA193 2.4.1).
    data = [0x807, 0x807B, 0x81D0, 0x1B02, 0x12646F] + Array.new(83, 0)
    frames = []
    described_class.emit_phase(words: data.map { |w| flex_word(w) }) { |f| frames << f }
    expect(frames).to be_empty
  end

  def alpha_phase(text, fragment:, continued:, signature:, number: 7)
    # TI SPRA193 Tables 2-5/2-6, synthetic plain ASCII fragments.
    chars = text.bytes
    chars.unshift(signature) if fragment == 3
    chars << 3 until (chars.length % 3).zero?
    payload = chars.each_slice(3).map { |a, b, c| a | (b << 7) | (c << 14) }
    header = (number << 13) | (fragment << 11) | (continued ? 1024 : 0)
    sum = ([header] + payload).sum { |word| (word & 255) + ((word >> 8) & 255) + (word >> 16) }
    header |= ~sum & 1023
    data = [0x807, 0x807B, 0x1D0 | ((payload.length + 1) << 14), header] + payload
    (data + Array.new(88 - data.length, 0)).map { |word| flex_word(word) }
  end

  it 'reassembles ordered alpha fragments and verifies the complete signature' do
    state = {}
    frames = []
    signature = ~'HELLO'.bytes.sum & 127
    first = alpha_phase('HE', fragment: 3, continued: true, signature: signature)
    last = alpha_phase('LLO', fragment: 0, continued: false, signature: signature)
    described_class.emit_phase(words: first, fragments: state) { |f| frames << f }
    expect(frames).to be_empty
    described_class.emit_phase(words: last, fragments: state) { |f| frames << f }
    expect(frames.map { |f| f[:type_payload] }).to eq(['HELLO'])
    expect(state).to be_empty
    frames = []
    described_class.emit_phase(words: last, fragments: state) { |f| frames << f }
    expect(frames).to be_empty
  end

  def alpha_audio(words)
    sync = '870CA6C6AAAA78F3'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    levels = (Array.new(160) { |i| i & 1 } + sync).map { |b| b == 1 ? -0.9 : 0.9 }
    fiw = flex_word(15)
    levels += Array.new(16, 0.9) + Array.new(32) { |i| fiw[i] == 1 ? 0.9 : -0.9 } + Array.new(40, 0.9)
    levels += Array.new(2816) do |i|
      words[((i >> 5) & 0xFFF8) | (i & 7)][(i >> 3) & 31] == 1 ? 0.9 : -0.9
    end
    levels.flat_map { |level| Array.new(30, level) }
  end

  it 'retains alpha assembly across discriminator chunks and successive received frames' do
    signature = ~'HELLO'.bytes.sum & 127
    demod = described_class::Demod.new
    frames = []
    [[3, true, 'HE'], [0, false, 'LLO']].each do |fragment, continued, text|
      words = alpha_phase(text, fragment: fragment, continued: continued, signature: signature)
      alpha_audio(words).each_slice(113) { |chunk| demod.feed(chunk) { |f| frames << f } }
    end
    expect(frames.map { |f| f[:type_payload] }).to eq(['HELLO'])
  end

  it 'includes ASCII controls in message integrity and removes only trailing fill' do
    text = "HI\r\n"
    frames = []
    words = alpha_phase(text, fragment: 3, continued: false, signature: ~text.bytes.sum & 127)
    described_class.emit_phase(words: words) { |f| frames << f }
    expect(frames.map { |f| f[:type_payload] }).to eq([text])
  end

  it 'rejects missing or misordered alpha fragments and a bad final signature' do
    signature = ~'HELLO'.bytes.sum & 127
    [
      [[3, true, 'HE', signature], [1, false, 'LLO', signature]],
      [[3, true, 'HE', signature ^ 1], [0, false, 'LLO', signature]],
      [[3, true, 'HE', signature], [0, false, 'LLP', signature]]
    ].each do |sequence|
      state = {}
      frames = []
      sequence.each do |fragment, continued, text, check|
        words = alpha_phase(text, fragment: fragment, continued: continued, signature: check)
        described_class.emit_phase(words: words, fragments: state) { |f| frames << f }
      end
      expect(frames).to be_empty
      expect(state).to be_empty
    end
  end

  it 'wraps the continuation sequence modulo three' do
    text = 'ABCDEFGHIJKLMN'
    signature = ~text.bytes.sum & 127
    state = {}
    frames = []
    [[3, 'AB'], [0, 'CDE'], [1, 'FGH'], [2, 'IJK'], [0, 'LMN']].each_with_index do |(fragment, part), i|
      words = alpha_phase(part, fragment: fragment, continued: i < 4, signature: signature)
      described_class.emit_phase(words: words, fragments: state) { |f| frames << f }
    end
    expect(frames.map { |f| f[:type_payload] }).to eq([text])
  end

  it 'does not decode secure messages through the plain alpha layout' do
    data = [0x807, 0x807B, 0x8180, 0x1B03, 0x12646E] + Array.new(83, 0)
    frames = []
    described_class.emit_phase(words: data.map { |w| flex_word(w) }) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'does not mislabel an unsupported long address as a short capcode' do
    data = [0x807, 0x40, 0x81D0, 0x1B03, 0x12646E] + Array.new(83, 0)
    frames = []
    described_class.emit_phase(words: data.map { |w| flex_word(w) }) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'streams a complete 1600/2 protected alpha frame before EOF and rejects truncation' do
    data = [0x807, 0x807B, 0x81D0, 0x1B03, 0x12646E] + Array.new(83, 0)
    words = data.map { |w| flex_word(w) }
    sync = '870CA6C6AAAA78F3'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    lead = Array.new(160) { |i| i & 1 }
    levels = (lead + sync).map { |b| b == 1 ? -0.9 : 0.9 }
    fiw = flex_word(15)
    levels += Array.new(16, 0.9) + Array.new(32) { |i| fiw[i] == 1 ? 0.9 : -0.9 }
    levels += Array.new(40, 0.9)
    levels += Array.new(2816) do |i|
      word = words[((i >> 5) & 0xFFF8) | (i & 7)]
      word[(i >> 3) & 31] == 1 ? 0.9 : -0.9
    end
    samples = levels.flat_map { |v| Array.new(30, v) }
    frames = []
    demod = described_class::Demod.new
    samples.each_slice(113) { |chunk| demod.feed(chunk) { |f| frames << f } }
    expect(frames.map { |f| f[:type_payload] }).to eq(['HI'])
    frames = []
    described_class::Demod.new.feed(samples[0...-960]) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'never silently falls back to energy detection from decode' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(hash_including(fallback: :raise))
    described_class.decode(freq_obj: {}, file: '/offline/fixture.cs16', fallback: :detector)
  end

  def flex_word(data)
    value = Array.new(21) { |i| data[i] }.inject(0) { |acc, bit| (acc << 1) | bit } << 10
    remainder = value
    30.downto(10) { |i| remainder ^= 0x769 << (i - 10) if remainder[i] == 1 }
    value |= remainder
    reversed = Array.new(31) { |i| value[i] }.inject(0) { |acc, bit| (acc << 1) | bit }
    reversed | ((reversed.digits(2).sum & 1) << 31)
  end

  it 'decodes a protected short-address alpha phase but rejects damaged payload words' do
    data = [0x807, 0x807B, 0x81D0, 0x1B03, 0x12646E] + Array.new(83, 0)
    words = data.map { |w| flex_word(w) }
    frames = []
    described_class.emit_phase(words: words, phase: 'A', cycle: 0, frame: 0) { |f| frames << f }
    expect(frames.first).to include(capcode: '000000123', type: 'ALN', type_payload: 'HI')
    bad = (1..4095).map { |mask| words[4] ^ mask }.find { |w| described_class.bch_fix(word: w)[1] < 0 }
    expect(bad).not_to be_nil
    words[4] = bad
    frames = []
    described_class.emit_phase(words: words, phase: 'A', cycle: 0, frame: 0) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'rejects incomplete phases without inventing absent codewords' do
    frames = []
    expect { described_class.emit_phase(words: []) { |f| frames << f } }.not_to raise_error
    # A valid BCH BIW declaring address/vector locations is still not a phase.
    described_class.emit_phase(words: [0xF27C46AE]) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'does not accept an uncorrectable FIW just because its nibble checksum passes' do
    word = (0...4096).map { |mask| 0xF27C46AE ^ (mask << 21) }.find do |w|
      described_class.bch_fix(word: w)[1] == -1
    end
    expect(word).not_to be_nil
    demod = described_class::Demod.new
    demod.instance_variable_set(:@state, :fiw)
    (Array.new(16, 0) + Array.new(32) { |i| word[i] }).each { |bit| demod.send(:st_fiw, bit == 1 ? 3 : 0) }
    expect(demod.instance_variable_get(:@state)).to eq(:sync1)
  end

  it 'exposes detection separately without claiming a decoded payload' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_detector) do |opts|
      detail = opts[:describe].call({})
      expect(detail).to include(event: 'detection', capability: 'energy-detection', decoded: false)
      expect(detail.keys & %i[text message payload type_payload]).to be_empty
      expect(opts[:interactive]).to eq(false)
      :detected
    end
    expect(described_class.detect(freq_obj: {}, interactive: false)).to eq(:detected)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::Flex
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::Flex
    expect(help_response).to respond_to :help
  end

  # Regression: A_TABLE was mis-assigned so 929–932 MHz US FLEX (0xDEA0) never
  # locked and reported the wrong mode (see mistakes sig 827de20227fa).
  it 'maps every Sync-1 A-word to the correct symbol-rate/levels' do
    t = PWN::SDR::Decoder::Flex::A_TABLE
    expect(t[0x870C]).to eq([1600, 2])
    expect(t[0xB068]).to eq([1600, 4])
    expect(t[0x7B18]).to eq([3200, 2])
    expect(t[0xDEA0]).to eq([3200, 4])
    expect(t[0x4C7C]).to eq([3200, 4])
  end

  it 'detects Sync-1 in a 64-bit shift register at either polarity' do
    # A(0xDEA0) | MARKER(0xA6C6AAAA) | ~A(0x215F) — canonical 3200/4 Sync-1
    buf = (0xDEA0 << 48) | (0xA6C6AAAA << 16) | 0x215F
    code, pol = PWN::SDR::Decoder::Flex.sync_check(buf: buf)
    expect(code).to eq(0xDEA0)
    expect(pol).to eq(0)
    code, pol = PWN::SDR::Decoder::Flex.sync_check(buf: ~buf & 0xFFFFFFFFFFFFFFFF)
    expect(code).to eq(0xDEA0)
    expect(pol).to eq(1)
  end

  # Regression: FLEX BCH bit-ordering is reversed vs POCSAG. FIW 0xF27C46AE
  # (cycle 10 / frame 70, live 929.625 MHz capture) must have zero syndrome.
  it 'computes BCH(31,21) syndrome with FLEX on-air bit ordering' do
    fiw = 0xF27C46AE
    expect(PWN::SDR::Decoder::Flex.bch_syn(word: fiw)).to eq(0)
    fixed, nerr = PWN::SDR::Decoder::Flex.bch_fix(word: fiw)
    expect(fixed).to eq(fiw)
    expect(nerr).to eq(0)
    # single-bit correction
    fixed, nerr = PWN::SDR::Decoder::Flex.bch_fix(word: fiw ^ (1 << 5))
    expect(fixed).to eq(fiw)
    expect(nerr).to eq(1)
  end

  # Regression: Demod#try_lock hardcoded a single A-word so it never locked on
  # anything but 1600/2. Synthesise the exact Sync-1 + FIW discriminator wave
  # for 3200/4 and require the demod to lock and decode cycle/frame.
  it 'locks on a synthesised 3200/4 Sync-1 and recovers cycle/frame from FIW' do
    rate = 48_000
    spb  = rate / 1600
    hi   = 0.9
    # bit convention (verified live): read_2fsk bit = (sample > 0)
    fiw = 0xF27C46AE
    fiw_bits = Array.new(32) { |i| (fiw >> i) & 1 } # LSB first on air
    # Sync-1 uses (sym < 2) → 1, i.e. NEGATIVE sample → bit=1
    sync_bits = 'DEA0A6C6AAAA215F'.chars.flat_map do |h|
      n = h.to_i(16)
      [3, 2, 1, 0].map { |i| (n >> i) & 1 }
    end
    lead   = Array.new(160) { |i| i.even? ? 1 : 0 } # dotting so PLL locks
    stream = lead + sync_bits + Array.new(16) { |i| i.even? ? 1 : 0 } + fiw_bits
    # sync-bit=1 → negative; FIW bit=1 → positive. Same wire, opposite conv:
    # a sample level v gives sync_bit=(v<0)?1:0 AND fiw_bit=(v>0)?1:0. So one
    # physical waveform carries both — encode via sync convention throughout,
    # FIW bits therefore need to be inverted before mapping to samples.
    fiw_phys = fiw_bits.map { |b| 1 - b }
    stream = lead + sync_bits + Array.new(16, 0) + fiw_phys
    samples = stream.flat_map { |b| Array.new(spb, b == 1 ? -hi : hi) }
    d = PWN::SDR::Decoder::Flex::Demod.new(rate: rate)
    d.feed(samples) { |_m| nil }
    expect(d.instance_variable_get(:@mode)).to eq([3200, 4])
    expect(d.instance_variable_get(:@cycle)).to eq(10)
    expect(d.instance_variable_get(:@frame)).to eq(70)
  end
end
