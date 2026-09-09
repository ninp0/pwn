# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::POCSAG do
  it 'does not emit a tone or partial text from truncated legacy bit input' do
    bits = [described_class::FSC, protected_word(123 << 2)].flat_map { |w| w.to_s(2).rjust(32, '0').chars.map(&:to_i) } + [1, 0, 1]
    frames = []
    described_class.decode_bits(bits: bits, baud: 1200) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'never silently falls back to energy detection from decode' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(hash_including(fallback: :raise))
    described_class.decode(freq_obj: {}, file: '/offline/fixture.cs16', fallback: :detector)
  end

  def protected_word(data)
    word = data << 11
    remainder = word >> 1
    30.downto(10) { |i| remainder ^= 0x769 << (i - 10) if remainder[i] == 1 }
    word |= remainder << 1
    word | (word.digits(2).sum & 1)
  end

  it 'corrects all one and two bit errors in independently specified POCSAG codewords' do
    # ITU-R M.584 fixed idle and synchronization words, not decoder-generated parity.
    [0x7A89C197, 0x7CD215D8].each do |word|
      expect(described_class.correct_word(word: word)).to eq(word)
      32.times do |i|
        expect(described_class.correct_word(word: word ^ (1 << i))).to eq(word)
        ((i + 1)...32).each do |j|
          expect(described_class.correct_word(word: word ^ (1 << i) ^ (1 << j))).to eq(word)
        end
      end
      expect(described_class.correct_word(word: word ^ 7)).to be_nil
    end
    expect(described_class.correct_word(word: -1)).to be_nil
  end

  it 'recovers damaged address and message words before emitting a terminated message' do
    address = protected_word(123 << 2)
    message = protected_word(0x100000 | 0x12345)
    [1, 2, 3, 0x80000001].each do |mask|
      frames = []
      stream = described_class::BitStream.new(baud: 1200)
      stream.feed([0x7CD215D8, address ^ mask, message ^ mask, 0x7A89C197].flat_map { |w| w.to_s(2).rjust(32, '0').chars.map(&:to_i) }) { |f| frames << f }
      expect(frames.length).to eq(1)
      expect(frames.first).to include(address: 984, message: '84 2*')
    end
  end

  it 'rejects uncorrectable BCH words and partial codewords without emitting a message' do
    address = protected_word(123 << 2)
    message = protected_word(0x100000 | 0x12345)
    [address ^ 7, address ^ 0xE0000000].each do |bad|
      frames = []
      stream = described_class::BitStream.new(baud: 1200)
      stream.feed([described_class::FSC, bad, message, described_class::IDLE_CW].flat_map { |w| w.to_s(2).rjust(32, '0').chars.map(&:to_i) }) { |f| frames << f }
      expect(frames).to be_empty
    end
    frames = []
    stream = described_class::BitStream.new(baud: 1200)
    stream.feed([described_class::FSC, address].flat_map { |w| w.to_s(2).rjust(32, '0').chars.map(&:to_i) } + [1, 0]) { |f| frames << f }
    stream.flush { |f| frames << f }
    expect(frames).to be_empty
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

  it 'emits a split message at its idle terminator, without replaying carry' do
    demod = described_class::Demod.new(rate: 48_000)
    words = [described_class::FSC, protected_word(123 << 2), protected_word(0x100000 | 0x12345), described_class::IDLE_CW]
    samples = words.flat_map { |w| w.to_s(2).rjust(32, '0').chars.flat_map { |b| Array.new(40, b == '1' ? 1.0 : -1.0) } }
    frames = []
    samples.each_slice(123) { |chunk| demod.feed(chunk) { |f| frames << f } }
    hits = frames.select { |f| f[:baud] == 1200 && f[:address] == 984 }
    expect(hits.length).to eq(1)
    expect(hits.first[:type]).to eq('Numeric')
    demod.feed(Array.new(4000, 1.0)) { |f| frames << f }
    expect(frames.select { |f| f[:baud] == 1200 && f[:address] == 984 }.length).to eq(1)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::POCSAG
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::POCSAG
    expect(help_response).to respond_to :help
  end
end
