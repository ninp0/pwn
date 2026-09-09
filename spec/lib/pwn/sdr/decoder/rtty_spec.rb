# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::RTTY do
  it 'never silently falls back to energy detection from decode' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(hash_including(fallback: :raise))
    described_class.decode(freq_obj: {}, file: '/offline/fixture.cs16', fallback: :detector)
  end

  it 'requires the complete 1.5-bit stop interval and emits a valid line before flush' do
    tone = lambda do |bit, count|
      Array.new(count) { |t| Math.sin(2 * Math::PI * (bit == 1 ? 1000 : 1500) * t / 8000) }
    end
    character = lambda do |code|
      ([0] + Array.new(5) { |i| code[i] }).flat_map { |b| tone.call(b, 160) } + tone.call(1, 240)
    end
    demod = described_class::Demod.new(rate: 8000, baud: 50, mark_hz: 1000, space_hz: 1500)
    frames = []
    samples = character.call(3) + character.call(2)
    samples.each_slice(113) { |s| demod.feed(s) { |f| frames << f } }
    expect(frames.map { |f| f[:text] }).to eq(['A'])
    demod = described_class::Demod.new(rate: 8000, baud: 50, mark_hz: 1000, space_hz: 1500)
    bad = character.call(3)[0...-80] + tone.call(0, 80)
    frames = []
    demod.feed(bad) { |f| frames << f }
    demod.flush { |f| frames << f }
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

  it 'processes long input before trimming and flushes the last partial line once' do
    rate = 8000
    samples = ([3] * 24).flat_map do |code|
      symbols = [0] + Array.new(5) { |i| (code >> i) & 1 } + [1]
      symbols.each_with_index.flat_map do |bit, i|
        Array.new(i == 6 ? 240 : 160) { |t| Math.sin(2 * Math::PI * (bit == 1 ? 1000 : 1500) * t / rate) }
      end
    end
    results = [samples.length, 113].map do |size|
      demod = described_class::Demod.new(rate: rate, baud: 50, mark_hz: 1000, space_hz: 1500)
      frames = []
      samples.each_slice(size) { |chunk| demod.feed(chunk) { |f| frames << f } }
      2.times { demod.flush { |f| frames << f } }
      frames.map { |f| f[:text] }.join
    end
    expect(results).to eq(['A' * 24, 'A' * 24])
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::RTTY
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::RTTY
    expect(help_response).to respond_to :help
  end
end
