# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::Morse do
  it 'emits SOS at a word gap before EOF and rejects low-amplitude noise' do
    samples = %w[... --- ...].flat_map do |symbols|
      symbols.chars.flat_map { |s| Array.new(s == '.' ? 480 : 1440, 1.0) + Array.new(480, 0.0) } + Array.new(960, 0.0)
    end + Array.new(3360, 0.0)
    frames = []
    demod = described_class::Demod.new(rate: 8000)
    samples.each_slice(113) { |chunk| demod.feed(chunk) { |f| frames << f } }
    expect(frames.map { |f| f[:text] }).to eq(['SOS'])
    noise = Random.new(8)
    frames = []
    demod = described_class::Demod.new(rate: 8000)
    demod.feed(Array.new(8000) { noise.rand(-0.001..0.001) }) { |f| frames << f }
    demod.flush { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'never silently falls back to energy detection from decode' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(hash_including(fallback: :raise))
    described_class.decode(freq_obj: {}, file: '/offline/fixture.cs16', fallback: :detector)
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

  it 'flushes an unfinished final word once at EOF' do
    demod = described_class::Demod.new(rate: 8000)
    frames = []
    demod.feed(Array.new(480, 1.0) + Array.new(200, 0.0)) { |f| frames << f }
    expect(frames).to be_empty
    2.times { demod.flush { |f| frames << f } }
    expect(frames.map { |f| f[:text] }).to eq(['E'])
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::Morse
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::Morse
    expect(help_response).to respond_to :help
  end
end
