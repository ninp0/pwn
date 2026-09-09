# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::Pager do
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

  it 'flushes a trailing POCSAG message through the composite' do
    demod = described_class::Demod.new
    words = [PWN::SDR::Decoder::POCSAG::FSC, 0xf6374, 0x891a2bfa]
    samples = words.flat_map { |w| w.to_s(2).rjust(32, '0').chars.flat_map { |b| Array.new(40, b == '1' ? 1.0 : -1.0) } }
    frames = []
    demod.feed(samples) { |f| frames << f }
    2.times { demod.flush { |f| frames << f } }
    expect(frames.select { |f| f[:baud] == 1200 && f[:address] == 984 }.length).to eq(1)
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::Pager
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::Pager
    expect(help_response).to respond_to :help
  end
end
