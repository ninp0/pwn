# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::GQRX do
  it 'forwards realtime viewing controls to the selected decoder' do
    allow(described_class).to receive(:cmd).and_return('0')
    allow(described_class).to receive(:tune_to)
    allow(described_class).to receive(:measure_signal_strength).and_return(-60.0)
    callback = ->(_frame) {}
    output = StringIO.new
    expect(PWN::SDR::Decoder::ADSB).to receive(:decode).with(hash_including(on_frame: callback, output: output, interactive: false, duration: 0.2, log_file: false))
    described_class.init_freq(gqrx_sock: Object.new, freq: 1_090_000_000, decoder: :adsb,
                              keep_alive: true, interactive: false, on_frame: callback,
                              output: output, duration: 0.2, log_file: false)
  end

  it 'uses streaming rather than the one-shot sampler when a callback is requested' do
    allow(described_class).to receive(:cmd).and_return('0')
    allow(described_class).to receive(:tune_to)
    allow(described_class).to receive(:measure_signal_strength).and_return(-60.0)
    expect(PWN::SDR::Decoder::RDS).not_to receive(:sample)
    expect(PWN::SDR::Decoder::RDS).to receive(:decode).with(hash_including(interactive: false, duration: 0.2))
    described_class.init_freq(gqrx_sock: Object.new, freq: 100_000_000, decoder: :rds,
                              keep_alive: true, interactive: false, on_frame: ->(_frame) {}, duration: 0.2)
  end

  describe 'decoder option routing' do
    before do
      allow(described_class).to receive(:cmd).and_return('0')
      allow(described_class).to receive(:tune_to)
      allow(described_class).to receive(:measure_signal_strength).and_return(-60.0)
    end

    it 'keeps legacy noninteractive RDS sampling without explicit decoder context' do
      expect(PWN::SDR::Decoder::RDS).not_to receive(:decode)
      expect(PWN::SDR::Decoder::RDS).to receive(:sample).with(
        hash_including(settle_secs: 0.75)
      ).and_return({ pi: '1234' })
      result = described_class.init_freq(gqrx_sock: Object.new, freq: 100_000_000,
                                         decoder: :rds, interactive: false, keep_alive: true,
                                         settle_secs: 0.75, udp_port: 8000)
      expect(result[:sample]).to eq(pi: '1234')
    end

    { mode: :mpx, backend: :redsea, source: StringIO.new, file: '/offline/mpx.raw',
      sample_rate: 192_000, iq_format: :cs16, chunk_bytes: 1024,
      interval: 0.25, network_keys: {}, encrypted: false, output: nil }.each do |key, value|
      it "routes RDS through decode when only #{key} is explicitly supplied" do
        expect(PWN::SDR::Decoder::RDS).not_to receive(:sample)
        expect(PWN::SDR::Decoder::RDS).to receive(:decode) do |options|
          expect(options).to have_key(key)
          expect(options[key]).to equal(value)
          expect(options[:interactive]).to be(false)
        end
        described_class.init_freq({ gqrx_sock: Object.new, freq: 100_000_000,
                                    decoder: :rds, interactive: false, keep_alive: true }.merge(key => value))
      end
    end

    {
      p25: { mode: :pdu, sample_rate: 48_000 },
      bluetooth: { phy: :le1m, channel: 17, access_address: 0x12345678, crc_init: 0x123456, encrypted: false },
      zigbee: { network_keys: { 3 => 'k' * 16 }, link_key: 'l' * 16, security_level: 5 }
    }.each do |decoder, context|
      it "delivers #{decoder} context through the real decoder to the mocked IQ runner" do
        delivered = nil
        allow(PWN::SDR::Decoder::Base).to receive(:run_iq) { |options| delivered = options }
        supplied = context.merge(iq_format: :cs16, source: StringIO.new,
                                 on_frame: ->(_frame) {}, stop: -> { false }, log_file: false)
        expect do
          described_class.init_freq(supplied.merge(gqrx_sock: Object.new, freq: 2_405_000_000,
                                                   decoder: decoder, interactive: false, keep_alive: true))
        end.to output('').to_stdout.and output('').to_stderr
        supplied.each do |key, value|
          expect(delivered).to have_key(key)
          expect(delivered[key]).to equal(value)
        end
        expect(delivered[:demod]).not_to be_nil
        expect(delivered[:interactive]).to be(false)
      end
    end

    it 'lets the real RDS decoder reject an explicit invalid backend rather than sampling' do
      allow(PWN::SDR::Decoder::Base).to receive(:run_stream)
      expect(PWN::SDR::Decoder::RDS).not_to receive(:sample)
      expect do
        described_class.init_freq(gqrx_sock: Object.new, freq: 100_000_000,
                                  decoder: :rds, interactive: false, keep_alive: true, backend: :invalid)
      end.to raise_error(ArgumentError, 'backend must be :gqrx or :redsea')
    end

    PWN::SDR::Decoder::REGISTRY.each do |key, target|
      it "preserves supplied decoder options through #{key} -> #{target}" do
        decoder = PWN::SDR::Decoder.const_get(target)
        callback = ->(_frame) {}
        stop = -> { false }
        source = StringIO.new
        supplied = {
          mode: :iq, backend: :native, iq_format: :cs16,
          native_executable: '/offline/decoder', channel: 17,
          network_keys: { 3 => 'sensitive-network-key' }, link_key: 'sensitive-link-key',
          access_address: 0x12345678, crc_init: 0x123456, encrypted: false,
          uri: 'ip:offline', soapy_args: { driver: 'offline' },
          source: source, on_frame: callback, stop: stop, output: nil
        }
        delivered = nil
        allow(decoder).to receive(:decode) { |options| delivered = options }
        expect(decoder).not_to receive(:sample) if decoder.respond_to?(:sample)
        result = nil
        expect do
          result = described_class.init_freq(supplied.merge(
                                               gqrx_sock: Object.new, freq: 100_000_000, decoder: key,
                                               keep_alive: true, interactive: false,
                                               freq_obj: { freq: 'injected' }, decoder_module: Object.new
                                             ))
        end.to output('').to_stdout.and output('').to_stderr
        supplied.each do |option, value|
          expect(delivered).to have_key(option)
          expect(delivered[option]).to equal(value)
          expect(result).not_to have_key(option)
        end
        expect(delivered.keys).to match_array(supplied.keys + %i[freq_obj interactive])
        expect(delivered[:freq_obj]).to equal(result)
        expect(delivered[:freq_obj][:decoder_module]).to equal(decoder)
        expect(delivered[:freq_obj][:freq]).to eq(100_000_000)
        expect(delivered[:interactive]).to be(false)
      end
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::GQRX
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::GQRX
    expect(help_response).to respond_to :help
  end
end
