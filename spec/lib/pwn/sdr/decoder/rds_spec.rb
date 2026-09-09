# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::RDS do
  it 'rejects native-backend implicit RF and invalid MPX inputs before spawning' do
    expect { described_class.decode(freq_obj: {}, backend: :redsea) }.to raise_error(ArgumentError, /exactly one MPX/)
    expect { described_class.decode(freq_obj: {}, backend: :redsea, source: 3) }.to raise_error(ArgumentError, /readable IO/)
    expect { described_class.decode(freq_obj: {}, backend: :redsea, file: '/not-opened', sample_rate: 48_000) }.to raise_error(ArgumentError, /sample rate/)
  end

  it 'surfaces native process failure instead of fabricating groups' do
    require 'timeout'
    expect do
      Timeout.timeout(3) do
        described_class.decode(freq_obj: {}, backend: :redsea, file: '/not-opened', executable: '/bin/false',
                               interactive: false, output: StringIO.new, log_file: false)
      end
    end.to raise_error(IOError, /redsea failed/)
  end

  it 'does not wait forever on blocked MPX input after the native process exits' do
    require 'timeout'
    reader, writer = IO.pipe
    expect do
      Timeout.timeout(3) do
        described_class.decode(freq_obj: {}, backend: :redsea, source: reader, executable: '/bin/false',
                               interactive: false, output: StringIO.new, log_file: false)
      end
    end.to raise_error(IOError, /redsea failed/)
    expect(reader).to be_closed
  ensure
    writer&.close unless writer&.closed?
    reader&.close unless reader&.closed?
  end

  it 'does not normalize malformed PI identifiers or mix text from different stations' do
    allow(PWN::SDR::GQRX).to receive(:cmd).and_return('13.1D')
    snap = described_class.send(:poll_once, sock: Object.new)
    expect(snap[:pi]).to eq('13.1D')
    result = described_class.send(:aggregate, samples: [
                                    { pi: '131D', ps: 'KBER', rt: 'First station' },
                                    { pi: 'ABCD', ps: 'OTHER', rt: 'A much longer second station text' }
                                  ], settle_secs: 1)
    expect(result).to include(pi: '131D', ps_name: 'KBER', radiotext: 'First station')
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

  it 'streams changed RDS snapshots through the shared runner and disables RDS on exit' do
    sock = Object.new
    controls = { on_frame: proc {}, output: false, interactive: false, duration: 0.1,
                 stop: proc { false }, queue_size: 2, log_file: false }
    allow(described_class).to receive(:enable_rds!).with(sock: sock).and_return(true)
    expect(described_class).to receive(:disable_rds!).with(sock: sock)
    expect(PWN::SDR::Decoder::Base).to receive(:run_stream) do |actual, &consume|
      expect(actual).to include(controls)
      expect(actual[:protocol]).to eq('RDS')
      frames = []
      emit = proc { |f| frames << f }
      consume.call({ pi: '0000', ps: '', rt: '' }, emit)
      2.times { consume.call({ pi: '131D', ps: 'KBER', rt: 'First' }, emit) }
      consume.call({ pi: '131D', ps: 'KBER', rt: 'Second' }, emit)
      expect(frames.map { |f| f[:rds_radiotext] }).to eq(%w[First Second])
    end
    require 'timeout'
    allow(described_class).to receive(:poll_once).and_return(pi: '0000', ps: '', rt: '')
    Timeout.timeout(0.5) { described_class.decode(controls.merge(freq_obj: { gqrx_sock: sock })) }
  end

  it 'delivers a callback before stopping even when the next RDS poll blocks' do
    require 'stringio'
    require 'timeout'
    sock = Object.new
    allow(described_class).to receive(:enable_rds!).and_return(true)
    expect(described_class).to receive(:disable_rds!).with(sock: sock)
    allow(described_class).to receive(:poll_once).and_return(pi: '131D', ps: 'KBER', rt: 'Live')
    frames = []
    Timeout.timeout(2) do
      described_class.decode(freq_obj: { gqrx_sock: sock }, interactive: false,
                             interval: 10, duration: 1, log_file: false, output: StringIO.new,
                             on_frame: proc { |f| frames << f }, stop: proc { !frames.empty? })
    end
    expect(frames.length).to eq(1)
    expect(frames.first).to include(rds_pi: '131D', rds_radiotext: 'Live')
    expect(frames.first).not_to have_key(:gqrx_sock)
  end

  it 'should display information for authors' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :help
  end

  it 'exposes a non-interactive .sample entry point (agents / automation)' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :sample
  end

  it 'exposes the interactive .decode entry point (TTY spinner)' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :decode
  end

  it 'aggregates RDS poll samples into pi/ps_name/radiotext/station' do
    samples = [
      { pi: '0000', ps: '', rt: '' },
      { pi: '131D', ps: 'KBER    ', rt: 'KBER 101' },
      { pi: '131D', ps: 'NIRVANA ', rt: 'KBER 101: Nirvana All Apologies' }
    ]
    result = PWN::SDR::Decoder::RDS.send(
      :aggregate,
      samples: samples,
      settle_secs: 8.0
    )
    expect(result[:pi]).to eq('131D')
    expect(result[:station]).to eq('KBER')
    expect(result[:radiotext]).to include('Nirvana')
    expect(result[:samples]).to eq(3)
    expect(result[:settle_secs]).to eq(8.0)
  end

  it 'returns an error Hash from .sample when gqrx_sock is missing' do
    # sample rescues ArgumentError only after resolve — missing sock raises first
    expect do
      PWN::SDR::Decoder::RDS.sample({})
    end.to raise_error(ArgumentError, /gqrx_sock/)
  end

  it 'returns an error Hash when the RDS backend refuses enable' do
    sock = Object.new
    # Stub GQRX.cmd so U RDS 1 fails
    allow(PWN::SDR::GQRX).to receive(:cmd).and_raise(StandardError.new('no rds'))
    result = PWN::SDR::Decoder::RDS.sample(gqrx_sock: sock, settle_secs: 0.5)
    expect(result).to be_a(Hash)
    expect(result[:error]).to match(/RDS not supported/)
    expect(result[:samples]).to eq(0)
  end
end
