# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'stringio'
require 'timeout'

describe PWN::SDR::Decoder::APT do
  it 'never silently falls back to energy detection from decode' do
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(hash_including(fallback: :raise))
    described_class.decode(freq_obj: {}, file: '/offline/fixture.cs16', fallback: :detector)
  end

  it 'uses the NOAA 2080-word scan line and rejects unsynchronized silence' do
    expect(described_class::WORDS_PER_LINE).to eq(2080)
    expect(described_class::WORD_RATE).to eq(4160)
    Dir.mktmpdir do |dir|
      demod = described_class::Demod.new(out_path: File.join(dir, 'silence.pgm'))
      frames = []
      demod.feed(Array.new(96_000, 0.0)) { |f| frames << f }
      expect(frames).to be_empty
      expect(File.exist?(File.join(dir, 'silence.pgm'))).to eq(false)
    end
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
    authors_response = PWN::SDR::Decoder::APT
    expect(authors_response).to respond_to :authors
  end

  it 'publishes bounded rolling PGM lines from synthetic AM audio before finish' do
    rate = 48_000
    words = described_class::SYNC_A.map { |v| v.zero? ? 0.1 : 0.9 } + Array.new(described_class::WORDS_PER_LINE - described_class::SYNC_A.length, 0.4)
    samples = Array.new(rate * 3) do |n|
      amplitude = words[((n * described_class::WORD_RATE) / rate) % words.length]
      amplitude * Math.cos(2 * Math::PI * 2400 * n / rate)
    end
    Dir.mktmpdir do |dir|
      results = [1, 997, 8192, samples.length].map do |chunk_size|
        demod = described_class::Demod.new(rate: rate, out_path: File.join(dir, 'apt.pgm'), max_lines: 2)
        events = []
        samples.each_slice(chunk_size) do |chunk|
          demod.feed(chunk) do |event|
            image = File.binread(event[:pgm])
            expect(image).to start_with("P5\n2080 #{[event[:lines], 2].min}\n255\n")
            events << [event[:lines], image]
          end
        end
        expect(events.length).to be >= 4
        expect(demod.instance_variable_get(:@rows).length).to eq(2)
        expect(demod.instance_variable_get(:@word_buf).length).to be < described_class::WORDS_PER_LINE
        expect(demod.finish[:lines]).to eq(events.length)
        events
      end
      expect(results.uniq.length).to eq(1)
    end
  end

  it 'delivers decode callbacks and readable artifacts while its I/Q pipe is still open' do
    Dir.mktmpdir do |dir|
      reader, writer = IO.pipe
      events = Queue.new
      output = StringIO.new
      path = File.join(dir, 'preview.pgm')
      rate = 48_000
      phase = 0.0
      iq = Array.new(rate * 2) do |n|
        word = (n * described_class::WORD_RATE / rate) % described_class::WORDS_PER_LINE
        amplitude = if word < described_class::SYNC_A.length
                      described_class::SYNC_A[word].zero? ? 0.1 : 0.9
                    else
                      0.3
                    end
        phase += amplitude * Math.cos(2 * Math::PI * 2400 * n / rate)
        [(20_000 * Math.cos(phase)).round, (20_000 * Math.sin(phase)).round]
      end.flatten
      opts = { sample_rate: rate, iq_format: :cs16, max_lines: 2 }
      worker = Thread.new do
        described_class.decode(opts.merge(freq_obj: {}, source: reader, output: output,
                                          interactive: false, log_file: false, queue_size: 2,
                                          chunk_bytes: 997, out_path: path,
                                          on_frame: ->(event) { events << [event, File.binread(event[:pgm])] }))
      end
      Timeout.timeout(5) do
        writer.write(iq.pack('s<*'))
        event, image = events.pop
        expect(event[:protocol]).to eq('NOAA-APT')
        expect(image).to start_with('P5')
        expect(worker).to be_alive
        expect(writer).not_to be_closed
        writer.close
        worker.value
      end
      expect(output.string).to include('"pgm"')
    ensure
      writer&.close unless writer&.closed?
      worker&.kill
      worker&.join
      reader&.close unless reader&.closed?
    end
  end

  it 'forwards common streaming controls without replacing caller objects' do
    callback = ->(_frame) {}
    stop = -> { false }
    output = StringIO.new
    opts = { freq_obj: {}, source: :file, file: '/tmp/fixture.cu8', on_frame: callback,
             output: output, interactive: false, duration: 2, stop: stop,
             queue_size: 2, log_file: false, chunk_bytes: 17, iq_format: :cs16 }
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(hash_including(opts)).and_return(:ok)
    expect(described_class.decode(opts)).to eq(:ok)
  end

  it 'forwards native audio controls and configures its actual sample rate' do
    opts = { freq_obj: {}, rate: 96_000, on_frame: ->(_event) {}, output: StringIO.new,
             interactive: false, stop: -> { false }, duration: 1, log_file: false, queue_size: 1 }
    expect(PWN::SDR::Decoder::Base).to receive(:run_native).with(hash_including(opts)) do |args|
      expect(args[:demod].instance_variable_get(:@rate)).to eq(96_000)
      :ok
    end
    expect(described_class.decode(opts)).to eq(:ok)
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::APT
    expect(help_response).to respond_to :help
  end
end
