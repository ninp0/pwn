# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tmpdir'
require 'stringio'
require 'timeout'

describe PWN::SDR::Decoder::Tempest do
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

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'delivers decode callbacks and readable artifacts while its I/Q pipe is still open' do
    Dir.mktmpdir do |dir|
      reader, writer = IO.pipe
      events = Queue.new
      output = StringIO.new
      path = File.join(dir, 'preview.pgm')
      iq = ([0, 12_000, 24_000, 24_000, 12_000, 0] * 3).flat_map { |v| [v, 0] }
      opts = { sample_rate: 6, iq_format: :cs16, h_active: 2, h_total: 3,
               v_active: 2, v_total: 2, refresh: 1 }
      worker = Thread.new do
        described_class.decode(opts.merge(freq_obj: {}, source: reader, output: output,
                                          interactive: false, log_file: false, queue_size: 2,
                                          chunk_bytes: 997, out_path: path,
                                          on_frame: ->(event) { events << [event, File.binread(event[:pgm])] }))
      end
      Timeout.timeout(5) do
        writer.write(iq.pack('s<*'))
        event, image = events.pop
        expect(event[:protocol]).to eq('TEMPEST')
        expect(image).to start_with('P5')
        expect(worker).to be_alive
        expect(writer).not_to be_closed
        writer.close
        worker.value
      end
      expect(output.string.lines.map { |line| JSON.parse(line)['frames'] }).to eq([1, 2, 3])
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

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'lists named VESA raster modes including VGA 640x480@60' do
    modes = described_class.modes
    expect(modes).to be_a(Hash)
    vga = modes['vga_640x480_60']
    expect(vga[:h_active]).to eq(640)
    expect(vga[:h_total]).to eq(800)
    expect(vga[:v_active]).to eq(480)
    expect(vga[:v_total]).to eq(525)
    expect(vga[:refresh]).to eq(60.0)
  end

  it 'is registered so GQRX can dispatch decoder: :tempest' do
    expect(PWN::SDR::Decoder::REGISTRY[:tempest]).to eq(:Tempest)
    expect(PWN::SDR::Decoder.resolve(decoder: :tempest)).to eq(described_class)
  end

  it 'reconstructs a greyscale PGM from a synthetic I/Q raster' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'frame.pgm')
      h_active = 8
      h_total = 10
      v_active = 4
      v_total = 6
      frames = 1
      pixels = []
      v_total.times do |row|
        h_total.times do |col|
          in_picture = row < v_active && col < h_active
          mag = if in_picture && ((row + col) % 2).zero?
                  0.9
                elsif in_picture
                  0.4
                else
                  0.05
                end
          pixels << mag
        end
      end
      iq = pixels.flat_map { |mag| [mag, 0.0] }
      rate = h_total * v_total * 1.0
      out = described_class.reconstruct(
        iq: iq,
        sample_rate: rate,
        h_active: h_active,
        h_total: h_total,
        v_active: v_active,
        v_total: v_total,
        refresh: 1.0,
        frames: frames,
        out_path: path
      )
      expect(out[:path]).to eq(path)
      expect(File.file?(path)).to eq(true)
      header = File.binread(path, 64)
      expect(header).to start_with("P5\n#{h_active} #{v_active}\n255\n")
      expect(out[:width]).to eq(h_active)
      expect(out[:height]).to eq(v_active)
      expect(out[:frames]).to eq(1)
    end
  end

  it 'streams successive raster artifacts before finish across odd and fractional-rate chunks' do
    Dir.mktmpdir do |dir|
      opts = { h_active: 2, h_total: 3, v_active: 2, v_total: 2, refresh: 1,
               continuous: true, out_path: File.join(dir, 'live.pgm') }
      iq = ([0.0, 0.5, 1.0, 1.0, 0.5, 0.0] * 4).flat_map { |v| [v, 0.0] }
      results = [1, 7, 20, iq.length].map do |chunk_size|
        demod = described_class::Demod.new(opts)
        events = []
        iq.each_slice(chunk_size) do |chunk|
          demod.feed_iq(chunk, rate: 9) do |event|
            events << [event[:frames], File.binread(event[:pgm])]
          end
        end
        expect(events.length).to eq(2)
        expect(demod.instance_variable_get(:@mag_buf).length).to be < 6
        expect(demod.finish[:frames]).to eq(2)
        events
      end
      expect(results.uniq.length).to eq(1)
    end
  end

  it 'rejects invalid raster timing rather than accumulating an unrenderable frame' do
    [{ h_total: 0 }, { h_active: 900 }, { v_total: -1 }, { refresh: Float::INFINITY }].each do |opts|
      expect { described_class::Demod.new(opts) }.to raise_error(ArgumentError)
    end
  end

  it 'discards excess finite capture input and preserves its offline one-frame default' do
    Dir.mktmpdir do |dir|
      demod = described_class::Demod.new(h_active: 2, h_total: 2, v_active: 1, v_total: 1,
                                         refresh: 1, out_path: File.join(dir, 'finite.pgm'))
      events = []
      100.times { demod.feed_iq([0.0, 0.0, 1.0, 0.0], rate: 2) { |e| events << e } }
      expect(events.length).to eq(1)
      expect(demod.instance_variable_get(:@mag_buf)).to be_empty
      expect(File.binread(events.first[:pgm])).to eq("P5\n2 1\n255\n".b + [0, 255].pack('C*'))
      expect(demod.finish[:frames]).to eq(1)
    end
  end

  it 'decode hands an I/Q tempest demod to Base.run_iq' do
    freq_obj = { freq: 142_000_000, iq_file: '/tmp/capture.cu8' }
    expect(PWN::SDR::Decoder::Base).to receive(:run_iq).with(
      hash_including(
        freq_obj: freq_obj,
        protocol: 'TEMPEST',
        fm_demod: false
      )
    ).and_return(:ok)
    expect(described_class.decode(freq_obj: freq_obj, mode: 'vga_640x480_60')).to eq(:ok)
  end
end
