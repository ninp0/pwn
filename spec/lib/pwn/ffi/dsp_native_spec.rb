# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ffi/dsp_native'
require 'open3'
require 'tmpdir'

describe PWN::FFI::DSPNative do
  it 'exposes availability, authors and documented public APIs' do
    expect([true, false]).to include(described_class.available?)
    expect(described_class.authors).to include('AUTHOR(S)')
    expect { described_class.help }.to output(/process_iq/).to_stdout
  end

  it 'loads without compiling when the bundled shared object is absent' do
    Dir.mktmpdir('pwn-dsp-absent') do |dir|
      source = File.expand_path('../../../../lib/pwn/ffi/dsp_native.rb', __dir__)
      target = File.join(dir, 'dsp_native.rb')
      File.write(target, File.read(source))
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-r', target, '-e', 'abort "unexpected native backend" if PWN::FFI::DSPNative.available?; puts PWN::FFI::DSPNative.load_error.class')
      expect(status.success?).to be(true), stderr
      expect(stdout).to include('LoadError')
      expect(Dir.children(dir)).to eq(['dsp_native.rb'])
    end
  end

  if described_class.available? || ENV['PWN_TEST_DSP_NATIVE'] == '1'
    it 'matches an independent direct DFT oracle for phase, padding and truncation' do
      input = [0.2, -0.7, 0.4, 0.1, -0.9, 0.5, 0.0, -0.3]
      [1, 2, 4, 8, 16].each do |n|
        expected = Array.new(n) do |k|
          sum = Complex(0.0, 0.0)
          n.times do |j|
            phase = -2.0 * Math::PI * j * k / n
            sum += Complex(input[2 * j].to_f, input[(2 * j) + 1].to_f) * Complex(Math.cos(phase), Math.sin(phase))
          end
          sum.abs
        end
        actual = described_class.cfft_mag(iq: input, n: n)
        actual.zip(expected).each { |a, b| expect(a).to be_within(1e-12).of(b) }
      end
    end

    it 'validates complete pairs and FFT size before entering C' do
      expect { described_class.process_iq(data: 'x', format: :cs16le) }.to raise_error(ArgumentError)
      expect { described_class.process_iq(data: '', format: :unknown) }.to raise_error(KeyError)
      expect { described_class.cfft_mag(iq: [], n: 3) }.to raise_error(ArgumentError)
      expect { described_class.cfft_mag(iq: [], n: 0) }.to raise_error(ArgumentError)
      expect(described_class.process_iq(data: '', previous: [0.2, 0.3])).to eq(samples: [], previous: [0.2, 0.3])
      expect(described_class.cfft_mag(iq: [1.0, 0.0], n: 8)).to eq(Array.new(8, 1.0))
    end
  end
end
