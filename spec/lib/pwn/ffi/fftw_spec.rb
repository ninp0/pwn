# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::FFTW do
  it 'handles a missing shared library without native calls' do
    allow(described_class).to receive(:available?).and_return(false)
    expect { described_class.rfft(samples: [1.0]) }.to raise_error(RuntimeError, /libfftw3f not available/)
  end

  it 'should display information for authors' do
    expect(PWN::FFI::FFTW).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::FFTW).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::FFTW).to respond_to :available?
  end

  it 'should compute an rfft impulse response', :fftw_integration do
    expect(described_class.available?).to be(true), 'Install libfftw3f and make it visible to the dynamic loader (PWN_TEST_FFTW=1).'

    spec = PWN::FFI::FFTW.rfft(samples: [1.0, 0, 0, 0, 0, 0, 0, 0])
    expect(spec.length).to eq(5) # n/2+1
    expect(spec[0][0]).to be_within(1e-5).of(1.0)
    expect(spec[0][1]).to be_within(1e-5).of(0.0)
  end
end
