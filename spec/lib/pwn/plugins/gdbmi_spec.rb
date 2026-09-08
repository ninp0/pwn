# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::GDBMI do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'break requires a location' do
    expect { described_class.break(location: '') }.to raise_error(/location/)
  end
end
