# frozen_string_literal: true

require 'spec_helper'

describe 'Native Ruby helper runtime dependencies' do
  let(:root) { File.expand_path('../..', __dir__) }

  it 'does not ship Python implementations for first-party runtime helpers' do
    python_helpers = Dir.glob(File.join(root, 'lib', '**', '*.py'))
    expect(python_helpers).to eq([]), "First-party runtime helpers must be Ruby: #{python_helpers.join(', ')}"
  end

  it 'does not require Python to execute first-party helper tests' do
    expect(Dir.glob(File.join(root, 'spec', '**', '*.py'))).to eq([])
  end

  it 'does not hide a Python interpreter behind the broker or sandbox Ruby entry points' do
    %w[bin/pwn-capd lib/pwn/plugins/sandbox.rb].each do |relative|
      source = File.read(File.join(root, relative))
      expect(source).not_to match(%r{(?:/usr/bin/|/usr/local/bin/)?python[23]?\b|(?:daemon|driver)\.py})
    end
  end
end
