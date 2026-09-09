# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'digest'

describe 'normalized binary analysis' do
  it 'executes the actual radare2 read-only JSON interfaces when installed' do
    require 'pwn/plugins/radare2'
    skip 'r2 unavailable' unless PWN::Plugins::BinaryAnalysis.available?(name: 'r2')
    result = PWN::Plugins::Radare2.analyze_all(path: '/bin/true')
    expect(result[:backend]).to eq('radare2')
    expect(result[:functions]).not_to be_empty
    expect(PWN::Plugins::Radare2.list_functions(path: '/bin/true')[:data]).not_to be_empty
    expect(PWN::Plugins::Radare2.disasm_function(path: '/bin/true', function: 'main')[:data]).to include('ops')
    expect(PWN::Plugins::Radare2.xrefs(path: '/bin/true', addr: 'main')[:data]).to be_a(Array)
    expect(PWN::Plugins::Radare2.strings(path: '/bin/true')[:data]).not_to be_empty
    expect(PWN::Plugins::Radare2.imports(path: '/bin/true')[:data]).not_to be_empty
    expect { PWN::Plugins::Radare2.disasm_function(path: '/bin/true', function: 'main;!id') }.to raise_error(ArgumentError)
  end

  it 'reports an honest Ghidra fallback and uses the requested hash cache directory' do
    Dir.mktmpdir do |dir|
      result = PWN::Plugins::GhidraHeadless.analyze(path: '/bin/true', backend: 'binutils', cache_dir: dir)
      expect(result[:backend]).to eq('binutils')
      expect(result[:status]).to eq('degraded')
      expect(result[:decompiled][:functions]).to eq([])
      expect(result[:sha256]).to eq(Digest::SHA256.file('/bin/true').hexdigest)
      expect(result[:cached]).to eq(false)
    end
  end
  it 'analyzes an actual ELF with binutils without modifying it' do
    sha = Digest::SHA256.file('/bin/true').hexdigest
    result = PWN::Plugins::Radare2.analyze_all(path: '/bin/true', backend: 'binutils')
    expect(result[:backend]).to eq('binutils')
    expect(result[:strings]).not_to be_empty
    expect(result[:imports]).not_to be_empty
    expect(result[:risk_level]).to eq('low')
    expect(Digest::SHA256.file('/bin/true').hexdigest).to eq(sha)
  end
end
