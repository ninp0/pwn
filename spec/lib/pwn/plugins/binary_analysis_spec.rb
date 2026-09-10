# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'digest'

describe 'normalized binary analysis' do
  it 'executes the actual radare2 read-only JSON interfaces on a controlled binary', :radare2_integration do
    expect(PWN::Plugins::BinaryAnalysis.available?(name: 'r2')).to be(true),
                                                                   'PWN_TEST_RADARE2=1 requires radare2: install r2 and add it to PATH.'
    expect(PWN::Plugins::BinaryAnalysis.available?(name: 'cc')).to be(true),
                                                                   'PWN_TEST_RADARE2=1 requires a C compiler: install cc and add it to PATH.'

    Dir.mktmpdir('pwn-radare2-spec-') do |dir|
      path = File.join(dir, 'fixture')
      source = File.join(dir, 'fixture.c')
      File.write(source, "#include <stdio.h>\nint main(void) { return puts(\"pwn radare2 fixture\") < 0; }\n")
      output, status = Open3.capture2e('cc', '-O0', '-g', '-o', path, source, chdir: dir)
      expect(status.success?).to be(true), "Unable to compile radare2 fixture with cc: #{output}"
      sha = Digest::SHA256.file(path).hexdigest

      result = PWN::Plugins::Radare2.analyze_all(path: path)
      expect(result).to include(backend: 'radare2', status: 'ok', sha256: sha)
      expect(result[:functions]).not_to be_empty
      expect(PWN::Plugins::Radare2.list_functions(path: path)[:data]).not_to be_empty
      disassembly = PWN::Plugins::Radare2.disasm_function(path: path, function: 'main')
      expect(disassembly).to include(backend: 'radare2', status: 'ok')
      expect(disassembly[:data]).to include('ops')
      expect(disassembly[:data]['ops']).not_to be_empty
      xrefs = PWN::Plugins::Radare2.xrefs(path: path, addr: 'main')
      expect(xrefs).to include(backend: 'radare2', status: 'ok')
      expect(xrefs[:data]).to be_a(Array)
      expect(PWN::Plugins::Radare2.strings(path: path)[:data]).not_to be_empty
      expect(PWN::Plugins::Radare2.imports(path: path)[:data]).not_to be_empty
      expect(Digest::SHA256.file(path).hexdigest).to eq(sha)
    end
  end

  it 'rejects command injection without requiring a native backend' do
    expect(PWN::Plugins::BinaryAnalysis).not_to receive(:run)
    expect { PWN::Plugins::Radare2.disasm_function(path: '/bin/true', function: 'main;!id') }.to raise_error(ArgumentError)
  end

  it 'falls back deterministically when radare2 is unavailable' do
    allow(PWN::Plugins::BinaryAnalysis).to receive(:available?).with(name: 'r2').and_return(false)
    result = PWN::Plugins::Radare2.analyze_all(path: '/bin/true')
    expect(result).to include(backend: 'binutils', status: 'degraded')
    expect(result[:strings]).not_to be_empty
    expect(result[:warnings]).not_to be_empty
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
