# frozen_string_literal: true

require 'spec_helper'
require 'socket'
require 'tmpdir'

RSpec.describe PWN::Plugins::Recon do
  it 'parses a real localhost TLS certificate without claiming trust validation' do
    require 'openssl'
    Dir.mktmpdir do |dir|
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=localhost')
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      context = OpenSSL::SSL::SSLContext.new
      context.cert = cert
      context.key = key
      tcp = TCPServer.new('127.0.0.1', 0)
      tls = OpenSSL::SSL::SSLServer.new(tcp, context)
      worker = Thread.new { tls.accept.close }
      result = described_class.run(target: '127.0.0.1', ports: [tcp.addr[1]], modules: ['tls'], root: dir)
      observation = result[:assets].first[:observations].first
      expect(observation[:certificate_sha256]).to eq(Digest::SHA256.hexdigest(cert.to_der))
      expect(observation[:subject]).to include('CN=localhost')
      expect(observation[:trust_verified]).to be(false)
    ensure
      tcp&.close
      worker&.join(2)
    end
  end

  it 'normalizes optional tool output and invokes ingestion only after a readable model exists' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:pipeline_command) do |opts|
        case opts[:argv].first
        when 'subfinder' then "api.fixture.test\napi.fixture.test\n"
        when 'nuclei' then "#{JSON.generate('host' => 'https://fixture.test', 'template-id' => 'fixture-check', 'info' => { 'severity' => 'info' })}\n"
        end
      end
      callback = lambda do |path, **_opts|
        expect(JSON.parse(File.read(path))['assets'].length).to eq(2)
        { status: 'ok', chunks: 2 }
      end
      result = described_class.run(target: 'fixture.test', modules: %w[subfinder nuclei], root: dir, ingest: true, ingestor: callback)
      expect(result[:ingestion]).to include(status: 'ok')
      expect(result[:assets].map { |row| row[:address] }).to contain_exactly('api.fixture.test', 'fixture.test')
      expect(result[:assets].all? { |row| row[:id].start_with?('asset-') }).to be(true)
      expect(result[:assets].last[:observations].first).not_to have_key(:finding_id)
    end
  end

  it 'reports missing optional binaries and ingestion errors without losing collected assets' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:pipeline_command).and_raise(Errno::ENOENT, 'fixture missing executable')
      result = described_class.run(target: 'fixture.test', modules: ['subfinder'], root: dir, ingest: true,
                                   ingestor: ->(*) { raise 'fixture embedding unavailable' })
      expect(result[:modules].first[:status]).to eq('unavailable')
      expect(result[:ingestion][:status]).to eq('error')
      expect(File.file?(result[:path])).to be(true)
    end
  end

  it 'runs real localhost banner and nmap probes and persists stable shared asset IDs' do
    Dir.mktmpdir do |dir|
      server = TCPServer.new('127.0.0.1', 0)
      port = server.addr[1]
      worker = Thread.new do
        loop do
          client = server.accept
          begin
            client.write("PWN localhost fixture\r\n")
          rescue StandardError
            nil
          end
          client.close
        end
      rescue IOError, Errno::EBADF
        nil
      end
      options = { target: '127.0.0.1', modules: %w[banner nmap], ports: [port], engagement_id: 'fixture', root: dir, timeout: 10 }
      result = described_class.run(options)
      expect(result[:modules].map { |row| row[:status] }).to eq(%w[ok ok])
      asset = result[:assets].find { |row| row[:port] == port }
      expect(asset[:observations].map { |row| row[:source] }).to contain_exactly('banner', 'nmap')
      expect(asset[:observations].first[:banner]).to include('PWN localhost fixture')
      persisted = JSON.parse(File.read(result[:path]))
      expect(persisted['assets'].first['id']).to eq(asset[:id])
      again = described_class.run(options.merge(modules: ['banner']))
      expect(again[:assets].map { |row| row[:id] }).to eq([asset[:id]])
      expect(again[:assets].first[:observations].map { |row| row[:source] }).to include('nmap', 'banner')
      expect(again[:assets].first[:evidence_paths].all? { |path| File.file?(path) }).to be(true)

      refused = TCPServer.new('127.0.0.1', 0)
      closed_port = refused.addr[1]
      refused.close
      partial = described_class.run(options.merge(modules: ['banner'], ports: [closed_port, port]))
      expect(partial[:modules].first[:status]).to eq('partial')
      expect(partial[:modules].first[:errors].first[:port]).to eq(closed_port)
      expect(partial[:assets].find { |row| row[:port] == port }[:id]).to eq(asset[:id])

      # Exercise the real P3 SQLite fallback and P10 export on observed localhost evidence.
      rag_opts = { session_id: 'fixture', root: File.join(dir, 'embeddings'), endpoint: 'http://127.0.0.1:1' }
      ingestion = PWN::AI::Context.ingest({ path: again[:path] }.merge(rag_opts))
      expect(ingestion[:chunks]).to be > 0
      retrieved = PWN::AI::Context.retrieve({ query: asset[:id] }.merge(rag_opts))
      expect(retrieved[:context]).to include(asset[:id], again[:path])
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      finding = PWN::Plugins::Findings.record_structured(
        title: 'Local fixture banner', cwe: 'CWE-200', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        cvss_score: 5.3, affected_asset: asset[:id], evidence_paths: asset[:evidence_paths],
        poc: "nc 127.0.0.1 #{port}", attack_chain_refs: [], remediation: 'Disable the fixture.', confidence: 1,
        engagement_id: 'fixture'
      )
      paths = PWN::Plugins::Findings.render(dir_path: dir, engagement_id: 'fixture')
      rendered = JSON.parse(File.read(paths[:json]))['findings'].first
      expect(rendered['affected_asset']).to eq(asset[:id])
      expect(rendered['id']).to eq(finding[:id])
    ensure
      server&.close
      worker&.join(2)
    end
  end
end
