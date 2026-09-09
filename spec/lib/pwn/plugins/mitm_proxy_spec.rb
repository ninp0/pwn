# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/mitm_proxy'
require 'webrick'
require 'net/http'
require 'tmpdir'

RSpec.describe PWN::Plugins::MitmProxy do
  it 'tunnels CONNECT locally and marks captured entries as opaque rather than claiming TLS interception' do
    Dir.mktmpdir do |dir|
      origin = TCPServer.new('127.0.0.1', 0)
      worker = Thread.new do
        socket = origin.accept
        socket.write(socket.read(4))
        socket.close
      end
      proxy = described_class.start(har_path: File.join(dir, 'connect.har'))
      socket = TCPSocket.new('127.0.0.1', proxy[:port])
      socket.write("CONNECT 127.0.0.1:#{origin.addr[1]} HTTP/1.1\r\nHost: localhost\r\n\r\n")
      expect(socket.gets).to include('200')
      32.times do
        line = socket.gets
        break if line.nil? || line == "\r\n"
      end
      socket.write('ping')
      expect(socket.read(4)).to eq('ping')
      entry = described_class.entries(proxy: proxy).first
      expect(entry[:_capture]).to eq('opaque_connect')
      expect { described_class.http_replay(proxy: proxy, request_id: entry[:_request_id]) }.to raise_error(ArgumentError, /opaque CONNECT/)
    ensure
      socket&.close
      origin&.close
      worker&.join(2)
      described_class.stop(proxy: proxy) if proxy
    end
  end

  it 'captures real localhost HTTP requests to HAR and replays mutations with replacement rules' do
    Dir.mktmpdir do |dir|
      origin = WEBrick::HTTPServer.new(BindAddress: '127.0.0.1', Port: 0, Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
      origin.mount_proc('/') { |req, res| res.body = "#{req.request_method}:#{req.path}:#{req['x-test']}:#{req.body}" }
      thread = Thread.new { origin.start }
      proxy = described_class.start(har_path: File.join(dir, 'capture.har'), rules: [{ phase: 'response', field: 'body', match: 'GET', replace: 'captured' }])
      uri = URI("http://127.0.0.1:#{origin.config[:Port]}/one")
      client = Net::HTTP::Proxy('127.0.0.1', proxy[:port]).new(uri.host, uri.port)
      expect(client.get(uri.request_uri).body).to start_with('captured:/one')
      rows = described_class.entries(proxy: proxy)
      expect(rows.length).to eq(1)
      result = described_class.http_replay(proxy: proxy, request_id: rows.first[:_request_id], mutations: { method: 'POST', path: '/two', headers: { 'X-Test' => 'yes' }, body: 'payload' })
      expect(result[:response][:content][:text]).to eq('POST:/two:yes:payload')
      har = JSON.parse(File.read(proxy[:har_path]))
      expect(har['log']['entries'].length).to eq(2)
      expect(har['log']['entries'].last['request']['postData']['text']).to eq('payload')
      described_class.rules(proxy: proxy, rules: [{ phase: 'request', field: 'header:x-test', match: 'yes', replace: 'changed' }])
      mutated = described_class.http_replay(proxy: proxy, request_id: result[:_request_id], mutations: { query: { 'q' => 'a b' } })
      expect(mutated[:response][:content][:text]).to eq('POST:/two:changed:payload')
      expect(mutated[:request][:url]).to end_with('/two?q=a+b')
      expect(described_class.entries(proxy: proxy)[1][:request][:headers]).to include(name: 'x-test', value: 'yes')
    ensure
      described_class.stop(proxy: proxy) if proxy
      origin&.shutdown
      thread&.join(2)
      thread&.kill
    end
  end

  it 'stop returns even when the WEBrick accept loop does not exit on shutdown' do
    Dir.mktmpdir do |dir|
      proxy = described_class.start(har_path: File.join(dir, 'stop.har'))
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      out = described_class.stop(proxy: proxy)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      expect(out[:stopped]).to eq(true)
      expect(elapsed).to be < 8
    end
  end
end
