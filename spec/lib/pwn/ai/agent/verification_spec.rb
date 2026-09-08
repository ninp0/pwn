# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'PWN::AI::Agent::Verification' do
  around do |example|
    Dir.mktmpdir('pwn-verification') do |root|
      @root = root
      example.run
    end
  end

  it 'checks actual JSON artifacts and counts missing files as failures rather than trusting supplied PASS' do
    File.write(File.join(@root, 'result.json'), JSON.generate({ value: 7 }))
    opts = { request: 'Produce the result', requirements: ['Produce the result'], root: @root }
    check = { requirement: 'Produce the result', kind: :json, path: 'result.json', expected: { value: 7 }, passed: true }
    expect(PWN::AI::Agent::Verification.run(opts.merge(checks: [check]))[:status]).to eq(:pass)
    File.write(File.join(@root, 'result.json'), 'PASS all done')
    expect(PWN::AI::Agent::Verification.run(opts.merge(checks: [check]))[:status]).to eq(:fail)
    File.unlink(File.join(@root, 'result.json'))
    expect(PWN::AI::Agent::Verification.run(opts.merge(checks: [check]))[:status]).to eq(:fail)
  end

  it 'accepts an explicitly expected empty artifact through the bounded reader' do
    File.write(File.join(@root, 'empty'), '')
    report = PWN::AI::Agent::Verification.run(
      request: 'Produce result', requirements: ['Produce result'], root: @root,
      checks: [{ requirement: 'Produce result', kind: :file, path: 'empty', expected: '' }]
    )
    expect(report[:status]).to eq(:pass)
  end

  it 'rejects symlink escapes without reading their contents' do
    Dir.mktmpdir('pwn-outside') do |outside|
      path = File.join(outside, 'result')
      File.write(path, 'private fixture')
      File.symlink(path, File.join(@root, 'result'))
      expect(File).not_to receive(:binread).with(File.join(@root, 'result'))
      report = PWN::AI::Agent::Verification.run(
        request: 'Produce result', requirements: ['Produce result'], root: @root,
        checks: [{ requirement: 'Produce result', kind: :file, path: 'result', expected: 'private fixture' }]
      )
      expect(report[:status]).to eq(:unknown)
    end
  end

  it 'rejects a directory swapped outside the root between path checks and reading' do
    Dir.mktmpdir('pwn-outside') do |outside|
      directory = File.join(@root, 'work')
      Dir.mkdir(directory)
      path = File.join(directory, 'result')
      File.write(path, 'safe')
      File.write(File.join(outside, 'result'), 'outside fixture')
      swapped = false
      swap = lambda do
        unless swapped
          File.rename(directory, "#{directory}-old")
          File.symlink(outside, directory)
          swapped = true
        end
      end
      allow(File).to receive(:size).and_wrap_original do |method, candidate|
        size = method.call(candidate)
        swap.call if candidate == path
        size
      end
      allow(File).to receive(:open).and_wrap_original do |method, *args, **kwargs, &block|
        swap.call if args.first == path
        method.call(*args, **kwargs, &block)
      end
      report = PWN::AI::Agent::Verification.run(
        request: 'Produce result', requirements: ['Produce result'], root: @root,
        checks: [{ requirement: 'Produce result', kind: :file, path: 'work/result', expected: 'outside fixture' }]
      )
      expect(swapped).to be(true)
      expect(report[:status]).to eq(:unknown)
      expect(report[:checks].first[:artifact]).to be_nil
    end
  end

  it 'does not certify a whole request when only one declared requirement has checks' do
    File.write(File.join(@root, 'answer.txt'), 'actual')
    report = PWN::AI::Agent::Verification.run(
      request: 'Write the answer and validate the service',
      requirements: ['Write the answer', 'validate the service'], root: @root,
      checks: [{ requirement: 'Write the answer', kind: :file, path: 'answer.txt', expected: 'actual' }]
    )
    expect(report[:status]).to eq(:unknown)
    expect(report[:missing]).to eq(['validate the service'])
    expect(report[:checks].first[:passed]).to be(true)
  end

  it 'checks final artifact state after test commands rather than certifying an earlier snapshot' do
    File.write(File.join(@root, 'result'), 'ok')
    report = PWN::AI::Agent::Verification.run(
      request: 'Produce result', requirements: ['Produce result'], root: @root, allow_commands: true,
      checks: [{ requirement: 'Produce result', kind: :file, path: 'result', expected: 'ok' },
               { requirement: 'Produce result', kind: :command, argv: [RbConfig.ruby, '-e', 'File.write("result", "wrong")'] }]
    )
    expect(report[:status]).to eq(:fail)
  end

  it 'executes opt-in test commands with bounded duration and treats timeouts as unknown' do
    opts = { request: 'Run tests', requirements: ['Run tests'], root: @root, allow_commands: true, timeout: 0.2 }
    check = { requirement: 'Run tests', kind: :command, argv: [RbConfig.ruby, '-e', 'puts "verified"'], expected: "verified\n" }
    expect(PWN::AI::Agent::Verification.run(opts.merge(checks: [check]))[:status]).to eq(:pass)
    check[:argv] = [RbConfig.ruby, '-e', 'exit 1']
    expect(PWN::AI::Agent::Verification.run(opts.merge(checks: [check]))[:status]).to eq(:fail)
    check[:argv] = [RbConfig.ruby, '-e', 'sleep 10']
    expect(PWN::AI::Agent::Verification.run(opts.merge(checks: [check]))[:status]).to eq(:unknown)
    expect(PWN::AI::Agent::Verification.run(opts.merge(allow_commands: false, checks: [check]))[:status]).to eq(:unknown)
  end

  it 'attributes a checked artifact only to its last observed writer rather than a later noop' do
    path = File.join(@root, 'result')
    File.write(path, 'ok')
    check = { requirement: 'Produce result', kind: :file, path: 'result', expected: 'ok' }
    snapshot = PWN::AI::Agent::Verification.snapshot(root: @root, checks: [check])
    actions = [{ action_id: 'writer', artifacts: snapshot }, { action_id: 'noop', artifacts: {} }]
    report = PWN::AI::Agent::Verification.run(request: 'Produce result', requirements: ['Produce result'], root: @root, checks: [check], actions: actions)
    expect(report[:attribution]).to eq(source: 'independent_verifier', verified_action_ids: ['writer'])
  end

  it 'cleans up descendants even after the direct command has exited' do
    script = 'pid = fork { STDIN.reopen(File::NULL); STDOUT.reopen(File::NULL, "w"); STDERR.reopen(File::NULL, "w"); sleep 0.3; File.write("escaped", "leak") }; File.write("child_pid", pid); exit! 0'
    report = PWN::AI::Agent::Verification.run(
      request: 'Run tests', requirements: ['Run tests'], root: @root, allow_commands: true,
      checks: [{ requirement: 'Run tests', kind: :command, argv: [RbConfig.ruby, '-e', script] }]
    )
    expect(report[:status]).to eq(:pass)
    sleep 0.6
    expect(File.exist?(File.join(@root, 'escaped'))).to be(false)
  ensure
    if File.exist?(File.join(@root, 'child_pid'))
      begin
        Process.kill('KILL', File.read(File.join(@root, 'child_pid')).to_i)
      rescue Errno::ESRCH
        nil
      end
    end
  end

  it 'never expands a single argv element as a shell command' do
    report = PWN::AI::Agent::Verification.run(
      request: 'Run tests', requirements: ['Run tests'], root: @root, allow_commands: true,
      checks: [{ requirement: 'Run tests', kind: :command, argv: ['printf bad > injected'] }]
    )
    expect(File.exist?(File.join(@root, 'injected'))).to be(false)
    expect(report[:status]).to eq(:unknown)
  end

  it 'checks only explicitly allowed service URLs against actual response contents' do
    require 'socket'
    server = TCPServer.new('127.0.0.1', 0)
    url = "http://127.0.0.1:#{server.addr[1]}/health"
    responder = Thread.new do
      client = server.accept
      client.gets
      client.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
      client.close
    end
    opts = { request: 'Validate service', requirements: ['Validate service'], root: @root,
             checks: [{ requirement: 'Validate service', kind: :http, url: url, expected: 'ok' }] }
    expect(PWN::AI::Agent::Verification.run(opts)[:status]).to eq(:unknown)
    expect(PWN::AI::Agent::Verification.run(opts.merge(allowed_urls: [url]))[:status]).to eq(:pass)
  ensure
    server&.close
    responder&.kill
    responder&.join
  end
end
