# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/sandbox/driver'
require 'open3'

RSpec.describe PWNSandboxDriver do
  it 'documents its standalone internal role' do
    expect(described_class.authors).to include('AUTHOR')
    expect { described_class.help }.to output(/standalone/).to_stdout
  end

  it 'reports malformed standalone JSON as a structured error' do
    runner = File.expand_path('../../../../../lib/pwn/plugins/sandbox/driver.rb', __dir__)
    output, error, status = Open3.capture3(RbConfig.ruby, runner, stdin_data: '{')
    expect(status.success?).to be(true), error
    expect(JSON.parse(output)).to include('ok' => false)
  end

  it 'plans restrictive Docker arguments and forced cleanup on backend failure (unit only)' do
    allow(described_class).to receive(:available?).with('docker').and_return(true)
    commands = []
    allow(described_class).to receive(:bounded) do |command, *_args|
      commands << command
      { exit: command[1] == 'run' ? 1 : 0, stderr: 'fixture failure', stdout: '', timed_out: false }
    end
    expect { described_class.execute(binary: '/bin/true', backend: 'docker') }.to raise_error(ArgumentError, /backend failed/)
    run = commands.find { |command| command[1] == 'run' }
    expect(run).to include('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pull=never', '--pids-limit=64', '--cpus=1', '--user=65534:65534', '--entrypoint=/usr/bin/ruby')
    expect(run[run.index('--memory') + 1]).to eq('256m')
    expect(run[run.index('--memory-swap') + 1]).to eq('256m')
    mount = run[run.index('--mount') + 1]
    expect(mount).to end_with(',dst=/artifacts,readonly')
    expect(commands.last).to eq(['docker', 'rm', '-f', run[run.index('--name') + 1]])
    expect(File.exist?(mount.split('src=').last.split(',').first)).to be(false)
  end
end
