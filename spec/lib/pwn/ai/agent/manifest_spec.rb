# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/manifest'
require 'tmpdir'

RSpec.describe PWN::AI::Agent::Manifest do
  around do |example|
    Dir.mktmpdir('manifest-spec') do |dir|
      @dir = dir
      example.run
    end
  end

  def check(args = {}, **options)
    described_class.check({ name: 'shell', args: args, scope_policy: { allowed_cidrs: ['192.0.2.0/24', '2001:db8::/32'], allowed_domains: ['example.test', '*.example.test'], allowed_ports: [443, '8000-8100'], risk_gates: { high: 'auto' } }, audit_path: File.join(@dir, 'audit.jsonl') }.merge(options))
  end

  it 'allows subnet subsets, IPv6, exact domains, wildcard boundaries and port ranges' do
    expect(check({ target: '192.0.2.0/25', port: 443 })).to be_nil
    expect(check({ target: '2001:db8::1', ports: ['8001-8003'] })).to be_nil
    expect(check({ url: 'https://api.example.test/resource' })).to be_nil
    expect(check({ target: 'EXAMPLE.TEST.' })).to be_nil
  end

  it 'denies subnet overlap, domain suffix tricks and every disallowed target or port' do
    [{ target: '192.0.0.0/16' }, { target: 'evilexample.test' }, { targets: ['example.test', 'outside.test'] }, { url: 'https://example.test:444/' }, { port: '8100-8200' }].each do |args|
      expect(check(args)[:denied]).to eq('out_of_scope')
    end
  end

  it 'does not scope incidental strings in general-purpose Ruby code' do
    expect(check({ code: 'puts "https://outside.test ..."' }, name: 'pwn_eval')).to be_nil
  end

  it 'denies risk gates and malformed policies without prompting' do
    expect(check({}, scope_policy: { risk_gates: { high: 'deny' } }, approval_callback: ->(_) { raise 'unexpected' })[:denied]).to eq('risk_denied')
    expect(check({}, scope_policy: [])[:denied]).to eq('invalid_scope_policy')
  end

  it 'fails closed for an existing empty policy file rather than treating it as absent' do
    path = File.join(@dir, 'scope.yaml')
    File.write(path, '')
    expect(check({}, scope_policy: nil, scope_path: path)[:denied]).to eq('invalid_scope_policy')
  end
end
