# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe 'Capability broker transport' do
  it 'rejects oversized requests before opening a connection' do
    require 'pwn/plugins/capability_broker'
    expect(UNIXSocket).not_to receive(:open)
    result = PWN::Plugins::CapabilityBroker.request(operation: 'status', extra: 'x' * 100_000)
    expect(result).to include(ok: false, degraded: true, error: 'broker request too large')
  end

  it 'fails closed when the broker socket is absent without recommending privileged Ruby' do
    require 'pwn/plugins/capability_broker'
    result = PWN::Plugins::CapabilityBroker.request(operation: 'status', socket: '/nonexistent/pwn-capd.sock')
    expect(result[:ok]).to eq(false)
    expect(result[:degraded]).to eq(true)
    expect(result[:remediation]).to include('pwn-capd')
    expect(result[:remediation]).not_to include('setcap')
  end
end
