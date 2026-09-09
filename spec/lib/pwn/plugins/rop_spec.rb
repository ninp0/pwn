# frozen_string_literal: true

require 'spec_helper'

describe 'ROP normalized adapter' do
  it 'enumerates actual ELF gadgets and applies constraints without execution' do
    require 'pwn/plugins/rop'
    expect(PWN::Plugins.const_defined?(:ROP)).to eq(true)
    result = PWN::Plugins::ROP.gadgets(path: '/bin/true', constraints: { contains: 'ret', max_instructions: 2 })
    expect(result[:gadgets]).not_to be_empty
    expect(result[:gadgets]).to all(include(:gadget, :address, :regs_clobbered))
    expect(result[:gadgets].all? { |row| row[:gadget].split(';').length <= 2 }).to eq(true)
  end
end
