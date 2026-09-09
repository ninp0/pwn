# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::MonkeyPatch do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::MonkeyPatch
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::MonkeyPatch
    expect(help_response).to respond_to :help
  end

  it 'routes CTRL+D in pwn-ai to leave_special_mode instead of exiting Pry' do
    src = File.read(described_class.method(:pry).source_location.first)
    expect(src).to include('leave_special_mode!')
    expect(src).to include('config.pwn_ai')
    expect(src).to include('control_d_handler')
  end
end
