# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::TransparentBrowser do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::TransparentBrowser
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::TransparentBrowser
    expect(help_response).to respond_to :help
  end

  it 'hooks a capture proxy descriptor into browser transport' do
    require 'pwn/plugins/mitm_proxy'
    Dir.mktmpdir do |dir|
      proxy = PWN::Plugins::MitmProxy.start(har_path: File.join(dir, 'browser.har'))
      original = RestClient.proxy
      browser = described_class.open(browser_type: :rest, capture_proxy: proxy)
      expect(RestClient.proxy).to eq(proxy[:url])
      expect(browser[:capture_proxy]).to eq(proxy)
    ensure
      RestClient.proxy = original
      PWN::Plugins::MitmProxy.stop(proxy: proxy) if proxy
    end
  end

  it 'routes Chrome loopback traffic through the capture proxy instead of bypassing it' do
    proxy = { id: 'fixture', url: 'http://127.0.0.1:8888' }
    driver = double('driver')
    allow(Watir::Browser).to receive(:new).with(driver).and_return(Object.new)
    %i[chrome headless_chrome].each do |type|
      expect(Selenium::WebDriver).to receive(:for) do |engine, options:|
        expect(engine).to eq(:chrome)
        expect(options.args).to include('--proxy-server=http://127.0.0.1:8888', '--proxy-bypass-list=<-loopback>')
        driver
      end
      described_class.open(browser_type: type, capture_proxy: proxy)
    end
  end

  it 'caps Watir element waits and Selenium page_load / script timeouts' do
    src = File.read(described_class.method(:open).source_location.first)
    expect(src).to match(/Watir\.default_timeout\s*=\s*15/)
    expect(src).not_to match(/Watir\.default_timeout\s*=\s*900/)
    expect(src).to match(/page_load\s*=\s*45/)
    expect(src).to match(/script\s*=\s*30/)
  end

  it 'evidence! writes screenshot, dom, and har files' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      browser = Object.new
      def browser.html
        '<html/>'
      end
      out = described_class.evidence!(browser_obj: { browser: browser }, label: 't', session_id: 's')
      expect(File.file?(out[:screenshot])).to be true
      expect(File.file?(out[:dom])).to be true
      expect(File.file?(out[:har])).to be true
    end
  end
end
