# frozen_string_literal: true

require 'socket'
require 'json'
require 'timeout'

module PWN
  module Plugins
    # Bounded, peer-authenticated client; never starts or elevates the helper.
    module CapabilityBroker
      public_class_method def self.request(opts = {})
        path = opts[:socket] || ENV.fetch('PWN_CAPD_SOCKET', '/run/pwn-capd/control.sock')
        Timeout.timeout(35) do
          UNIXSocket.open(path) do |socket|
            _pid, uid, = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_PEERCRED).unpack('iii')
            raise 'untrusted broker peer' unless [0, Process.uid].include?(uid)

            socket.puts(JSON.generate(opts.except(:socket)))
            line = socket.gets(2_000_001)
            raise 'invalid broker response' unless line && line.bytesize <= 2_000_000 && line.end_with?("\n")

            JSON.parse(line, symbolize_names: true)
          end
        end
      rescue StandardError => e
        { ok: false, degraded: true, error: e.message,
          remediation: "sudo /usr/local/libexec/pwn-capd --uid #{Process.uid} --interface lo" }
      end

      public_class_method def self.authors
        'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
      end

      public_class_method def self.help
        puts "USAGE:
          # Send a typed bounded request to the authenticated local broker.
          #{self}.request(
            operation: 'required - status, raw_send, capture, arp or nd',
            socket: 'optional - local broker Unix socket path',
            iface: 'optional - administrator-allowed network interface',
            frame: 'optional - base64 Ethernet frame for raw_send',
            address: 'optional - typed IP address for neighbor lookup',
            count: 'optional - maximum packets to capture',
            timeout: 'optional - capture seconds budget'
          )
          # Print the module author information.
          #{self}.authors
        "
      end
    end
  end
end
