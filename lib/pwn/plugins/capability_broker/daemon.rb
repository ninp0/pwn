# frozen_string_literal: true

require 'socket'
require 'json'
require 'ipaddr'
require 'timeout'
require 'io/wait'
require 'ffi'
require 'fileutils'
require 'optparse'
require 'pwn/plugins/capability_broker'

module PWN
  module Plugins
    module CapabilityBroker
      # Linux-only, bounded network capability service. Never acquires privileges.
      module Daemon
        extend ::FFI::Library

        ffi_lib ::FFI::Library::LIBC
        attach_function :prctl, %i[int ulong ulong ulong ulong], :int
        attach_function :capget, %i[pointer pointer], :int
        attach_function :capset, %i[pointer pointer], :int
        private_class_method :prctl, :capget, :capset

        public_class_method def self.dispatch(opts = {})
          request = opts[:request]
          raise ArgumentError, 'peer UID denied' unless opts[:peer_uid] == opts[:uid]
          raise ArgumentError, 'object required' unless request.is_a?(Hash)

          operation = request['operation']
          raise ArgumentError, 'operation denied' unless %w[status raw_send capture arp nd].include?(operation)

          interfaces = opts.fetch(:interfaces)
          if operation == 'status'
            caps = File.read('/proc/self/status')[/^CapEff:\s+(\h+)/, 1].to_i(16)
            missing = { 13 => 'CAP_NET_RAW', 12 => 'CAP_NET_ADMIN' }.filter_map { |bit, name| name if caps.nobits?(1 << bit) }
            return { ok: true, backend: 'pwn-capd', missing: missing, interfaces: interfaces }
          end
          raise ArgumentError, 'interface denied' unless interfaces.include?(request['iface'])

          case operation
          when 'raw_send' then raw_send(request: request)
          when 'capture' then capture(request: request)
          when 'arp', 'nd' then neighbors(request: request)
          end
        rescue StandardError => e
          { ok: false, degraded: true, error: e.message }
        end

        private_class_method def self.neighbors(opts = {})
          request = opts[:request]
          text = request.fetch('address')
          raise ArgumentError, 'single IP address required' unless text.is_a?(String) && !text.include?('/')

          address = IPAddr.new(text)
          ipv4 = request['operation'] == 'arp'
          raise ArgumentError, 'address family mismatch' unless address.ipv4? == ipv4

          output = bounded_command(argv: ['/usr/sbin/ip', '-j', ipv4 ? '-4' : '-6', 'neigh', 'show', 'to', address.to_s, 'dev', request['iface']])
          { ok: true, backend: 'pwn-capd', neighbors: JSON.parse(output) }
        end

        private_class_method def self.bounded_command(opts = {})
          reader, writer = IO.pipe
          pid = Process.spawn({ 'PATH' => '/usr/sbin:/usr/bin', 'LANG' => 'C' }, *opts[:argv], in: File::NULL, out: writer, err: File::NULL, unsetenv_others: true, close_others: true)
          writer.close
          Timeout.timeout(opts.fetch(:timeout, 5)) do
            output = reader.read(1_000_001).to_s
            raise IOError, 'neighbor output too large' if output.bytesize > 1_000_000

            _, status = Process.wait2(pid)
            pid = nil
            raise IOError, 'neighbor query failed' unless status.success?

            output
          end
        ensure
          reader&.close
          writer&.close unless writer&.closed?
          if pid
            begin
              Process.kill('KILL', pid)
            rescue Errno::ESRCH
              nil
            end
            begin
              Process.wait(pid)
            rescue Errno::ECHILD
              nil
            end
          end
        end

        private_class_method def self.packet_socket(opts = {})
          iface = opts[:iface]
          index = Socket.getifaddrs.find { |entry| entry.name == iface }&.ifindex
          raise ArgumentError, 'unknown interface' unless index

          raw = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, [3].pack('n').unpack1('S'))
          raw.bind([Socket::AF_PACKET, 3, index, 0, 0, 0, "\0" * 8].pack('S n i S C C a8'))
          raw
        rescue StandardError
          raw&.close
          raise
        end

        private_class_method def self.raw_send(opts = {})
          request = opts[:request]
          frame = request.fetch('frame').unpack1('m0')
          raise ArgumentError, 'frame size must be 14..65535' unless (14..65_535).cover?(frame.bytesize)

          raw = packet_socket(iface: request['iface'])
          raise Timeout::Error, 'send timed out' unless raw.wait_writable(5)

          { ok: true, backend: 'pwn-capd', bytes: raw.sendmsg_nonblock(frame) }
        ensure
          raw&.close
        end

        private_class_method def self.capture(opts = {})
          request = opts[:request]
          count = Integer(request.fetch('count', 8))
          seconds = Float(request.fetch('timeout', 5))
          raise ArgumentError, 'capture budget out of range' unless (1..128).cover?(count) && seconds.positive? && seconds <= 30

          data = [0xa1b2c3d4, 2, 4, 0, 0, 4096, 1].pack('VvvVVVV')
          captured = 0
          raw = packet_socket(iface: request['iface'])
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
          while captured < count
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break unless remaining.positive? && raw.wait_readable(remaining)

            frame = raw.recv_nonblock(4096, exception: false)
            next if frame == :wait_readable

            now = Time.now
            data << [now.to_i, now.usec, frame.bytesize, frame.bytesize].pack('V4') << frame
            captured += 1
          end
          { ok: true, backend: 'pwn-capd', count: captured, pcap: [data].pack('m0') }
        ensure
          raw&.close
        end

        public_class_method def self.serve_client(opts = {})
          client = opts.fetch(:client)
          Timeout.timeout(opts.fetch(:timeout, 35)) do
            _pid, uid, = client.getsockopt(Socket::SOL_SOCKET, Socket::SO_PEERCRED).unpack('iii')
            begin
              raise ArgumentError, 'peer UID denied' unless uid == opts[:uid]

              line = client.gets(100_001)
              raise ArgumentError, 'request too large or incomplete' unless line && line.bytesize <= 100_000 && line.end_with?("\n")

              response = dispatch(request: JSON.parse(line), peer_uid: uid, uid: opts[:uid], interfaces: opts[:interfaces])
            rescue ArgumentError, JSON::ParserError => e
              response = { ok: false, degraded: true, error: e.message }
            end
            client.write(JSON.generate(response) << "\n")
          end
        end

        # Native-width pointers and unsigned 32-bit capability words.
        private_class_method def self.capability_state
          raise SystemCallError.new('cannot set no_new_privs', ::FFI.errno) unless prctl(38, 1, 0, 0, 0).zero?

          header = ::FFI::MemoryPointer.new(:uint32, 2)
          header.write_array_of_uint32([0x20080522, 0])
          data = ::FFI::MemoryPointer.new(:uint32, 6)
          raise SystemCallError.new('cannot read capabilities', ::FFI.errno) unless capget(header, data).zero?

          effective, permitted = data.read_array_of_uint32(6)
          mask = (1 << 12) | (1 << 13)
          data.write_array_of_uint32([effective & mask, permitted & mask, 0, 0, 0, 0])
          [header, data]
        end

        private_class_method def self.drop_capabilities(opts = {})
          state = opts[:state]
          raise SystemCallError.new('cannot drop excess capabilities', ::FFI.errno) unless capset(*state).zero?
        end

        public_class_method def self.run(opts = {})
          uid = opts[:uid]
          interfaces = opts.fetch(:interfaces)
          path = opts.fetch(:socket, '/run/pwn-capd/control.sock')
          raise ArgumentError, 'UID and at least one interface required' unless uid.is_a?(Integer) && uid >= 0 && interfaces.is_a?(Array) && !interfaces.empty? && interfaces.all? { |iface| iface.is_a?(String) && iface.match?(/\A[a-zA-Z0-9_.:-]{1,15}\z/) }

          state = capability_state
          parent = File.dirname(path)
          FileUtils.mkdir_p(parent, mode: 0o755)
          info = File.stat(parent)
          raise ArgumentError, 'socket directory must be owned by daemon and not group/world writable' unless info.uid == Process.euid && info.mode.nobits?(0o022)

          begin
            old_umask = File.umask(0o177)
            server = UNIXServer.new(path) # Existing paths and symlinks are refused.
            identity = File.lstat(path)
          ensure
            File.umask(old_umask)
          end
          File.chown(uid, -1, path)
          drop_capabilities(state: state)
          server.listen(8)
          loop do
            client = server.accept
            begin
              serve_client(client: client, uid: uid, interfaces: interfaces)
            rescue SystemCallError, IOError, Timeout::Error, ArgumentError
              # A disconnected, malformed or idle client cannot stop the listener.
              nil
            ensure
              client.close
            end
          end
        ensure
          server&.close
          if identity
            begin
              current = File.lstat(path)
              File.unlink(path) if current.ino == identity.ino && current.dev == identity.dev
            rescue Errno::ENOENT
              nil
            end
          end
        end

        public_class_method def self.main(opts = {})
          config = { interfaces: [] }
          parser = OptionParser.new do |options|
            options.banner = 'Usage: pwn-capd --uid UID --interface IFACE [--socket PATH]'
            options.on('--uid UID', Integer) { |uid| config[:uid] = uid }
            options.on('--interface IFACE') { |iface| config[:interfaces] << iface }
            options.on('--socket PATH') { |path| config[:socket] = path }
          end
          parser.parse!((opts[:argv] || ARGV).dup)
          raise ArgumentError, parser.banner unless config.key?(:uid) && !config[:interfaces].empty?

          previous = Signal.trap('TERM') { raise Interrupt }
          run(config)
        rescue Interrupt
          nil
        ensure
          Signal.trap('TERM', previous) if previous
        end

        public_class_method def self.authors
          CapabilityBroker.authors
        end

        public_class_method def self.help
          puts "USAGE:
            # Dispatch a typed operation after verifying the configured caller.
            #{self}.dispatch(
              request: 'required - parsed JSON request Hash with string keys',
              peer_uid: 'required - UID from kernel SO_PEERCRED credentials',
              uid: 'required - administrator configured allowed caller UID',
              interfaces: 'required - administrator configured interface allowlist'
            )
            # Handle one bounded request on an accepted Unix connection.
            #{self}.serve_client(
              client: 'required - accepted Unix socket connection',
              uid: 'required - administrator configured allowed caller UID',
              interfaces: 'required - administrator configured interface allowlist',
              timeout: 'optional - total connection deadline in seconds, default 35'
            )
            # Start the Linux listener after narrowing existing capabilities.
            #{self}.run(
              uid: 'required - administrator configured allowed caller UID',
              interfaces: 'required - administrator configured interface allowlist',
              socket: 'optional - protected Unix socket pathname'
            )
            # Parse administrator CLI arguments and run the daemon.
            #{self}.main(argv: 'optional - CLI argument array, default ARGV')
            # Print the module author information.
            #{self}.authors
          "
        end
      end
    end
  end
end
