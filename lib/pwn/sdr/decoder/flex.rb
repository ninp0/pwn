# frozen_string_literal: true

require 'json'
require 'open3'
require 'tty-spinner'
require 'io/wait'

module PWN
  module SDR
    module Decoder
      # Flex Decoder Module for Pagers
      module Flex
        # Supported Method Parameters::
        # pocsag_resp = PWN::SDR::Decoder::Flex.decode(
        #   freq_obj: 'required - GQRX socket object returned from #connect method'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          gqrx_sock = freq_obj[:gqrx_sock]
          udp_ip    = freq_obj[:udp_ip]    || '127.0.0.1'
          udp_port  = freq_obj[:udp_port]  || 7355

          freq_obj.delete(:gqrx_sock)

          skip_freq_char = "\n"

          puts JSON.pretty_generate(freq_obj)
          puts 'Press [ENTER] to Continue to next frequency...'

          # Spinner setup with dynamic terminal width awareness
          spinner = TTY::Spinner.new(
            '[:spinner] :status',
            format: :arrow_pulse,
            clear: true,
            hide_cursor: true
          )

          spinner_overhead = 12
          max_title_length = [TTY::Screen.width - spinner_overhead, 50].max

          initial_title = "INFO: Decoding #{self.to_s.split('::').last} on udp://#{udp_ip}:#{udp_port} ..."
          initial_title = initial_title[0...max_title_length] if initial_title.length > max_title_length
          spinner.update(status: initial_title)
          spinner.auto_spin

          skip_freq = false

          # === Replace netcat with PWN::Plugins::Sock.listen ===
          udp_listener = PWN::SDR::GQRX.listen_udp(
            udp_ip: udp_ip,
            udp_port: udp_port
          )

          # Combined processing pipeline: sox → multimon-ng
          decode_cmd = '
            sox -t raw -e signed-integer -b 16 -r 48000 -c 1 - \
                -t raw -e signed-integer -b 16 -r 22050 -c 1 - | \
            multimon-ng -t raw \
              -a FLEX \
              -a FLEX_NEXT \
              -
          '

          mm_stdin, mm_stdout, mm_stderr, mm_wait_thr = Open3.popen3(decode_cmd)

          current_title = 'Waiting for data frames...'

          # Thread: read from UDP listener and feed to sox|multimon pipeline
          receiver_thread = Thread.new do
            begin
              loop do
                data, _sender = udp_listener.recv(4096)
                next unless data.to_s.bytesize.positive?

                mm_stdin.write(data)
                mm_stdin.flush rescue nil
              end
            rescue IOError, Errno::EPIPE, EOFError, Errno::ECONNRESET
              # normal exit path when shutting down
            end
          end

          # Thread: read decoded output from multimon-ng and display it
          decoder_thread = Thread.new do
            # buffer = +''
            buffer = ''

            valid_types = %w[ALN BIN HEX NUM TON TONE UNK]
            loop do
              begin
                chunk = mm_stdout.readpartial(4096)
                # buffer << chunk
                buffer = "#{buffer}#{chunk}"

                while (line = buffer.slice!(/^.*\n/))
                  line = line.chomp
                  next if line.empty? || !line.start_with?('FLEX')

                  decoded_at = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
                  dec_msg = { decoded_at: decoded_at }
                  dec_msg[:raw_inspected] = line.inspect

                  protocol = line[0..8]
                  protocol = 'FLEX' unless protocol == 'FLEX_NEXT'
                  dec_msg[:protocol] = protocol

                  # ────────────────────────────── Detect format ──────────────────────────────
                  # Sometimes Flex is space delimited, sometimes pipe delimited
                  # FLEX_NEXT appears to always be pipe delimited

                  delimiter = '|'
                  space_delim = false
                  if line.start_with?('FLEX: ')
                    delimiter = ' '
                    space_delim = true
                  end

                  flex_pipe_delim = false
                  flex_pipe_delim = true if line.start_with?('FLEX|')

                  parts = line.split(delimiter)

                  # protocol index already used
                  idx_already_used = [0]
                  target_parts_idx = 1
                  target_parts_idx += 1 if flex_pipe_delim
                  target_parts_idx += 2 if space_delim
                  dec_msg[:speed] = parts[target_parts_idx] if parts[target_parts_idx]
                  idx_already_used.push(target_parts_idx)

                  target_parts_idx += 2
                  dec_msg[:capcode] = parts[target_parts_idx] if parts[target_parts_idx]
                  idx_already_used.push(target_parts_idx)

                  target_parts_idx -= 1
                  dec_msg[:capcode_loc] = parts[target_parts_idx] if parts[target_parts_idx]
                  idx_already_used.push(target_parts_idx)

                  while target_parts_idx < parts.size
                    if idx_already_used.include?(target_parts_idx)
                      target_parts_idx += 1
                      next
                    end

                    key = parts[target_parts_idx]
                    key = 'long_sequence_number' if key == 'LS'

                    if key && valid_types.include?(key)
                      dec_msg[:type] = key

                      dec_msg[:type_desc] = case key
                                            when 'ALN'
                                              'Human-readable text'
                                            when 'BIN'
                                              'Binary / data payload (typically 32 bit words)'
                                            when 'HEX'
                                              'Raw hex representation of data'
                                            when 'NUM'
                                              'Numbers only'
                                            when 'TON', 'TONE'
                                              'Just alert tone, no message'
                                            when 'UNK'
                                              'Decoded but type unknown / unsupported format'
                                            end

                      target_parts_idx += 1
                      payload_parts = parts[target_parts_idx..]
                      dec_msg[:type_payload] = payload_parts.join(delimiter)

                      break
                    else
                      target_parts_idx += 1
                      dec_msg[key] = parts[target_parts_idx] if parts[target_parts_idx]
                    end

                    idx_already_used.push(target_parts_idx)
                    target_parts_idx += 1
                  end

                  final_msg = freq_obj.merge(dec_msg)
                  puts JSON.pretty_generate(final_msg)
                  # TODO: Append dec_msg to a log file in a better way
                  flex_log_file = "/tmp/flex_decoder_#{Time.now.strftime('%Y%m%d')}.log"
                  File.open(flex_log_file, 'a') do |f|
                    f.puts("#{JSON.generate(final_msg)},")
                  end
                end
              rescue EOFError, IOError
                break
              end
            end
          end

          loop do
            spinner.update(status: current_title)

            # Non-blocking ENTER check to exit gracefully
            next unless $stdin.wait_readable(0)

            begin
              char = $stdin.read_nonblock(1)
              next unless char == skip_freq_char

              skip_freq = true
              puts "\n[!] ENTER pressed → stopping decoder..."

              break
            rescue IO::WaitReadable, EOFError
              # ignore
            end

            break if skip_freq
          end

          spinner.success('Decoding stopped')
        rescue StandardError => e
          spinner.error("Decoding failed: #{e.message}") if defined?(spinner)
          raise
        ensure
          # Cleanup
          [receiver_thread, decoder_thread].each do |thread|
            thread.kill if thread.alive?
          end

          [mm_stdin, mm_stdout, mm_stderr].each { |io| io.close rescue nil }

          mm_wait_thr&.value rescue nil

          PWN::SDR::GQRX.disconnect_udp(udp_listener: udp_listener) if defined?(udp_listener) && udp_listener

          spinner.stop if defined?(spinner) && spinner
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq method'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
