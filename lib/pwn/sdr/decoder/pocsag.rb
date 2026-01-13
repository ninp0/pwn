# frozen_string_literal: true

require 'json'
require 'tty-spinner'

module PWN
  module SDR
    module Decoder
      # POCSAG Decoder Module for Pagers
      module POCSAG
        # Supported Method Parameters::
        # pocsag_resp = PWN::SDR::Decoder::POCSAG.decode(
        #   freq_obj: 'required - GQRX socket object returned from #connect method'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          gqrx_sock = freq_obj[:gqrx_sock]
          record_path = freq_obj[:record_path]
          freq_obj = freq_obj.dup
          freq_obj.delete(:gqrx_sock)
          skip_freq_char = "\n"
          puts JSON.pretty_generate(freq_obj)
          puts "\n*** Pager POCSAG Decoder ***"
          puts 'Press [ENTER] to continue...'

          # Toggle POCSAG off and on to reset the decoder
          PWN::SDR::GQRX.cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RECORD 0',
            resp_ok: 'RPRT 0'
          )

          PWN::SDR::GQRX.cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RECORD 1',
            resp_ok: 'RPRT 0'
          )

          # Spinner setup with dynamic terminal width awareness
          spinner = TTY::Spinner.new(
            '[:spinner] :decoding',
            format: :arrow_pulse,
            clear: true,
            hide_cursor: true
          )

          record_header_size = 44
          wav_header = File.binread(record_path, record_header_size)
          raise 'ERROR: WAV file header is invalid!' unless wav_header[0, 4] == 'RIFF' && wav_header[8, 4] == 'WAVE'

          bytes_read = wav_header_size

          # Conservative overhead for spinner animation, colors, and spacing
          spinner_overhead = 12
          max_title_length = [TTY::Screen.width - spinner_overhead, 50].max

          initial_title = 'INFO: Decoding Pager POCSAG data...'
          initial_title = initial_title[0...max_title_length] if initial_title.length > max_title_length
          spinner.update(title: initial_title)
          spinner.auto_spin

          last_resp = {}

          loop do
            current_wav_size = File.size?(record_path) ||= 0
            pocsag_resp = {}

            # Only update when we have valid new data
            if current_wav_size > bytes_read
              new_bytes = current_wav_size - bytes_read
              # Ensure full I/Q pairs (8 bytes each)
              new_bytes -= new_bytes % 8
              data = File.binread(record_path, new_bytes, bytes_read)

              msg = "DECODED DATA"

              spinner.update(decoding: msg)
              last_resp = pocsag_resp.dup
            end

            # Non-blocking check for ENTER key to exit
            if $stdin.wait_readable(0)
              begin
                char = $stdin.read_nonblock(1)
                break if char == skip_freq_char
              rescue IO::WaitReadable, EOFError
                # No-op
              end
            end

            sleep 0.01
          end
        rescue StandardError => e
          spinner.error('Decoding failed') if defined?(spinner)
          raise e
        ensure
          File.unlink(record_path) if File.exist?(record_path)
          PWN::SDR::GQRX.cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RECORD 0',
            resp_ok: 'RPRT 0'
          )

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
