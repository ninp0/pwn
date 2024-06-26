# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # This plugin is a simple wrapper around the ps command.
    module PS
      # Supported Method Parameters::
      # proc_list_arr = PWN::Plugins::PS.list

      public_class_method def self.list(opts = {})
        pid = opts[:pid]

        which_os = PWN::Plugins::DetectOS.type

        case which_os
        when :cygwin
          cmd = 'ps'
          params = "w -p #{pid}"
          params = 'waux' if pid.nil?
        when :freebsd, :linux, :netbsd, :openbsd, :osx
          cmd = 'ps'
          format = 'user,pcpu,pid,ppid,uid,group,gid,cpu,pmem,command'
          params = "w -p #{pid} -o #{format}"
          params = "wax -o #{format}" if pid.nil?
        else
          raise "Unsupported OS: #{which_os}"
        end
        full_cmd = "#{cmd} #{params}"

        stdout, _stderr, _status = Open3.capture3(full_cmd)

        proc_list_arr = []
        stdout_arr = stdout.split("\n")
        stdout_arr.each do |line|
          column_len = format.split(',').length
          cmd_idx = column_len - 1
          first_cols = line.split[0..(cmd_idx - 1)]
          cmd = [line.split[cmd_idx..].join(' ')]
          proc_line = first_cols + cmd
          proc_list_arr.push(proc_line)
        end

        proc_list_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::PS.cleanup_pids(
      #   pids_arr: 'required - array of pids to kill'
      # )
      public_class_method def self.cleanup_pids(opts = {})
        pids_arr = opts[:pids_arr]

        pids_arr.each do |pid_line|
          pid = pid_line[2].to_i
          Process.kill('TERM', pid)
        rescue Errno::ESRCH
          next
        end
      rescue StandardError => e
        raise e
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
          proc_list_arr = #{self}.list

          #{self}.cleanup_pids(
            pids_arr: 'required - array of pids to kill'
          )

          #{self}.authors
        "
      end
    end
  end
end
