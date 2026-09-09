# frozen_string_literal: true

# Explicit opt-in: ruby ext/pwn_dsp/build.rb. Never invoked by library load.
require 'rbconfig'
require 'shellwords'
require 'tempfile'

Dir.chdir(__dir__) do
  extension = RbConfig::CONFIG.fetch('DLEXT')
  output = "libpwn_dsp.#{extension}"
  Tempfile.create(['.pwn-dsp-', ".#{extension}"], __dir__) do |file|
    compiler = Shellwords.split(ENV.fetch('CC', RbConfig::CONFIG.fetch('CC')))
    link = RUBY_PLATFORM.include?('darwin') ? '-dynamiclib' : '-shared'
    command = compiler + ['-O3', '-std=c99', '-Wall', '-Wextra', '-Werror', '-fPIC', '-ffp-contract=off', link, 'pwn_dsp.c', '-lm', '-o', file.path]
    abort 'DSP native build failed; Ruby fallback remains available' unless system(*command)
    File.rename(file.path, output)
    puts File.expand_path(output)
  end
end
