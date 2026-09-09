# frozen_string_literal: true

# Optional third-party C++ backend. Requires git, Meson/Ninja, a C++17 compiler,
# libsndfile, liquid-dsp, and nlohmann-json development headers.
require 'fileutils'
root = File.expand_path(__dir__)
source = File.join(root, 'vendor')
revision = '7555c9f6259d50718697ee8c9f218ea012c6892c'
abort 'clone failed' if !Dir.exist?(source) && !system('git', 'clone', 'https://github.com/windytan/redsea.git', source)
abort 'checkout failed' unless system('git', '-C', source, 'checkout', '--detach', revision)
build = File.join(root, 'build')
abort 'configure failed' unless system('meson', 'setup', build, source, '-Dbuild_tests=false')
abort 'compile failed' unless system('meson', 'compile', '-C', build, '-j', '4')
abort 'version check failed' unless system(File.join(build, 'redsea'), '--version')
puts "REDSEA=#{File.join(build, 'redsea')}"
