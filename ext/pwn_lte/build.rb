# frozen_string_literal: true

# Explicit build against an operator-built srsRAN_4G source tree.
require 'rbconfig'
source = File.expand_path(ARGV.fetch(0))
build = File.expand_path(ARGV.fetch(1, File.join(source, 'build')))
output = File.join(__dir__, "libpwn_lte.#{RbConfig::CONFIG.fetch('DLEXT')}")
args = [ENV.fetch('CC', 'cc'), '-shared', '-fPIC', '-O2', '-std=c99',
        '-I', File.join(source, 'lib/include'), '-I', File.join(build, 'lib/include'),
        File.join(__dir__, 'pwn_lte.c'), File.join(build, 'lib/src/phy/libsrsran_phy.a'),
        '-lfftw3f', '-lstdc++', '-lm', '-lpthread', '-Wl,--no-undefined', '-o', output]
abort 'LTE native bridge build failed' unless system(*args)
puts output
