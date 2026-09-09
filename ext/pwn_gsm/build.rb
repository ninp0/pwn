# frozen_string_literal: true

require 'rbconfig'
output = File.join(__dir__, "libpwn_gsm.#{RbConfig::CONFIG.fetch('DLEXT')}")
abort 'GSM scanner build failed' unless system(ENV.fetch('CC', 'cc'), '-shared', '-fPIC', '-O3', '-std=c99', '-Wall', '-Wextra',
                                               File.join(__dir__, 'pwn_gsm.c'), '-lm', '-o', output)
puts output
