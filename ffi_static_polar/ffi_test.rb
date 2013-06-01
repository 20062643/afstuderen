require 'ffi'
require './polarssl'


entropy_context = FFI::MemoryPointer.new(:pointer)

ret = PolarSSL.entropy_init(entropy_context)