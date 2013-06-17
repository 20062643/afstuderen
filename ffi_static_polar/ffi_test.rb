require 'ffi'
require './polarssl'


entropy_context = FFI::MemoryPointer.from_string("entropy_context")

ret = PolarSSL.entropy_init(entropy_context)