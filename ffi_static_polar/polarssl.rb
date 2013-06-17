module PolarSSL
  extend FFI::Library
  ffi_lib "/usr/local/lib/libpolarssl.dylib"

  attach_function :entropy_init, [:pointer], :int
end
