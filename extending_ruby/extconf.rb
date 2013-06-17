require 'mkmf'

LIBDIR      = RbConfig::CONFIG['libdir']
INCLUDEDIR  = RbConfig::CONFIG['includedir']

HEADER_DIRS = [INCLUDEDIR]

LIB_DIRS = [LIBDIR]

dir_config('polarssl', HEADER_DIRS, LIB_DIRS)

unless find_header('polarssl/entropy.h')
  abort "libpolarssl is missing. please install libpolarssl"
end

unless find_library('polarssl', 'entropy_init')
  abort "libpolarssl is missing.  please install libpolarssl"
end

create_makefile('polarssl/polarssl')