#ifndef RUBY_POLARSSL
#define RUBY_POLARSSL

#include <ruby.h>;
#include <polarssl/entropy.h>;
#include <polarssl/ctr_drbg.h>;
#include <polarssl/ssl.h>;

#include <entropy_context.h>;
#include <ssl_context.h>;

extern VALUE mPolarSSL;

#endif