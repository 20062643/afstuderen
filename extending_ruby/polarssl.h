#ifndef RUBY_POLARSSL
#define RUBY_POLARSSL

#include <ruby.h>;
#include <polarssl/entropy.h>;
#include <polarssl/ctr_drbg.h>;

#include <entropy_context.h>;

extern VALUE mPolarSSL;

#endif