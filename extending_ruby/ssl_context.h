#ifndef RUBY_SSL_CONTEXT
#define RUBY_SSL_CONTEXT

#include <polarssl.h>

void Init_ssl_context();
void Init_ctr_drbg_context();

static VALUE ssl_context_allocate();
static VALUE ssl_context_initialize();
static VALUE ssl_context_set_bio();
static VALUE ssl_context_set_random_number_generator();
static void ssl_context_free();
static VALUE ssl_context_handshake();
static VALUE ssl_context_ssl_write();
static VALUE ssl_context_ssl_read();

#endif