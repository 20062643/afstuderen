#ifndef RUBY_ENTROPY_CONTEXT
#define RUBY_ENTROPY_CONTEXT

#include <polarssl.h>

void Init_entropy_context();
void Init_ctr_drbg_context();

static VALUE entropy_context_allocate();
static VALUE entropy_context_gather();

static VALUE ctr_drbg_context_allocate();
static VALUE ctr_drbg_context_initialize();

#endif