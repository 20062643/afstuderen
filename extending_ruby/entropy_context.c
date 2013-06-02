#include <entropy_context.h>

void Init_entropy_context()
{
  VALUE cEntropyContext = rb_define_class_under(mPolarSSL, "EntropyContext", rb_cObject);

  rb_define_alloc_func(cEntropyContext, entropy_context_allocate);
  rb_define_method(cEntropyContext, "gather", entropy_context_gather, 0);
}

static VALUE entropy_context_allocate(VALUE klass)
{
  entropy_context *entropy_p = malloc(sizeof(entropy_context));

  entropy_init(entropy_p);

  return Data_Wrap_Struct(klass, NULL, NULL, entropy_p);
}

static VALUE entropy_context_gather(VALUE self)
{
  entropy_context *entropy_p;

  Data_Get_Struct(self, entropy_context, entropy_p);

  VALUE ret;

  if (entropy_gather(entropy_p) == 0)
  {
    ret = Qtrue;
  } else {
    ret = Qfalse;
  }

  return ret;
}

void Init_ctr_drbg_context()
{
  VALUE cCtrDrbgContext = rb_define_class_under(mPolarSSL, "CtrDrbgContext", rb_cObject);

  rb_define_alloc_func(cCtrDrbgContext, ctr_drbg_context_allocate);
  rb_define_method(cCtrDrbgContext, "initialize", ctr_drbg_context_initialize, 1);
}

static VALUE ctr_drbg_context_allocate(VALUE klass)
{
  ctr_drbg_context *context_p = malloc(sizeof(ctr_drbg_context));

  return Data_Wrap_Struct(klass, NULL, NULL, context_p);
}

static VALUE ctr_drbg_context_initialize(VALUE self, VALUE entropy_context_object)
{
  entropy_context *entropy_p;
  ctr_drbg_context *ctr_drbg_p;

  Data_Get_Struct(entropy_context_object, entropy_context, entropy_p);
  Data_Get_Struct(self, ctr_drbg_context, ctr_drbg_p);

  ctr_drbg_init(ctr_drbg_p, entropy_func, entropy_p, NULL, 0);

  return self;
}