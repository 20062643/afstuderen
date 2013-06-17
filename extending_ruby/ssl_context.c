#include <ssl_context.h>
#include <ruby/io.h>

void my_debug(void *ctx, int level, const char *str)
{
  fprintf((FILE *)ctx, "%s", str);
}

void Init_ssl_context()
{
  VALUE cSSLContext = rb_define_class_under(mPolarSSL, "SSLContext", rb_cObject);

  rb_define_alloc_func(cSSLContext, ssl_context_allocate);
  rb_define_method(cSSLContext, "initialize", ssl_context_initialize, 0);
  rb_define_method(cSSLContext, "set_bio", ssl_context_set_bio, 1);
  rb_define_method(cSSLContext, "random_number_generator=", ssl_context_set_random_number_generator, 1);
  rb_define_method(cSSLContext, "handshake", ssl_context_handshake, 0);
  rb_define_method(cSSLContext, "write", ssl_context_ssl_write, 1);
  rb_define_method(cSSLContext, "read", ssl_context_ssl_read, 0);
}

static VALUE ssl_context_allocate(VALUE klass)
{
  ssl_context *ssl = malloc(sizeof(ssl_context));
  memset(ssl, 0, sizeof(ssl_context));

  return Data_Wrap_Struct(klass, NULL, ssl_context_free, ssl);
}

static VALUE ssl_context_initialize(VALUE self)
{
  ssl_context *ssl;

  Data_Get_Struct(self, ssl_context, ssl);
  ssl_init(ssl);
  ssl_set_endpoint( ssl, SSL_IS_CLIENT );
  ssl_set_authmode( ssl, SSL_VERIFY_NONE );
  ssl_set_ciphersuites( ssl, ssl_default_ciphersuites );
  // ssl_set_dbg( ssl, my_debug, stderr );

  return self;
}

static VALUE ssl_context_set_bio(VALUE self, VALUE io)
{
  ssl_context *ssl;
  rb_io_t *fptr;

  GetOpenFile(io, fptr);

  Data_Get_Struct(self, ssl_context, ssl);

  ssl_set_bio(ssl, net_recv, &fptr->fd, net_send, &fptr->fd);

  return self;
}

static VALUE ssl_context_set_random_number_generator(VALUE self, VALUE oCtrDrbgContext)
{
  ssl_context *ssl;
  ctr_drbg_context *ctr_drbg;

  Data_Get_Struct(self, ssl_context, ssl);
  Data_Get_Struct(oCtrDrbgContext, ctr_drbg_context, ctr_drbg);

  ssl_set_rng(ssl, ctr_drbg_random, ctr_drbg);

  return self;
}

static VALUE ssl_context_handshake(VALUE self)
{
  ssl_context *ssl;

  int ret;

  Data_Get_Struct(self, ssl_context, ssl);
  ssl_handshake(ssl);
  return Qtrue;
}

static VALUE ssl_context_ssl_write(VALUE self, VALUE oString)
{
  ssl_context *ssl;
  Data_Get_Struct(self, ssl_context, ssl);

  ssl_write(ssl, RSTRING_PTR(oString), RSTRING_LEN(oString) );

  return Qtrue;
}

static VALUE ssl_context_ssl_read(VALUE self)
{
  ssl_context *ssl;
  Data_Get_Struct(self, ssl_context, ssl);
  VALUE ret;

  ret = Qnil;

  if(rb_block_given_p())
  {
    while (1)
    {
      int len;
      char chunk[BUFSIZ];
      VALUE str;

      memset(chunk, 0, BUFSIZ);

      len = ssl_read( ssl, chunk, BUFSIZ - 1 );

      if (len <= 0) {
        break;
      } else {
        str = rb_str_new2(chunk);

        rb_yield(str);
      }
    }
  } else {
    int len;
    char chunk[BUFSIZ];
    VALUE str;

    memset(chunk, 0, BUFSIZ);

    len = ssl_read( ssl, chunk, BUFSIZ - 1 );
    str = rb_str_new2(chunk);

    ret = str;
  }

  return ret;
}

static void ssl_context_free(void *p) {
  ssl_free(p);
}