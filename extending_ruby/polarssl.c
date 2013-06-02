#include <polarssl.h>

VALUE mPolarSSL;

void Init_polarssl()
{
  mPolarSSL = rb_define_module("PolarSSL");

  Init_entropy_context();
  Init_ctr_drbg_context();
  Init_ssl_context();
}