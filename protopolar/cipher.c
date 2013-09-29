#include "polarssl/cipher.h"
#include "polarssl/base64.h"
#include "stdio.h"

int main()
{
  cipher_context_t ctx;
  const char key[16] = "1234567890123456";
  const char *input = "Fusce dapibus, tellus ac cursus commodo, tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Sed posuere consectetur est at lobortis. Curabitur blandit tempus porttitor. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Sed posuere consectetur est at lobortis.";
  char output[1024];
  int ret;
  memset(output, 0, sizeof(output));

  size_t olen = 0;

  cipher_init_ctx(&ctx, cipher_info_from_type(POLARSSL_CIPHER_AES_128_CTR));
  ret = cipher_setkey(&ctx, (const unsigned char *) key, 128, POLARSSL_ENCRYPT);
  printf("%d\n", ret);
  cipher_update(&ctx, (const unsigned char *) input, strlen(input), output, &olen);

  printf("%zu\n", olen);
  printf("%zu\n", strlen(output) );

  cipher_finish(&ctx, output, &olen);

  unsigned char dst[1024];

  size_t dlen = 1024;

  base64_encode(dst, &dlen, output, strlen(input) );

  printf("%s\n", dst);

  cipher_free_ctx(&ctx);

  return 0;
}