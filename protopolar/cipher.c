#include "polarssl/cipher.h"
#include "polarssl/base64.h"
#include "stdio.h"

int main()
{
  cipher_context_t ctx;
  const char key[16] = "test";
  const char input[20] = "halloinputballoha";
  unsigned char output[20];
  memset(output, 0, sizeof(output));

  size_t olen = 20;

  cipher_init_ctx(&ctx, cipher_info_from_type(POLARSSL_CIPHER_AES_128_CTR));
  cipher_setkey(&ctx, (const unsigned char *) key, 128, POLARSSL_ENCRYPT);
  cipher_update(&ctx, (const unsigned char *) input, strlen(input), output, &olen);
  cipher_finish(&ctx, output, &olen);

  printf("%s\n", output);

  unsigned char dst[1024];

  size_t dlen = 1024;

  base64_encode(dst, &dlen, output, strlen(input));

  printf("%s\n", dst);

  cipher_free_ctx(&ctx);

  return 0;
}