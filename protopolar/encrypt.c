#include "stdio.h"

#include "polarssl/aes.h"
#include "polarssl/base64.h"

int main()
{
  unsigned char key[16] = "123456789012344";
  const unsigned char input[16] = "hallozestien34";
  unsigned char output[16];
  unsigned char original_input[16];

  printf("%s\n", input);

  aes_context ctx;
  aes_setkey_enc(&ctx, key, 128);

  aes_crypt_ecb(&ctx, AES_ENCRYPT, input, output);

  unsigned char output_buf[1024];
  size_t baselen = 1024;

  base64_encode(output_buf, &baselen, output, 16);

  printf("%s\n", output_buf);

  aes_setkey_dec(&ctx, key, 128);
  aes_crypt_ecb(&ctx, AES_DECRYPT, output, original_input);

  printf("original input:\n%s\n", original_input);


  return 0;
}