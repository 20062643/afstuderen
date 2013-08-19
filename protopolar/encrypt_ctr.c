#include "stdio.h"

#include "polarssl/aes.h"
#include "polarssl/base64.h"

int main()
{
  unsigned char key[16] = "klein";
  const unsigned char *input = "{my_json: 'yes', mit: 'awesome', cool: 'very cool'}";

  unsigned char output[strlen(input)];
  unsigned char original_input[1024];

  aes_context ctx;

  size_t length = strlen(input);
  size_t nc_off = 0;

  unsigned char nonce_counter[16];
  unsigned char stream_block[16];

  memset(nonce_counter, 0, sizeof(nonce_counter));
  memset(stream_block, 0, sizeof(stream_block));
  memset(output, 0, sizeof(output));

  aes_setkey_enc(&ctx, key, 128);

  aes_crypt_ctr(&ctx, length, &nc_off, nonce_counter, stream_block, input, output);

  printf("%d\n", nc_off);

  unsigned char dst[1024];
  size_t dlen = 1024;

  base64_encode(dst, &dlen, output, strlen(input));

  printf("%s\n", dst);

  return 0;
}