#include "stdio.h"
#include "math.h"

#include "polarssl/aes.h"
#include "polarssl/base64.h"

int main()
{
  unsigned char key[16] = "123456789012345";
  const char input[] = "testhalloditiseenlanfdsafdsafdsafdsafdasfadsgetesthalloditiseenlanfdsafdsafdsafdsafdasfadsgetesthalloditiseenlanfdsafdsafdsafdsafdasfadsgetesthalloditiseenlanfdsafdsafdsafdsafdasfadsgetesthalloditiseenlanfdsafdsafdsafdsafdasfadsgetesthalloditiseenlanfdsafdsafdsafdsafdasfadsgetesthalloditiseenlanfdsafdsafdsafdsafdasfadsgetesthalloditiseenlanfdsafdsafdsafdsafdasfadsge";

  printf("%s\n", key);

  unsigned char output[sizeof(input)];

  aes_context ctx;

  size_t nc_off = 0;

  unsigned char nonce_counter[16];
  unsigned char stream_block[16];

  // memset(nonce_counter, 0, sizeof(nonce_counter));
  // memset(stream_block, 0, sizeof(stream_block));
  // memset(output, 0, sizeof(output));

  aes_setkey_enc(&ctx, key, 128);

  aes_crypt_ctr(&ctx, sizeof(input), &nc_off, nonce_counter, stream_block, (unsigned char *) input, output);

  // printf("%zu\n", nc_off);
  // printf("%zu\n", strlen(input));

  unsigned char dst[1024];

  size_t dlen = 1024;

  base64_encode(dst, &dlen, output, sizeof(input));

  printf("%s\n%zu\n", dst, strlen((char *)dst));

  return 0;
}