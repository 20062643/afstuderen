#include "stdio.h"
#include "math.h"

#include "polarssl/aes.h"
#include "polarssl/base64.h"

int main()
{
  unsigned char key[16] = "polarssl";
  const char *input = "{batsmy_json: 'yes', mit: 'awesomde', cool: 'very cool', wow: 'Cras justo odio, dapibus ac facilisis in, egestas eget quam. Nullam id dolor id nibh ultricies vehicula ut id elit. Praesent commodo cursus magna, vel scelerisque nisl consectetur et. Praesent commodo cursus magna, vel scelerisque nisl consectetur et. Vestibulum id ligula porta felis euismod semper. Cras mattis consectetur purus sit amet fermentum. Aenean eu leo quam. Pellentesque ornare sem lacinia quam venenatis vestibulum.Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum id ligula porta felis euismod semper. Cras mattis consectetur purus sit amet fermentum. Fusce dapibus, tellus ac cursus commodo, tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Donec id elit non mi porta gravida at eget metus. Cras justo odio, dapibus ac facilisis in, egestas eget quam. Aenean eu leo quam. Pellentesque ornare sem lacinia quam venenatis vestibulum.}";

  unsigned char output[strlen(input)];

  aes_context ctx;

  size_t length = strlen(input);
  size_t nc_off = 0;

  unsigned char nonce_counter[16];
  unsigned char stream_block[16];

  memset(nonce_counter, 0, sizeof(nonce_counter));
  memset(stream_block, 0, sizeof(stream_block));
  memset(output, 0, sizeof(output));

  aes_setkey_enc(&ctx, key, 128);

  aes_crypt_ctr(&ctx, length, &nc_off, nonce_counter, stream_block, (unsigned char *) input, output);

  // printf("%zu\n", nc_off);
  // printf("%zu\n", strlen(input));

  unsigned char dst[(int) ceil(length * 1.4)];

  size_t dlen = (int) ceil(length * 1.4);

  base64_encode(dst, &dlen, output, sizeof(output));

  printf("%s\n%zu\n", dst, strlen((char *)dst));

  return 0;
}