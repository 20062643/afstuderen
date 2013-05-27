#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <regex.h>
#include <stdlib.h>

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/ssl.h"

#define SERVER_PORT 443
#define SERVER_NAME "www.google.nl"
#define GET_REQUEST "GET / HTTP/1.1\r\nHost: www.google.nl\r\n\r\n"
#define HTTP_1_1_END_OF_RESPONSE "0\r\n\r\n"

int main()
{
  int ret, len, server_fd;
  unsigned char buf[BUFSIZ];
  unsigned char *result;
  struct sockaddr_in server_addr;
  struct hostent *server_host;

  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  ssl_context ssl;
  char *pers = "ssl_example";

  entropy_init( &entropy );
  ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen( pers ));
  memset(&ssl, 0, sizeof(ssl_context) );

  /* start connection */
  printf("Connecting to tcp/%s/%4d...\n", SERVER_NAME, SERVER_PORT);

  server_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  ret = net_connect( &server_fd, SERVER_NAME, SERVER_PORT );
  ret = ssl_init( &ssl );

  ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
  ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

  ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
  // ssl_set_dbg( &ssl, my_debug, stdout );
  ssl_set_bio( &ssl, net_recv, &server_fd,
    net_send, &server_fd );

  ssl_set_ciphersuites( &ssl, ssl_default_ciphersuites );

  printf("ok\n");

  len = sprintf( (char *) buf, GET_REQUEST );

  while( ( ret = ssl_write ( &ssl, buf, len ) ) <= 0 )
  {
    if ( ret != 0 )
    {
      printf( " failed write\n" );
      close( server_fd );
      return 0;
    }
  }

  len = ret;
  printf( "written: %d\n%s\n", len, (char *) buf );

  result = (unsigned char *) malloc(BUFSIZ);
  int result_size = 0;

  while(1)
  {
    len = BUFSIZ;
    ret = ssl_read( &ssl, &result[result_size], len );

    printf("%s", result);

    regex_t regex;
    int reti;
    reti = regcomp(&regex, HTTP_1_1_END_OF_RESPONSE, 0);
    if (reti) { fprintf(stderr, "Could not compile regex\n"); exit(1); }

    /* HTTP 1.1 */
    reti = regexec(&regex, result, 0, NULL, 0);
    if ( !reti ) {
      break;
    } else if( reti == REG_NOMATCH ) {
    }

    regfree(&regex);

    result_size += ret;

    result = (unsigned char *) realloc(result, result_size * 2);

    /* HTTP 1.0
    if (ret <= 0) {
      break;
    }*/
  }

  printf("%s", result);

  net_close( server_fd );
  ssl_free( &ssl );
  free(result);

  return(0);

}