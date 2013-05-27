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

#define SERVER_PORT 80
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
  entropy_init( &entropy );

  /* start connection */
  printf("Connecting to tcp/%s/%4d...\n", SERVER_NAME, SERVER_PORT);

  server_host = gethostbyname(SERVER_NAME);
  server_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  memcpy( (void *) &server_addr.sin_addr,
    (void *) server_host->h_addr,
             server_host->h_length);

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons( SERVER_PORT );

  ret = connect( server_fd, (struct sockaddr *) &server_addr, sizeof( server_addr ) );

  printf("ok\n");

  len = sprintf( (char *) buf, GET_REQUEST );

  while( ( ret = write ( server_fd, buf, len ) ) <= 0 )
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
    ret = read( server_fd, &result[result_size], len );

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

  close( server_fd );
  free(result);

  return(0);

}