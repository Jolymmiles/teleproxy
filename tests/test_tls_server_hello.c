#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/net-tls-parse.h"

static unsigned char *read_fixture (const char *path, int *len) {
  FILE *f = fopen (path, "rb");
  if (!f) {
    return NULL;
  }
  fseek (f, 0, SEEK_END);
  long size = ftell (f);
  rewind (f);
  unsigned char *buf = malloc ((size_t)size);
  if (!buf || fread (buf, 1, (size_t)size, f) != (size_t)size) {
    free (buf);
    fclose (f);
    return NULL;
  }
  fclose (f);
  *len = (int)size;
  return buf;
}

static int parse_response (const unsigned char *response, int len) {
  int is_reversed = -1;
  int record_sizes[MAX_ENCRYPTED_RECORDS] = {};
  int record_count = 0;
  return tls_check_server_hello (response, len, response + 44,
                                 &is_reversed, record_sizes, &record_count);
}

int main (void) {
  int len = 0;
  unsigned char *response =
    read_fixture ("fuzz/corpus/tls_server_hello/valid_tls13.bin", &len);
  if (!response) {
    fprintf (stderr, "failed to read TLS fixture\n");
    return 1;
  }

  if (!parse_response (response, len)) {
    fprintf (stderr, "valid TLS 1.3 fixture was rejected\n");
    free (response);
    return 1;
  }

  int server_hello_end = 5 + response[3] * 256 + response[4];
  if (server_hello_end + 6 >= len ||
      memcmp (response + server_hello_end, "\x14\x03\x03\x00\x01\x01", 6)) {
    fprintf (stderr, "fixture has no dummy ChangeCipherSpec\n");
    free (response);
    return 1;
  }
  memmove (response + server_hello_end, response + server_hello_end + 6,
           (size_t)(len - server_hello_end - 6));
  len -= 6;

  if (!parse_response (response, len)) {
    fprintf (stderr, "TLS 1.3 response without dummy ChangeCipherSpec was rejected\n");
    free (response);
    return 1;
  }

  free (response);
  puts ("TLS ServerHello parser tests passed");
  return 0;
}
