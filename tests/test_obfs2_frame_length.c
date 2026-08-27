/*
    This file is part of Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

/* Differential test for obfs2_parse_frame_length.
 *
 * Oracle: the frame-length algorithm as it lived inline in
 * net-tcp-rpc-ext-server.c before the parser was delegated to the
 * obfs2 module (see git history). The module must agree with it on
 * accept/reject, decoded length, header size and QUICKACK for every
 * input class, including the boundary cases that motivated each rule.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "net/net-obfs2-parse.h"

/* ---- crypto stubs: the frame parser needs none of it, but the TU ---- */

EVP_CIPHER_CTX *evp_cipher_ctx_init (const EVP_CIPHER *cipher, unsigned char *key, unsigned char iv[16], int is_encrypt) {
  (void) cipher; (void) key; (void) iv; (void) is_encrypt;
  return NULL;
}
void evp_crypt (EVP_CIPHER_CTX *evp_ctx, const void *in, void *out, int size) {
  (void) evp_ctx; (void) in; (void) out; (void) size;
}
void sha256 (const unsigned char *input, int ilen, unsigned char output[32]) {
  (void) input; (void) ilen; (void) output;
}
const EVP_CIPHER *EVP_aes_256_ctr (void) {
  return NULL;
}
void EVP_CIPHER_CTX_free (EVP_CIPHER_CTX *ctx) {
  (void) ctx;
}

/* Module TU: brings net-tcp-rpc-common.h (RPC_F_* bits) along. */
#include "../src/net/net-obfs2-parse.c"

/* ---- oracle: the retired inline algorithm ---- */

enum { REF_OK = 0, REF_BAD = 1, REF_TRANSPORT = 2, REF_OVERLONG = 3 };

struct ref_res { int ok, kind, len, hdr, qk; };

static struct ref_res ref_parse (int packet_len, int medium, int pad, int maxlen) {
  struct ref_res r = { 0, REF_BAD, 0, 4, 0 };
  int packet_len_bytes = 4;
  int quickack = 0;

  if (medium) {
    if (packet_len < 0 && packet_len > -1000) {
      r.kind = REF_TRANSPORT;
      r.len = packet_len;
      return r;
    }
    quickack = !!(packet_len & RPC_F_QUICKACK);
    packet_len &= ~RPC_F_QUICKACK;
  } else {
    if (packet_len & 0x80) {
      quickack = 1;
      packet_len &= ~0x80;
    }
    if ((packet_len & 0xff) == 0x7f) {
      packet_len = ((unsigned) packet_len >> 8);
      if (packet_len < 0x7f) {
        r.kind = REF_OVERLONG;
        r.len = packet_len;
        return r;
      }
    } else {
      packet_len &= 0x7f;
      packet_len_bytes = 1;
    }
    packet_len <<= 2;
  }

  r.len = packet_len;
  r.hdr = packet_len_bytes;
  r.qk = quickack;

  if (packet_len <= 0 || (packet_len & 0xc0000000) || (!pad && (packet_len & 3))) {
    return r;
  }
  if (maxlen > 0 && packet_len > maxlen) {
    return r;
  }
  r.ok = 1;
  r.kind = REF_OK;
  return r;
}

/* ---- harness ---- */

static long long mismatches = 0, checks = 0;

static void check (int raw4, int medium, int pad, int maxlen) {
  int flags = (medium ? RPC_F_MEDIUM : 0) | (pad ? RPC_F_PAD : 0);
  struct ref_res ref = ref_parse (raw4, medium, pad, maxlen);
  struct obfs2_frame_result fr;
  int ret = obfs2_parse_frame_length (raw4, flags, maxlen, &fr);
  checks++;

  if ((ret == 0) != (ref.ok == 1) ||
      (ret < 0 && ((ref.kind == REF_TRANSPORT && fr.status != OBFS2_FRAME_TRANSPORT_ERROR) ||
                   (ref.kind == REF_OVERLONG && fr.status != OBFS2_FRAME_OVERLONG) ||
                   (ref.kind == REF_BAD && fr.status != OBFS2_FRAME_BAD_LENGTH) ||
                   fr.parsed_len != ref.len)) ||
      (ret == 0 && (fr.packet_len != ref.len || fr.header_bytes != ref.hdr ||
                    fr.quickack != ref.qk || fr.status != OBFS2_FRAME_OK ||
                    fr.parsed_len != ref.len))) {
    if (mismatches < 20) {
      fprintf (stderr, "MISMATCH raw4=%d medium=%d pad=%d maxlen=%d -> ret=%d status=%d parsed_len=%d"
                       " (ref ok=%d kind=%d len=%d hdr=%d qk=%d)\n",
               raw4, medium, pad, maxlen, ret, fr.status, fr.parsed_len,
               ref.ok, ref.kind, ref.len, ref.hdr, ref.qk);
    }
    mismatches++;
  }
}

int main (void) {
  /* Hand-picked boundaries behind each rule. */
  static const int edges[] = {
    0, 1, 2, 3, 4, 0x7e, 0x7f, 0x80, 0x81, 0xfd, 0xfe, 0xff,
    0x7f, 0x017f, 0x7f00, 0x7fff, 0x8000, 0xff7f, 0x7f80, 0x3fffff, 0x400000,
    0x01ff7f, 0x03000000, 0x3fffffff, 0x40000000, 0x7fffffff, (int) 0x80000000,
    -1, -2, -404, -429, -999, -1000, -1001, -1004, (int) 0xc0000000, (int) 0xfffffffc
  };
  for (unsigned i = 0; i < sizeof (edges) / sizeof (edges[0]); i++) {
    for (int medium = 0; medium <= 1; medium++) {
      for (int pad = 0; pad <= 1; pad++) {
        check (edges[i], medium, pad, 0);
        check (edges[i], medium, pad, 8);
        check (edges[i], medium, pad, 60000);
      }
    }
  }

  /* maxlen cut right at a decoded boundary. */
  for (int ml = 120; ml <= 130; ml++) {
    check (0x0000001f, 1, 0, ml);  /* medium: plen = 0x1f & ~QUICKACK */
    check (0x00000020, 1, 0, ml);
  }

  /* Deterministic sweep over the full input space. */
  unsigned x = 0x12345678u;
  for (long i = 0; i < 2000000; i++) {
    x = x * 1664525u + 1013904223u;
    int raw4 = (int) x;
    for (int medium = 0; medium <= 1; medium++) {
      for (int pad = 0; pad <= 1; pad++) {
        check (raw4, medium, pad, 0);
      }
    }
    if ((i & 0xffff) == 0) {
      check (raw4, 0, 0, 16384);
      check (raw4, 1, 1, 16384);
    }
  }

  if (mismatches != 0) {
    fprintf (stderr, "FAIL: %lld mismatches out of %lld checks\n", mismatches, checks);
    return 1;
  }
  printf ("OBFS2 DIFFERENTIAL PARITY OK (%lld checks)\n", checks);
  return 0;
}
