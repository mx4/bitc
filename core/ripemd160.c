/*
 * RIPEMD-160 -- public-domain implementation based on the reference by
 * Antoon Bosselaers. Produces the 20-byte digest used for bitcoin hash160.
 */
#include <string.h>

#include "ripemd160.h"

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* nonlinear function at round j (0..79) */
static uint32
rmd_f(int j, uint32 x, uint32 y, uint32 z)
{
   if (j < 16) return x ^ y ^ z;
   if (j < 32) return (x & y) | (~x & z);
   if (j < 48) return (x | ~y) ^ z;
   if (j < 64) return (x & z) | (y & ~z);
   return x ^ (y | ~z);
}

/* added constants, left and right lines (indexed by round = j/16) */
static const uint32 KL[5] = { 0x00000000u, 0x5A827999u, 0x6ED9EBA1u,
                              0x8F1BBCDCu, 0xA953FD4Eu };
static const uint32 KR[5] = { 0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u,
                              0x7A6D76E9u, 0x00000000u };

/* message word order */
static const uint8 RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
    3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
    1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
    4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13 };
static const uint8 RR[80] = {
    5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
    6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
   15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
    8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
   12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11 };

/* rotate amounts */
static const uint8 SL[80] = {
   11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
    7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
   11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
   11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
    9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6 };
static const uint8 SR[80] = {
    8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
    9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
    9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
   15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
    8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11 };

static void
rmd_transform(uint32 h[5], const uint8 block[64])
{
   uint32 X[16];
   uint32 al, bl, cl, dl, el;
   uint32 ar, br, cr, dr, er;
   int j;

   for (j = 0; j < 16; j++) {
      X[j] = (uint32)block[j * 4]            | ((uint32)block[j * 4 + 1] << 8) |
            ((uint32)block[j * 4 + 2] << 16) | ((uint32)block[j * 4 + 3] << 24);
   }

   al = ar = h[0]; bl = br = h[1]; cl = cr = h[2];
   dl = dr = h[3]; el = er = h[4];

   for (j = 0; j < 80; j++) {
      int r = j / 16;
      uint32 t;

      t = ROL(al + rmd_f(j, bl, cl, dl) + X[RL[j]] + KL[r], SL[j]) + el;
      al = el; el = dl; dl = ROL(cl, 10); cl = bl; bl = t;

      t = ROL(ar + rmd_f(79 - j, br, cr, dr) + X[RR[j]] + KR[r], SR[j]) + er;
      ar = er; er = dr; dr = ROL(cr, 10); cr = br; br = t;
   }

   {
      uint32 t = h[1] + cl + dr;
      h[1] = h[2] + dl + er;
      h[2] = h[3] + el + ar;
      h[3] = h[4] + al + br;
      h[4] = h[0] + bl + cr;
      h[0] = t;
   }
}

void
ripemd160(const void *data, size_t len, uint8 digest[20])
{
   uint32 h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu,
                   0x10325476u, 0xC3D2E1F0u };
   const uint8 *p = data;
   uint64 bits = (uint64)len * 8;
   uint8 block[64];
   size_t i;

   while (len >= 64) {
      rmd_transform(h, p);
      p += 64;
      len -= 64;
   }

   memcpy(block, p, len);
   block[len++] = 0x80;
   if (len > 56) {
      memset(block + len, 0, 64 - len);
      rmd_transform(h, block);
      len = 0;
   }
   memset(block + len, 0, 56 - len);
   for (i = 0; i < 8; i++) {
      block[56 + i] = (uint8)(bits >> (8 * i));
   }
   rmd_transform(h, block);

   for (i = 0; i < 5; i++) {
      digest[i * 4]     = (uint8)(h[i]);
      digest[i * 4 + 1] = (uint8)(h[i] >> 8);
      digest[i * 4 + 2] = (uint8)(h[i] >> 16);
      digest[i * 4 + 3] = (uint8)(h[i] >> 24);
   }
}
