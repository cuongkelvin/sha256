#ifndef __TEST_VECTOR__
#define __TEST_VECTOR__

#include <stddef.h>
#include <sys/types.h>
#include <string.h>
 
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
/*
 * FIPS specification refers to right rotations, while our ROTATE macro
 * is left one. This is why you might notice that rotation coefficients
 * differ from those observed in FIPS document by 32-N...
 */
#ifndef Sigma0
# define Sigma0(x)       (ROTATE((x),30) ^ ROTATE((x),19) ^ ROTATE((x),10))
#endif
#ifndef Sigma1
# define Sigma1(x)       (ROTATE((x),26) ^ ROTATE((x),21) ^ ROTATE((x),7))
#endif
#ifndef sigma0
# define sigma0(x)       (ROTATE((x),25) ^ ROTATE((x),14) ^ ((x)>>3))
#endif
#ifndef sigma1
# define sigma1(x)       (ROTATE((x),15) ^ ROTATE((x),13) ^ ((x)>>10))
#endif
#ifndef Ch
# define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
#endif
#ifndef Maj
# define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#endif


#define SHA256_192_DIGEST_LENGTH 24
#define SHA224_DIGEST_LENGTH    28
#define SHA256_DIGEST_LENGTH    32
#define SHA384_DIGEST_LENGTH    48
#define SHA512_DIGEST_LENGTH    64

#define SHA_LONG unsigned long
#define SHA_LBLOCK      16
#define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */


typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;


int SHA256_Init(SHA256_CTX *c);
static void sha256_update(SHA256_CTX *c, const void *data, size_t len);

#endif