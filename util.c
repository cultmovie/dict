#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>

#include "util.h"
#include "sha256.h"

/* Get random bytes, attempts to get an initial seed from /dev/urandom and
 * the uses a one way hash function in counter mode to generate a random
 * stream. However if /dev/urandom is not available, a weaker seed is used.
 *
 * This function is not thread safe, since the state is global. */
void getRandomBytes(unsigned char *p, size_t len) {
    /* Global state. */
    static int seed_initialized = 0;
    static unsigned char seed[64]; /* 512 bit internal block size. */
    static uint64_t counter = 0; /* The counter we hash with the seed. */

    if (!seed_initialized) {
        /* Initialize a seed and use SHA1 in counter mode, where we hash
         * the same seed with a progressive counter. For the goals of this
         * function we just need non-colliding strings, there are no
         * cryptographic security needs. */
        FILE *fp = fopen("/dev/urandom","r");
        if (fp == NULL || fread(seed,sizeof(seed),1,fp) != 1) {
            /* Revert to a weaker seed, and in this case reseed again
             * at every call.*/
            for (unsigned int j = 0; j < sizeof(seed); j++) {
                struct timeval tv;
                gettimeofday(&tv,NULL);
                pid_t pid = getpid();
                seed[j] = tv.tv_sec ^ tv.tv_usec ^ pid ^ (long)fp;
            }
        } else {
            seed_initialized = 1;
        }
        if (fp) fclose(fp);
    }

    while(len) {
        /* This implements SHA256-HMAC. */
        unsigned char digest[SHA256_BLOCK_SIZE];
        unsigned char kxor[64];
        unsigned int copylen =
            len > SHA256_BLOCK_SIZE ? SHA256_BLOCK_SIZE : len;

        /* IKEY: key xored with 0x36. */
        memcpy(kxor,seed,sizeof(kxor));
        for (unsigned int i = 0; i < sizeof(kxor); i++) kxor[i] ^= 0x36;

        /* Obtain HASH(IKEY||MESSAGE). */
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx,kxor,sizeof(kxor));
        sha256_update(&ctx,(unsigned char*)&counter,sizeof(counter));
        sha256_final(&ctx,digest);

        /* OKEY: key xored with 0x5c. */
        memcpy(kxor,seed,sizeof(kxor));
        for (unsigned int i = 0; i < sizeof(kxor); i++) kxor[i] ^= 0x5C;

        /* Obtain HASH(OKEY || HASH(IKEY||MESSAGE)). */
        sha256_init(&ctx);
        sha256_update(&ctx,kxor,sizeof(kxor));
        sha256_update(&ctx,digest,SHA256_BLOCK_SIZE);
        sha256_final(&ctx,digest);

        /* Increment the counter for the next iteration. */
        counter++;

        memcpy(p,digest,copylen);
        len -= copylen;
        p += copylen;
    }
}
