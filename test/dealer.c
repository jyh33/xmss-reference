#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"
#include "../threshold.h"

#define XMSS_MLEN 32

#ifndef XMSS_SIGNATURES
    #define XMSS_SIGNATURES 16
#endif

#define THRESHOLD_T 2
#define THRESHOLD_N 3

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif 

int main()
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int THRESHOLD_DIVIDE;
    int THRESHOLD_EACH_SEED;
    int i;

    THRESHOLD_DIVIDE = ts_fact(THRESHOLD_N) / (ts_fact(THRESHOLD_T-1) * ts_fact(THRESHOLD_N - THRESHOLD_T + 1));
    THRESHOLD_EACH_SEED = THRESHOLD_DIVIDE - ts_fact(THRESHOLD_N-1) / (ts_fact(THRESHOLD_T-2) * ts_fact(THRESHOLD_N - THRESHOLD_T + 1));

    // TODO test more different variants
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *helper_sk = malloc(XMSS_OID_LEN + params.index_bytes)
    unsigned long long smlen;
    unsigned long long ts_smlen[THRESHOLD_DIVIDE];
    unsigned long long mlen;

    //    unsigned char THRESHOLD_sk[THRESHOLD_DIVIDE][XMSS_OID_LEN + params.sk_bytes];
    unsigned char **THRESHOLD_sk = malloc(THRESHOLD_DIVIDE * sizeof(unsigned char *));
    for (i = 0; i < THRESHOLD_DIVIDE; i++) {
        THRESHOLD_sk[i] = malloc((XMSS_OID_LEN + params.sk_bytes) * sizeof(unsigned char));
    }

    unsigned char **THRESHOLD_sm = malloc(THRESHOLD_DIVIDE * sizeof(unsigned char *));
    for (i = 0; i < THRESHOLD_DIVIDE; i++) {
        THRESHOLD_sm[i] = malloc((params.sig_bytes + XMSS_MLEN) * sizeof(unsigned char));
    }

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */

    FILE *file = fopen("helper.save", "w+b");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    XMSS_KEYPAIR(pk, sk, oid);

    for (i = 0; i < THRESHOLD_DIVIDE ; i++){
        printf("Initing THRESHOLD_sk \n");
        threshold_key_init(sk, THRESHOLD_sk[i],oid);
    }
    threshold_helper_divide(sk, THRESHOLD_sk, THRESHOLD_DIVIDE, helper_sk, file);

    randombytes(m, XMSS_MLEN);

    printf("Testing %d %s signatures.. \n", XMSS_SIGNATURES, XMSS_VARIANT);

    for (i = 0; i < XMSS_SIGNATURES; i++) {
        printf("  - iteration #%d:\n", i);

        XMSS_SIGN(sk, sm, &smlen, m, XMSS_MLEN);

        for (i = 0; i < THRESHOLD_DIVIDE ; i++){
            printf("THRESHOLD part %d signing \n", i);
            xmss_sign(THRESHOLD_sk[i], THRESHOLD_sm[i], &ts_smlen[i], m, XMSS_MLEN);
        }

        threshold_sign(THRESHOLD_sm, file);

        printf("THRESHOLD helper signing \n");
        threshold_sign()

        if (smlen != params.sig_bytes + XMSS_MLEN) {
            printf("  X smlen incorrect [%llu != %u]!\n",
                   smlen, params.sig_bytes);
            ret = -1;
        }
        else {
            printf("    smlen as expected [%llu].\n", smlen);
        }

        /* Test if signature is valid. */
        if (XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
            printf("  X verification failed!\n");
            ret = -1;
        }
        else {
            printf("    verification succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (mlen != XMSS_MLEN) {
            printf("  X mlen incorrect [%llu != %u]!\n", mlen, XMSS_MLEN);
            ret = -1;
        }
        else {
            printf("    mlen as expected [%llu].\n", mlen);
        }
        if (memcmp(m, mout, XMSS_MLEN)) {
            printf("  X output message incorrect!\n");
            ret = -1;
        }
        else {
            printf("    output message as expected.\n");
        }

        /* Test if flipping bits invalidates the signature (it should). */

        /* Flip the first bit of the message. Should invalidate. */
        sm[smlen - 1] ^= 1;
        if (!XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
            printf("  X flipping a bit of m DID NOT invalidate signature!\n");
            ret = -1;
        }
        else {
            printf("    flipping a bit of m invalidates signature.\n");
        }
        sm[smlen - 1] ^= 1;

#ifdef XMSS_TEST_INVALIDSIG
        int j;
        /* Flip one bit per hash; the signature is almost entirely hashes.
           This also flips a bit in the index, which is also a useful test. */
        for (j = 0; j < (int)(smlen - XMSS_MLEN); j += params.n) {
            sm[j] ^= 1;
            if (!XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
                printf("  X flipping bit %d DID NOT invalidate sig + m!\n", j);
                sm[j] ^= 1;
                ret = -1;
                break;
            }
            sm[j] ^= 1;
        }
        if (j >= (int)(smlen - XMSS_MLEN)) {
            printf("    changing any signature hash invalidates signature.\n");
        }
#endif
    }

    free(m);
    free(sm);
    free(mout);

    for (size_t i = 0; i < THRESHOLD_DIVIDE; i++) {
        free(THRESHOLD_sk[i]);
    }
    free(THRESHOLD_sk);
    fclose(file);

    return ret;
}
