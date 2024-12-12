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
#define THRESHOLD_KEY threshold_key_init
#define THRESHOLD_PART threshold_part

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
/*
void print_unsigned_char_array(const unsigned char *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", arr[i]);
    }
    printf("\n");
}
*/

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
    unsigned long long smlen;
    unsigned long long mlen;

    unsigned char THRESHOLD_sk[THRESHOLD_DIVIDE][XMSS_OID_LEN + params.sk_bytes];

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
    FILE *file = fopen("example.txt", "rw");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    XMSS_KEYPAIR(pk, sk, oid);

    for (i = 0; i < THRESHOLD_DIVIDE ; i++){
        printf("Initing THRESHOLD_sk \n");
        threshold_key_init(sk, THRESHOLD_sk[i],oid);
    }
    threshold_helper_divide(sk, THRESHOLD_sk, THRESHOLD_DIVIDE, file);
}

