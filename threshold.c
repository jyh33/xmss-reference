#include <stdint.h>

#include "params.h"
#include "threshold.h"

/*建立每个份额的随机数
*/
void threshold_key_init(unsigned char sk,unsigned char *ts_sk, const uint32_t oid){
    xmss_params params;
    unsigned int i;

    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        /* For an implementation that uses runtime parameters, it is crucial
        that the OID is part of the secret key as well;
        i.e. not just for interoperability, but also for internal use. */
        ts_sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    return threshold_core_keypair(&params, sk, ts_sk + XMSS_OID_LEN);
} 


int xmssmt_core_keypair(const xmss_params *params,
                        unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[3 * params->n];

    randombytes(seed, 3 * params->n);
    xmssmt_core_seed_keypair(params, pk, sk, seed);

    return 0;
}

int xmssmt_core_seed_keypair(const xmss_params *params,
                             unsigned char *pk, unsigned char *sk,
                             unsigned char *seed)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[params->tree_height * params->n];
    uint32_t top_tree_addr[8] = {0};
    set_layer_addr(top_tree_addr, params->d - 1);

    /* Initialize index to 0. */
    memset(sk, 0, params->index_bytes);
    sk += params->index_bytes;

    /* Initialize SK_SEED and SK_PRF. */
    memcpy(sk, seed, 2 * params->n);

    /* Initialize PUB_SEED. */
    memcpy(sk + 3 * params->n, seed + 2 * params->n,  params->n);
    memcpy(pk + params->n, sk + 3*params->n, params->n);

    /* Compute root node of the top-most subtree. */
    treehash(params, pk, auth_path, sk, pk + params->n, 0, top_tree_addr);
    memcpy(sk + 2*params->n, pk, params->n);

    return 0;
}