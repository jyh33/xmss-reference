#include <stdint.h>

#include "params.h"
#include "threshold.h"
#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_core.h"


/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
//建立每个份额的随机数种子

void threshold_key_init(unsigned char sk,unsigned char *ts_sk, const uint32_t oid){

    xmss_params params;
    unsigned int i;

    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    ts_sk = sk;

    ts_sk += XMSS_OID_LEN;
    ts_sk += params->index_bytes;

    unsigned char seed[3 * params->n];

    randombytes(seed, 3 * params->n);

    memcpy(ts_sk, seed, 2 * params->n);

    memcpy(ts_sk + 3 * params->n, seed + 2 * params->n,  params->n);
    
    return 0;
} 


//门限种子分配，我们一共有C(n,t−1)份种子，每人C(n−1,t−2)个种子
void threshold_part_divide(unsigned char *ts_in_sk, unsigned char *ts_out_sk, 
                        int size, int each_seed)
{

}

//门限参与方签名份额生成，helper的份额产生并按行存入wots_file与path_file当中
int threshold_helper_divide(unsigned char sk, unsigned char *ts_sk, 
                        int size, int each_seed)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }

    const unsigned char *sk_seed = sk + params->index_bytes;
    const unsigned char *sk_prf = sk + params->index_bytes + params->n;
    const unsigned char *pub_root = sk + params->index_bytes + 2*params->n;
    const unsigned char *pub_seed = sk + params->index_bytes + 3*params->n;

    unsigned char root[params->n];
    unsigned char *mhash = root;
    unsigned long long idx;
    unsigned char idx_bytes_32[32];
    unsigned int i;
    uint32_t idx_leaf;

    uint32_t ots_addr[8] = {0};
    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
//    memcpy(sm + params->sig_bytes, m, mlen);
//    *smlen = params->sig_bytes + mlen;



//while()
    /* Read and use the current index from the secret key. */
    idx = (unsigned long)bytes_to_ull(sk, params->index_bytes);
    
    /* Check if we can still sign with this sk.
     * If not, return -2
     * 
     * If this is the last possible signature (because the max index value 
     * is reached), production implementations should delete the secret key 
     * to prevent accidental further use.
     * 
     * For the case of total tree height of 64 we do not use the last signature 
     * to be on the safe side (there is no index value left to indicate that the 
     * key is finished, hence external handling would be necessary)
     */ 

    /*
    if (idx >= ((1ULL << params->full_height) - 1)) {
        // Delete secret key here. We only do this in memory, production code
        // has to make sure that this happens on disk.
        memset(sk, 0xFF, params->index_bytes);
        memset(sk + params->index_bytes, 0, (params->sk_bytes - params->index_bytes));
        if (idx > ((1ULL << params->full_height) - 1))
            return -2; // We already used all one-time keys
        if ((params->full_height == 64) && (idx == ((1ULL << params->full_height) - 1))) 
                return -2; // We already used all one-time keys
    }
    */
//    memcpy(sm, sk, params->index_bytes);

    /*************************************************************************
     * THIS IS WHERE PRODUCTION IMPLEMENTATIONS WOULD UPDATE THE SECRET KEY. *
     *************************************************************************/
    /* Increment the index in the secret key. */
    ull_to_bytes(sk, params->index_bytes, idx + 1);

    /* Compute the digest randomization value. */
    ull_to_bytes(idx_bytes_32, 32, idx);
    prf(params, sm + params->index_bytes, idx_bytes_32, sk_prf);

    /* Compute the message hash. 
    hash_message(params, mhash, sm + params->index_bytes, pub_root, idx,
                 sm + params->sig_bytes - params->padding_len - 3*params->n,
                 mlen);
    sm += params->index_bytes + params->n;
    */
    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);



    for (i = 0; i < params->d; i++) {
        idx_leaf = (idx & ((1 << params->tree_height)-1));
        idx = idx >> params->tree_height;

        set_layer_addr(ots_addr, i);
        set_tree_addr(ots_addr, idx);
        set_ots_addr(ots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        /* Initially, root = mhash, but on subsequent iterations it is the root
           of the subtree below the currently processed subtree. */
        wots_sign(params, sm, root, sk_seed, pub_seed, ots_addr);
        sm += params->wots_sig_bytes;   

        /* Compute the authentication path for the used WOTS leaf. */
        treehash(params, root, sm, sk_seed, pub_seed, idx_leaf, ots_addr);
        sm += params->tree_height*params->n;     
    
    }

    return 0;
}

void wots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;

    chain_lengths(params, lengths, msg);

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, sig, seed, pub_seed, addr);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, sig + i*params->n, sig + i*params->n,
                  0, lengths[i], pub_seed, addr);
    }
}

//helper签名流程
int threshold_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    return threshold_core_sign(&params, sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}
/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int threshold_core_sign(const xmss_params *params,
                   unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen)
{
    /* XMSS signatures are fundamentally an instance of XMSSMT signatures.
       For d=1, as is the case with XMSS, some of the calls in the XMSSMT
       routine become vacuous (i.e. the loop only iterates once, and address
       management can be simplified a bit).*/
    return thresholdmt_core_sign(params, sk, sm, smlen, m, mlen);
}

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int thresholdmt_core_sign(const xmss_params *params,
                     unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen)
{
    const unsigned char *sk_seed = sk + params->index_bytes;
    const unsigned char *sk_prf = sk + params->index_bytes + params->n;
    const unsigned char *pub_root = sk + params->index_bytes + 2*params->n;
    const unsigned char *pub_seed = sk + params->index_bytes + 3*params->n;

    unsigned char root[params->n];
    unsigned char *mhash = root;
    unsigned long long idx;
    unsigned char idx_bytes_32[32];
    unsigned int i;
    uint32_t idx_leaf;

    uint32_t ots_addr[8] = {0};
    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    memcpy(sm + params->sig_bytes, m, mlen);
    *smlen = params->sig_bytes + mlen;

    /* Read and use the current index from the secret key. */
    idx = (unsigned long)bytes_to_ull(sk, params->index_bytes);
    
    /* Check if we can still sign with this sk.
     * If not, return -2
     * 
     * If this is the last possible signature (because the max index value 
     * is reached), production implementations should delete the secret key 
     * to prevent accidental further use.
     * 
     * For the case of total tree height of 64 we do not use the last signature 
     * to be on the safe side (there is no index value left to indicate that the 
     * key is finished, hence external handling would be necessary)
     */ 
    if (idx >= ((1ULL << params->full_height) - 1)) {
        // Delete secret key here. We only do this in memory, production code
        // has to make sure that this happens on disk.
        memset(sk, 0xFF, params->index_bytes);
        memset(sk + params->index_bytes, 0, (params->sk_bytes - params->index_bytes));
        if (idx > ((1ULL << params->full_height) - 1))
            return -2; // We already used all one-time keys
        if ((params->full_height == 64) && (idx == ((1ULL << params->full_height) - 1))) 
                return -2; // We already used all one-time keys
    }
    
    memcpy(sm, sk, params->index_bytes);

    /*************************************************************************
     * THIS IS WHERE PRODUCTION IMPLEMENTATIONS WOULD UPDATE THE SECRET KEY. *
     *************************************************************************/
    /* Increment the index in the secret key. */
    ull_to_bytes(sk, params->index_bytes, idx + 1);

    /* Compute the digest randomization value. */
    ull_to_bytes(idx_bytes_32, 32, idx);
    prf(params, sm + params->index_bytes, idx_bytes_32, sk_prf);

    /* Compute the message hash. */
    hash_message(params, mhash, sm + params->index_bytes, pub_root, idx,
                 sm + params->sig_bytes - params->padding_len - 3*params->n,
                 mlen);
    sm += params->index_bytes + params->n;

    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    for (i = 0; i < params->d; i++) {
        idx_leaf = (idx & ((1 << params->tree_height)-1));
        idx = idx >> params->tree_height;

        set_layer_addr(ots_addr, i);
        set_tree_addr(ots_addr, idx);
        set_ots_addr(ots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        /* Initially, root = mhash, but on subsequent iterations it is the root
           of the subtree below the currently processed subtree. */
        wots_sign(params, sm, root, sk_seed, pub_seed, ots_addr);
        sm += params->wots_sig_bytes;

        /* Compute the authentication path for the used WOTS leaf. */
        treehash(params, root, sm, sk_seed, pub_seed, idx_leaf, ots_addr);
        sm += params->tree_height*params->n;
    }

    return 0;
}