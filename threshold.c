#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "threshold.h"
#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_core.h"

static treehash(const xmss_params *params,
                     unsigned char *root, unsigned char *auth_path,
                     const unsigned char *sk_seed,
                     const unsigned char *pub_seed,
                     uint32_t leaf_idx, const uint32_t subtree_addr[8])
{
    unsigned char stack[(params->tree_height+1)*params->n];
    unsigned int heights[params->tree_height+1];
    unsigned int offset = 0;

    /* The subtree has at most 2^20 leafs, so uint32_t suffices. */
    uint32_t idx;
    uint32_t tree_idx;

    /* We need all three types of addresses in parallel. */
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    /* Select the required subtree. */
    copy_subtree_addr(ots_addr, subtree_addr);
    copy_subtree_addr(ltree_addr, subtree_addr);
    copy_subtree_addr(node_addr, subtree_addr);

    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);

    for (idx = 0; idx < (uint32_t)(1 << params->tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        gen_leaf_wots(params, stack + offset*params->n,
                      sk_seed, pub_seed, ltree_addr, ots_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1)*params->n, params->n);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Hash the top-most nodes from the stack together. */
            /* Note that tree height is the 'lower' layer, even though we use
               the index of the new node on the 'higher' layer. This follows
               from the fact that we address the hash function calls. */
            set_tree_height(node_addr, heights[offset - 1]);
            set_tree_index(node_addr, tree_idx);
            thash_h(params, stack + (offset-2)*params->n,
                           stack + (offset-2)*params->n, pub_seed, node_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1]*params->n,
                       stack + (offset - 1)*params->n, params->n);
            }
        }
    }
    memcpy(root, stack, params->n);
}

void print_unsigned_char_array(const unsigned char *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", arr[i]);
    }
    printf("\n");
}
/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
//建立每个份额的随机数种子

int threshold_key_init(unsigned char *sk,unsigned char *ts_sk, const uint32_t oid){

    xmss_params params;

    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    memcpy(ts_sk, sk, XMSS_OID_LEN + params.sk_bytes);

    ts_sk += XMSS_OID_LEN;
    ts_sk += params.index_bytes;

    unsigned char seed[3 * params.n];

    randombytes(seed, 3 * params.n);

    memcpy(ts_sk, seed, 2 * params.n);

    memcpy(ts_sk + 3 * params.n, seed + 2 * params.n,  params.n);
    
    return 0;
} 


//门限种子分配，我们一共有C(n,t−1)份种子，每人C(n−1,t−2)个种子
void threshold_part_divide(unsigned char *ts_in_sk, unsigned char *ts_out_sk, 
                        int size, int each_seed)
{

}

//门限参与方签名份额生成，helper的份额产生并按行存入wots_file与path_file当中
int threshold_helper_divide(unsigned char *sk,unsigned char **ts_sk, 
                        int size, unsigned char *helper_sk, FILE *hleper_file)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;
    unsigned int j;
    unsigned int z;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }

    for (i = 0; i < XMSS_OID_LEN + params.index_bytes; i++) {
        helper_sk[i]= sk[i];
    }

    const unsigned char *sk_seed = sk + params.index_bytes;
    const unsigned char *sk_prf = sk + params.index_bytes + params.n;
    const unsigned char *pub_root = sk + params.index_bytes + 2*params.n;
    const unsigned char *pub_seed = sk + params.index_bytes + 3*params.n;

/*      
    params->sig_bytes = (params->index_bytes + params->n
                         + params->d * params->wots_sig_bytes
                         + params->full_height * params->n);
*/
//[index || first_tree_path || 2th_tree_sign || 2th_tree_path || ...... || first_tree_sign_full_Matrix]
//    unsigned char helper_cache[params.index_bytes 
//                         + (params.d - 1) * params.wots_sig_bytes
//                         + params.full_height * params.n + params.wots_w * params.wots_sig_bytes];
    unsigned char *helper_cache = malloc(params.index_bytes 
                         + (params.d - 1) * params.wots_sig_bytes
                         + params.full_height * params.n + params.wots_w * params.wots_sig_bytes);
    if (!helper_cache) {
        perror("sig allocation failed");
        exit(-2);
    }

    unsigned char *helper_buff = malloc(params.index_bytes 
                         + (params.d - 1) * params.wots_sig_bytes
                         + params.full_height * params.n + params.wots_w * params.wots_sig_bytes);
    if (!helper_buff) {
        perror("sig allocation failed");
        exit(-2);
    }
//    unsigned char helper_buff[params.index_bytes 
//                         + (params.d - 1) * params.wots_sig_bytes
//                         + params.full_height * params.n + params.wots_w * params.wots_sig_bytes];
    unsigned char root[params.n];
    unsigned char *mhash = root;
    unsigned long long idx;
    unsigned char idx_bytes_32[32];
//    unsigned int i;
    uint32_t idx_leaf;

    uint32_t ots_addr[8] = {0};
    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
//    memcpy(sm + params->sig_bytes, m, mlen);
//    *smlen = params->sig_bytes + mlen;



    for(bool sk_flag = true; sk_flag; ){

        /* Read and use the current index from the secret key. */
        idx = (unsigned long)bytes_to_ull(sk, params.index_bytes);
        printf("%ld \n", idx);
        
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

        
        if (idx >= ((1ULL << params.full_height) - 1)) {
            // Delete secret key here. We only do this in memory, production code
            // has to make sure that this happens on disk.
        //    memset(sk, 0xFF, params->index_bytes);
        //    memset(sk + params->index_bytes, 0, (params->sk_bytes - params->index_bytes));
            ull_to_bytes(sk, params.index_bytes, 0);
            if (idx > ((1ULL << params.full_height) - 1))
                sk_flag = false; // We already used all one-time keys
            if ((params.full_height == 64) && (idx == ((1ULL << params.full_height) - 1))) 
                sk_flag = false; // We already used all one-time keys
        }
        
    //    memcpy(sm, sk, params->index_bytes);

        /*************************************************************************
         * THIS IS WHERE PRODUCTION IMPLEMENTATIONS WOULD UPDATE THE SECRET KEY. *
         *************************************************************************/
        /* Increment the index in the secret key. */
        ull_to_bytes(sk, params.index_bytes, idx + 1);

        /* Compute the digest randomization value. */
    //    ull_to_bytes(idx_bytes_32, 32, idx);
    //    prf(&params, sm + params.index_bytes, idx_bytes_32, sk_prf);

        /* Compute the message hash. 
        hash_message(params, mhash, sm + params->index_bytes, pub_root, idx,
                    sm + params->sig_bytes - params->padding_len - 3*params->n,
                    mlen);
        sm += params->index_bytes + params->n;
        */
        set_type(ots_addr, XMSS_ADDR_TYPE_OTS);


        for (i = 0; i < params.d; i++) {
            idx_leaf = (idx & ((1 << params.tree_height)-1));
            idx = idx >> params.tree_height;

            set_layer_addr(ots_addr, i);
            set_tree_addr(ots_addr, idx);
            set_ots_addr(ots_addr, idx_leaf);
//            printf(i);
//            print_unsigned_char_array(sk , XMSS_OID_LEN + params.sk_bytes);
//            printf("%ld \n", sizeof(sk));

            /* Compute a WOTS signature. */
            /* Initially, root = mhash, but on subsequent iterations it is the root
            of the subtree below the currently processed subtree. */
            if(i==0){
                wots_sign_all(&params, helper_cache + params.index_bytes, sk_seed, pub_seed, ots_addr);
//                helper_cache += params-> *params->wots_sig_bytes;
            }
            else{
                wots_sign(&params, helper_cache + params.index_bytes + params.wots_w * params.wots_sig_bytes + params.tree_height*params.n*i + params.wots_sig_bytes*(i-1) , root, sk_seed, pub_seed, ots_addr);
//                helper_cache += params-> *params->wots_sig_bytes;
            }

            /* Compute the authentication path for the used WOTS leaf. */
            treehash(&params, root, helper_cache + params.index_bytes + params.wots_w * params.wots_sig_bytes + params.tree_height*params.n*i + params.wots_sig_bytes*i , sk_seed, pub_seed, idx_leaf, ots_addr);
//            sm += params->tree_height*params->n;            
        }
        for (j=0; j < size; j++){
            for (i = 0; i < params.d; i++) {
                idx_leaf = (idx & ((1 << params.tree_height)-1));
                idx = idx >> params.tree_height;

                set_layer_addr(ots_addr, i);
                set_tree_addr(ots_addr, idx);
                set_ots_addr(ots_addr, idx_leaf);
//                printf(i);

                /* Compute a WOTS signature. */
                /* Initially, root = mhash, but on subsequent iterations it is the root
                of the subtree below the currently processed subtree. */
                if(i==0){
//                    print_unsigned_char_array(ts_sk[j] , XMSS_OID_LEN + params.sk_bytes);
//                    printf("%ld \n", sizeof(ts_sk[j]));
                    wots_sign_all(&params, helper_buff + params.index_bytes, ts_sk[j] + params.index_bytes, pub_seed, ots_addr);
    //                helper_cache += params-> *params->wots_sig_bytes;
                }
                else{
                    wots_sign(&params, helper_buff + params.index_bytes + params.wots_w * params.wots_sig_bytes
                    + params.tree_height*params.n*i + params.wots_sig_bytes*(i-1) , root, ts_sk[j] + params.index_bytes, pub_seed, ots_addr);
    //                helper_cache += params-> *params->wots_sig_bytes;
                }

                /* Compute the authentication path for the used WOTS leaf. */
                treehash(&params, root, helper_buff + params.index_bytes + params.wots_w * params.wots_sig_bytes
                + params.tree_height*params.n*i + params.wots_sig_bytes*i , ts_sk[j] + params.index_bytes, pub_seed, idx_leaf, ots_addr);
    //            sm += params->tree_height*params->n;
            
            }

            for (z = 0; z < (params.d - 1) * params.wots_sig_bytes + params.full_height * params.n + params.wots_w * params.wots_sig_bytes; z++) {
                    helper_cache[params.index_bytes + z] ^= helper_buff[params.index_bytes + z];
            }

        }        

        fwrite(helper_cache, sizeof(unsigned char), params.index_bytes 
                         + (params.d - 1) * params.wots_sig_bytes
                         + params.full_height * params.n + params.wots_w * params.wots_sig_bytes, hleper_file);
//        fputc("\n", hleper_file);
        fflush(hleper_file);
    }
    free(helper_buff);
    free(helper_cache);
    return 0;
}

void wots_sign_all(const xmss_params *params,
               unsigned char *sig, const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[params->wots_len * params->n];
    uint32_t i;
    uint32_t j;
//    unsigned char exp_seed[params->wots_len * params->n];
    unsigned char *exp_seed = malloc(params->wots_len * params->n);
    if (!exp_seed) {
        perror("sig allocation failed");
        exit(-2);
    }
//    printf("len: %zu\n", params->wots_len);

//    printf("len: %zu\n", params->n);

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, exp_seed, seed, pub_seed, addr);

    for(j = 0; j < params -> wots_w; j++ ) {
        set_lengths(params, lengths, j);
        for (i = 0; i < params->wots_len; i++) {
            set_chain_addr(addr, i);
            gen_chain(params, sig + i*params->n + j * params->wots_len * params->n, exp_seed + i*params->n,
                    0, lengths[i], pub_seed, addr);
//            printf("%d %d \n", j, i);
        }
    }
    free(exp_seed);
}

void set_lengths(const xmss_params *params, int *lengths, int j){
    for(int i = 0; i< params->wots_len; i++){
        lengths[i] = j;
    }
}


//helper签名流程
int threshold_sign(unsigned char **ts_sm, FILE *hleper_file
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