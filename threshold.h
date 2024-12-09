#ifndef THRESHOLD_H
#define THRESHOLD_H

#include "params.h"

int threshold_key_init(unsigned char *sk,unsigned char *ts_sk, const uint32_t oid);

void threshold_part_divide(unsigned char *ts_in_sk, unsigned char *ts_out_sk, 
                        int size, int each_seed);

int threshold_helper_divide(unsigned char *sk, unsigned char **ts_sk, 
                        int size, FILE *hleper_file);


void wots_sign_all(const xmss_params *params,
               unsigned char *sig, const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8]);


void set_lengths(const xmss_params *params, int *lengths, int j);

static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed, 
                        const unsigned char *pub_seed, uint32_t addr[8]);


int threshold_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen);

int threshold_core_sign(const xmss_params *params,
                   unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen);




#endif