#ifndef THRESHOLD_H
#define THRESHOLD_H

#include "params.h"

void threshold_key_init(unsigned char sk,unsigned char *ts_sk, const uint32_t oid);

void threshold_part_divide(unsigned char *ts_in_sk, unsigned char *ts_out_sk, 
                        int size, int each_seed);

int threshold_helper_divide(unsigned char sk, unsigned char **ts_sk, 
                        int size, FILE *hleper_file);


void wots_sign_all(const xmss_params *params,
               unsigned char *sig, const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8]);


void set_lengths(int *lengths, int j);


#endif