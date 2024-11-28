#ifndef XMSS_RANDOMBYTES_H
#define XMSS_RANDOMBYTES_H

/**
 * Tries to read xlen bytes from a source of randomness, and writes them to x.
 */
void randombytes(unsigned char *x, unsigned long long xlen);

int fact(int num);//求num的阶乘的函数

#endif
