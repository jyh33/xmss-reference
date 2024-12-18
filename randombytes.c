/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#include <fcntl.h>
#include <unistd.h>

static int fd = -1;

void randombytes(unsigned char *x, unsigned long long xlen)
{
    int i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) {
            i = xlen;
        }
        else {
            i = 1048576;
        }

        i = read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}

int ts_fact(int num)//求num的阶乘的函数
//5=5*4！=5*（4*3*2*1）
//4=4*3！=4*（3*2*1）
//递归的思想，列出函数，直接对着写
{
	if (num < 0)
	{
		return 0;
	}
	if (num == 1||num == 0)
	{
		return 1;
	}
	if (num > 1)
	{
		return num * ts_fact(num - 1);
	}
    else{
        return -1;
    }
}