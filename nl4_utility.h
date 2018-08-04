#ifndef __NL4_UTILITY_H__
#define __NL4_UTILITY_H__

#define ENCRYPTION 0x1
#define DECRYPTION 0x0


//Crypto Reference
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/err.h>


struct tcrypt_result {
	struct completion completion;
	int err;
};

/* tie all data structures together */
struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct tcrypt_result result;
};

char padding_fill(int data_len);
char padding_check(char * data, int len);

int aes_crypto_cipher(char *, __u16, int);

#endif