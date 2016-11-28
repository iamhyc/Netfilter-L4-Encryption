#ifndef __AES_METHOD_H
#define __AES_METHOD_H

#define ENCRYPTION 0x1
#define DECRYPTION 0x0

#include <linux/skbuff.h>


//Crypto Reference
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/gfp.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/highmem.h>

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


char paddingFill(char *, int);
int aes_crypto_cipher(struct sk_buff *, char *, __u16, int);

#endif