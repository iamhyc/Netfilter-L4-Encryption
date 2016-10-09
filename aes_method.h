#ifndef __AES_METHOD_H
#define __AES_METHOD_H

#define ENCRYPTION 0x1
#define DECRYPTION 0x0

#include <linux/skbuff.h>

//Crypto Reference
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/jiffies.h>

char paddingFill(char *, int);

void aes_crypto_cipher(struct sk_buff *, char *, __u16, int);

#endif