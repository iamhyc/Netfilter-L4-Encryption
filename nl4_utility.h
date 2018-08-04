#ifndef __NL4_UTILITY_H__
#define __NL4_UTILITY_H__

#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/err.h>

#define KEYWORD "[nl4-aes]"
#define KERN_LOG KERN_NOTICE KEYWORD
#define printh(x) printk(KERN_LOG x)

#define ENCRYPTION	0x1
#define DECRYPTION	0x0
#define COMP_LENGTH(x) ((16-x%16)&0x00FF)

#define INBOUND     0x0
#define OUTBOUND    0x1
#define IPV4A(x)   ((u8 *)x)[0]
#define IPV4B(x)   ((u8 *)x)[1]
#define IPV4C(x)   ((u8 *)x)[2]
#define IPV4D(x)   ((u8 *)x)[3]

#define GET_PPDST(iph)  (__be16 *)((char *)iph + iph->ihl*4 + 2)
#define GET_PDST(iph)   ntohs(*GET_PPDST(iph))
#define GET_PPSRC(iph)  (__be16 *)((char *)iph + iph->ihl*4 + 4)
#define GET_PSRC(iph)   ntohs(*GET_PPSRC(iph))

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

u32 IP2NUM(const char *addr);
inline void NUM2IP(u32 addr, char *str);

char get_comp_length(char * data, int len);

int aes_crypto_cipher(char *, __u16, int);

#endif