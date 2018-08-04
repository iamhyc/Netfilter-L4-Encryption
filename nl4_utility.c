
#include <linux/string.h>
#include "nl4_utility.h"

u32 IP2NUM(const char *addr)
{
    u8 num[4];
    int a,b,c,d;
    sscanf(addr, "%d.%d.%d.%d", &a,&b,&c,&d);
    num[0]=a; num[1]=b; num[2]=c; num[3]=d;
    return *(u32 *)num;
}

inline void NUM2IP(u32 addr, char *str)
{
    snprintf(str, 16, "%pI4", &addr);
}

char get_comp_length(char * data, int len)
{
	char ex;
	int i = 0;

	ex = data[len - 1]; //the last element
	if ( (ex&0x00FF) == 0)
		return 0;

	for (i = 1; i < ex; i++)
	{
		if (data[len-1 - i] != 0)
			return 0;
	}

	return ex;
}

/***************proto define***************/
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc);
static void test_skcipher_cb(struct crypto_async_request *req, int error);

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
	struct tcrypt_result *result = req->data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
	//pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
					 int enc)
{
	int rc = 0;

	if (enc)
		rc = crypto_skcipher_encrypt(sk->req);
	else
		rc = crypto_skcipher_decrypt(sk->req);

	switch (rc) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		rc = wait_for_completion_interruptible(
			&sk->result.completion);
		if (!rc && !sk->result.err) {
			reinit_completion(&sk->result.completion);
			break;
		}
	default:
		//pr_info("skcipher encrypt returned with %d result %d\n", rc, sk->result.err);
		break;
	}
	init_completion(&sk->result.completion);

	return rc;
}

int aes_crypto_cipher(	char* data, __u16 data_len,
						int enc) 
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	unsigned char key[32];
	int ret = -EFAULT, i;

	//allocate skcipher handle
	skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}
	//allocate skcipher request
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	//set callback for request
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, \
				      test_skcipher_cb, \
				      &sk.result);

	/* AES 256 with certain key */
	memset(key, 1, 32);//FULL 'F'
	/*get_random_bytes(&key, 32);*/
	if (crypto_skcipher_setkey(skcipher, key, 32)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	/* IV will be all 0 */
	ivdata = kmalloc(16, GFP_KERNEL);
	if (!ivdata) {
		pr_info("could not allocate ivdata\n");
		goto out;
	}
	memset(ivdata, 0, 16);
	/*get_random_bytes(ivdata, 16);*/

	sk.tfm = skcipher;
	sk.req = req;

	for (i = 0; i < data_len/16; i++)
	{
		/* We encrypt one block */
		sg_init_one(&sk.sg, data + i*16, 16);//sg_init_table(&sgl, data_len/16);
		skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
		init_completion(&sk.result.completion);

		/* encrypt data */
		ret = test_skcipher_encdec(&sk, enc);
	}
	
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (ivdata)
		kfree(ivdata);
	return ret;
}