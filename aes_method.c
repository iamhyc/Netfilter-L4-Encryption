
#include <linux/string.h>
#include "aes_method.h"

/*

*/

/***************proto define***************/
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc);
static void test_skcipher_cb(struct crypto_async_request *req, int error);

int aes_crypto_cipher(struct sk_buff *skb, 
						char* data, __u16 data_len,
						int enc) {
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *scratchpad = NULL;
	char *ivdata = NULL;
	unsigned char key[32];
	int ret = -EFAULT;
	int padding_len = 0;
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

	/* AES 256 with random key */
	get_random_bytes(&key, 32);
	if (crypto_skcipher_setkey(skcipher, key, 32)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	/* IV will be random */
	ivdata = kmalloc(16, GFP_KERNEL);
	if (!ivdata) {
		pr_info("could not allocate ivdata\n");
		goto out;
	}
	get_random_bytes(ivdata, 16);

	/* padding with Input data*/
	/*padding_len = paddingFill(data, data_len);
	if(padding_len) {
		skb_push(skb, padding_len);
		data_len += padding_len;
	}*/
	/* AES 256 with random key */
	get_random_bytes(&key, 32);
	if (crypto_skcipher_setkey(skcipher, key, 32)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	sk.tfm = skcipher;
	sk.req = req;

	/* We encrypt one block */
	sg_init_one(&sk.sg, scratchpad, 16);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
	init_completion(&sk.result.completion);

	/* encrypt data */
	ret = test_skcipher_encdec(&sk, enc);
	if (ret)
		goto out;

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (ivdata)
		kfree(ivdata);
	if (scratchpad)
		kfree(scratchpad);
	return ret;
}

char paddingFill(char *data, int data_len) {
	char tmp_len = 0;
	char *data_tmp = NULL;

	tmp_len = (char)(16 - data_len % 16)/2;

	if(tmp_len != 0) {
		data_tmp = kmalloc((data_len + tmp_len)* sizeof(char), GFP_KERNEL);
		memset(data_tmp, 0, data_len + tmp_len);//padding with 0
		data_tmp[data_len + tmp_len] = tmp_len;//ANSI X.923 padding
		memcpy(data_tmp, data, data_len);//copy original data
		kfree(data);
		data = data_tmp;
	}

	return tmp_len;
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,int enc)
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
		rc = wait_for_completion_interruptible(&sk->result.completion);
		if (!rc && !sk->result.err) {
			reinit_completion(&sk->result.completion);
			break;
		}
	default:
		//pr_info("skcipher encrypt returned with %d result %d\n",rc, sk->result.err);
		break;
	}
	init_completion(&sk->result.completion);

	return rc;
}

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
	struct tcrypt_result *result = req->data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
}