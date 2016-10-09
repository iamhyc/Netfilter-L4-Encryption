
#include <linux/string.h>

#include "aes_method.h"

static const char *aes_key = "00112233445566778899aabbccddeeff";

void aes_crypto_cipher(struct sk_buff *skb, 
						char* data, __u16 data_len,
						int enc) {

	__u16 padding_len;
	char iv[32];
	struct scatterlist sg[1];
	struct skcipher_request *req;
	struct crypto_skcipher *tfm = crypto_alloc_skcipher("ecb(aes)", CRYPTO_ALG_INTERNAL, 0);
									//(driver, type | CRYPTO_ALG_INTERNAL, mask)

	//Encrypt L3 payload
	padding_len = paddingFill(data, data_len);
	if(padding_len) {
		skb_push(skb, padding_len);
		data_len += padding_len;
	}

	memset(iv, 0, 32);
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	crypto_skcipher_setkey(tfm, aes_key, 16);
	sg_init_one(&sg[0], data, data_len);
	skcipher_request_set_crypt(req, sg, sg, data_len, iv);
	crypto_skcipher_encrypt(req);
	/*crypto_cipher_setkey(tfm, aes_key, 16);
	sg_init_one(sg, data, data_len/2);
	crypto_cipher_encrypt(tfm, sg, sg, data_len/2);
	data_tmp = kmap(sg[0].page_link) + sg[0].offset;
	printkHex(data_tmp, sg[0].length, "ENCRYPT_INPUT");
	crypto_free_tfm(tfm);*/
	//Replace and Checksum re-calc

	//Decrypt L3 payload
	/*crypto_cipher_setkey(tfm, aes_key, 16);
	sg_init_one(sg, data, data_len/2);
	crypto_cipher_decrypt(tfm, sg, sg, data_len/2);
	data_tmp = kmap(sg[0].page_link) + sg[0].offset;
	printkHex(data, data_len, "DECRYPT_OUTPUT");
	crypto_free_tfm(tfm);*/
}

char paddingFill(char *data, int data_len) {
	char tmp_len = 0;
	char *data_tmp = NULL;

	tmp_len = (char)(16 - data_len % 16);

	if(tmp_len) {
		data_tmp = kmalloc((data_len + tmp_len)* sizeof(char), GFP_KERNEL);
		memset(data_tmp, 0, data_len + tmp_len);//padding with 0
		data_tmp[data_len + tmp_len] = tmp_len;//ANSI X.923 padding
		memcpy(data_tmp, data, data_len);//copy original data
		kfree(data);
		data = data_tmp;
	}

	return tmp_len;
}