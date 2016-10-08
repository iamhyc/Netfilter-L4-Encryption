/*
 * @Author: MarkHong
 * @TimeStamp: 20161001TUE0933
 * @Comment: AES Hook on NF_LOCAL_IN & NF_LOCAL_OUT
 */

//Moudle reference
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
//Network Reference
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
//Crypto Reference
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/highmem.h>
//User Reference
#include "AESHook.h"
#include <linux/string.h>
#include <linux/kmod.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark-PC");

static struct nf_hook_ops nfhk_local_in;
static struct nf_hook_ops nfhk_local_out;

static struct crypto_tfm *tfm = crypto_alloc_tfm("aes", CRYPTO_TFM_MODE_ECB);
static const char *aes_key = "00112233445566778899aabbccddeeff";

unsigned int nf_hookfn_in(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	char *data, *data_tmp = NULL;
	char* data_origin;
	struct iphdr *iph = NULL;
	struct scatterlist sg[1];

	if(skb == NULL) {
		printk("%s\n", "*skb is NULL");
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph == NULL) {
		printk("%s\n", "*iph is NULL");
		return NF_ACCEPT;
	}

	data_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
	data = kmalloc(data_len * sizeof(char), GFP_KERNEL);

	//Get Original L3 payload
	data_origin = skb->head + skb->network_header + iph->ihl * 4;
	memcpy(data, data_origin, data_len);
	printkHex(data, data_len, "ORIGIN_INPUT");

	//Encrypt L3 payload
	crypto_cipher_setkey(tfm, aes_key, 16);
	sg_init_one(sg, data, data_len/2);
	crypto_cipher_encrypt(tfm, sg, sg, data_len/2);
	data_tmp = kmap(sg[0].page_link) + sg[0].offset;
	printkHex(data_tmp, sg[0].length, "ENCRYPT_INPUT");
	crypto_free_tfm(tfm);
	//Replace and Checksum re-calc
	
	kfree(data);

	return NF_ACCEPT;
}


unsigned int nf_hookfn_out(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	char *data, *data_tmp = NULL;
	char* data_origin;
	struct iphdr *iph = NULL;
	struct scatterlist sg[1];

	if(skb == NULL) {
		printk("%s\n", "*skb is NULL");
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph == NULL) {
		printk("%s\n", "*iph is NULL");
		return NF_ACCEPT;
	}

	data_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
	data = kmalloc(data_len * sizeof(char), GFP_KERNEL);

	//Get Original L3 payload
	data_origin = skb->head + skb->network_header + iph->ihl * 4;
	memcpy(data, data_origin, data_len);
	printkHex(data, data_len, "ORIGIN_OUTPUT");
	
	//Decrypt L3 payload
	crypto_cipher_setkey(tfm, aes_key, 16);
	sg_init_one(sg, data, data_len/2);
	crypto_cipher_decrypt(tfm, sg, sg, data_len/2);
	data_tmp = kmap(sg[0].page_link) + sg[0].offset;
	printkHex(data, data_len, "DECRYPT_OUTPUT");
	crypto_free_tfm(tfm);

	kfree(data);

	return NF_ACCEPT;
}

void printkHex(char *data, int data_len, char* pt_mark) {
	int i = 0;
	printk("[%s]length=%d;Data Content: ", pt_mark, data_len);
	for (i = 0; i < data_len; i ++) {
		printk("%02x ", data[i] & 0xFF);
	}
	printk("\n");
}

static int init(void)
{
	unsigned int ret;

	printk("AES kexec start ...\n");

	nfhk_local_in.hook = nf_hookfn_in;
	nfhk_local_in.pf = PF_INET;
	nfhk_local_in.hooknum = NF_INET_LOCAL_IN;
	nfhk_local_in.priority = NF_IP_PRI_FIRST;

	nfhk_local_out.hook = nf_hookfn_out;
	nfhk_local_out.pf = PF_INET;
	nfhk_local_out.hooknum = NF_INET_LOCAL_IN;
	nfhk_local_out.priority = NF_IP_PRI_LAST;

	ret = nf_register_hook(&nfhk_local_in);
	if (ret < 0) {
        printk("Register ERROR\n");
        return ret;
    }
	ret = nf_register_hook(&nfhk_local_out);
	if (ret < 0) {
        printk("Register ERROR\n");
        return ret;
    }

	return 0;
}

static void fini(void)
{
	nf_unregister_hook(&nfhk_local_in);
	nf_unregister_hook(&nfhk_local_out);

	printk("AES kexec exit ...\n");
}

module_init(init);
module_exit(fini);