/*
 * @Author: MarkHong
 * @TimeStamp: 20161001TUE0933
 * @Comment: AES Hook on NF_LOCAL_IN & NF_LOCAL_OUT
 */
/* Includes ------------------------------------------------------------------*/
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
//User Reference
#include "AESHook.h"
#include "aes_method.h"
#include <linux/string.h>
#include <linux/kmod.h>

/* Module Definition ---------------------------------------------------------*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark-PC");

/* Private function prototypes -----------------------------------------------*/
static struct nf_hook_ops nfhk_local_in;
static struct nf_hook_ops nfhk_local_out;

/**
  * @brief  
  * @param  
  * @retval 
  */
char padding_fill(int data_len) {
	char tmp_len = 0;

	tmp_len = data_len % 16;
	tmp_len = (tmp_len==0?0:16-tmp_len);

	return tmp_len;
}

/**
  * @brief  
  * @param  
  * @retval 
  */
char padding_check(char * data, int len)
{
	char ex;
	int flag = 0, i = 0;

	ex = data[len - 1];
	for (i = 0; i < ex; i++)
	{
		flag += data[len - i - 1];
	}

	if(flag==0)
		return ex;
	else
		return 0;
}

/**
  * @brief  
  * @param  
  * @retval uint16_t, the length of '*data' pointer(in bit)
  */
unsigned int nf_hookfn_in(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	char padding_len;
	char *data = NULL;
	char* data_origin;
	struct iphdr *iph = NULL;

	if(skb == NULL) {
		printk("%s\n", "*skb is NULL");
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph == NULL) {
		printk("%s\n", "*iph is NULL");
		return NF_ACCEPT;
	}

	//Get Original L3 payload, Extract data from payload
	data_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
	data_origin = skb->head + skb->network_header + iph->ihl * 4;
	//printkHex(data_origin, data_len, 0, "ORIGIN\tINPUT");
	/* Decryption function */
	aes_crypto_cipher(data_origin, data_len, DECRYPTION);

	//allocate memory for data without padding
	padding_len = padding_check(data_origin, data_len);
	data = kmalloc((data_len - padding_len) * sizeof(char), GFP_KERNEL);
	memcpy(data, data_origin, (data_len - padding_len));
	//re-checksum for IP header
	iph->tot_len = htons(ntohs(iph->tot_len) - padding_len);//remove padding from length
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);//re-checksum
	memcpy(data_origin, data, data_len);

	kfree(data);

	return NF_ACCEPT;
}

/**
  * @brief  
  * @param  
  * @retval uint16_t, the length of '*data' pointer(in bit)
  */
unsigned int nf_hookfn_out(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	char padding_len;
	char *data = NULL;
	char* data_origin;
	struct iphdr *iph = NULL;

	if(skb == NULL) {
		printk("%s\n", "*skb is NULL");
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph == NULL) {
		printk("%s\n", "*iph is NULL");
		return NF_ACCEPT;
	}

	//pre padding allocate
	data_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
	padding_len = padding_fill(data_len);
	data = kmalloc((data_len+padding_len) * sizeof(char), GFP_KERNEL);
	memset(data, 0, (data_len+padding_len));//padding with 0
	data[data_len + padding_len - 1] = padding_len;//ANSI X.923 format

	//Get Original L3 payload
	data_origin = skb->head + skb->network_header + iph->ihl * 4;
	memcpy(data, data_origin, data_len);
	printkHex(data, data_len, padding_len, "ORIGIN\tOUTPUT");

	/* Encryption function */
	aes_crypto_cipher(data, data_len, ENCRYPTION);

	/* substitute original data */
	skb_put(skb, padding_len);//forward from tail
	memcpy(data_origin, data, data_len);
	//re-checksum for IP segment
	iph->tot_len = htons(ntohs(iph->tot_len) + padding_len);//'total length' segment in IP
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);//re-checksum

	kfree(data);

	return NF_ACCEPT;
}

/**
  * @brief  print in kernel with Hex data
  * @param  (char *)data pointer, (int)data length, (char *)description of data
  */
void printkHex(char *data, int data_len, int padding_len, char* pt_mark) {
	int i = 0;
	printk("[%s]length=%d:%d;Data Content: ", pt_mark, data_len, padding_len);
	for (i = 0; i < data_len; i ++) {
		printk("%02x ", data[i] & 0xFF);
	}
	printk("\n");
}

/**
  * @brief  module init function
  */
static int init(void)
{
	unsigned int ret;

	printk("AES kexec start ...\n");
	//NF_LOCAL_IN HOOK struct
	nfhk_local_in.hook = nf_hookfn_in;
	nfhk_local_in.pf = PF_INET;
	nfhk_local_in.hooknum = NF_INET_LOCAL_IN;
	nfhk_local_in.priority = NF_IP_PRI_FIRST;
	//NF_LOCAL_OUT HOOK struct
	nfhk_local_out.hook = nf_hookfn_out;
	nfhk_local_out.pf = PF_INET;
	nfhk_local_out.hooknum = NF_INET_LOCAL_OUT;
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

/**
  * @brief  module exit callback function
  */
static void fini(void)
{
	nf_unregister_hook(&nfhk_local_in);
	nf_unregister_hook(&nfhk_local_out);

	printk("AES kexec exit ...\n");
}

module_init(init);
module_exit(fini);