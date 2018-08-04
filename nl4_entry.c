/**
 * @Author: Mark Hong
*/

//Moudle reference
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
//Network Reference
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "nl4_entry.h"

static u32 remote_addr = 0;

static struct nf_hook_ops nfhk_local_in = 
{
	.hook = nf_hookfn_in,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfhk_local_out =
{
	.hook = nf_hookfn_out,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_LAST
};

int remoteAllowed(struct iphdr *iph, int bound)
{
	u32 tmp_addr = (bound==INBOUND)?iph->saddr:iph->daddr;
	if (tmp_addr==remote_addr)
		return 1;
	else
		return 0;
}

unsigned int nf_hookfn_in(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	char padding_len;
	char* data_origin;
	struct iphdr *iph = NULL;
    // struct tcphdr *tcph = NULL;

	//NOTE: bypass non-linear skb
	if (unlikely(skb_linearize(skb) != 0))
        return NF_ACCEPT;

	iph = ip_hdr(skb);

	if(iph!=NULL && remoteAllowed(iph, INBOUND))
	{
		//NOTE: Get Original L3 payload, Extract data from payload
		data_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
		data_origin = skb->head + skb->network_header + iph->ihl * 4;

		//NOTE: Decryption function
		aes_crypto_cipher(data_origin, data_len, DECRYPTION);

		//NOTE: re-checksum
		padding_len = get_comp_length(data_origin, data_len);
		skb->tail -= padding_len; skb->len  -= padding_len;
		iph->tot_len = htons(ntohs(iph->tot_len) - padding_len);//remove padding from length
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);//re-checksum for IP
		skb->csum = skb_checksum(skb, iph->ihl*4, skb->len - iph->ihl * 4, 0);//re-checksum for skb
		printk("[INBOUND] prot: %d, len: %d", iph->protocol, htons(iph->tot_len));
		// printkHex(data_origin, data_len, -padding_len, "FINAL\tINPUT");
	}

	return NF_ACCEPT;
}

unsigned int nf_hookfn_out(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	char padding_len;
	char *data = NULL;
	char* data_origin;
	struct iphdr *iph = NULL;
	// struct tcphdr *tcph = NULL;

	//NOTE: bypass non-linear skb
	if (unlikely(skb_linearize(skb) != 0))
        return NF_ACCEPT;

	iph = ip_hdr(skb);

	if(iph!=NULL && remoteAllowed(iph, OUTBOUND))
	{
		printk("[OUTBOUND] prot: %d, len: %d", iph->protocol, htons(iph->tot_len));
		//NOTE: pre padding allocate
		data_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
		padding_len = COMP_LENGTH(data_len);
		data = kmalloc((data_len+padding_len) * sizeof(char), GFP_KERNEL);
		memset(data, 0, (data_len+padding_len));//padding with 0
		data[data_len + padding_len - 1] = padding_len;//ANSI X.923 format

		//NOTE: Get Original L3 payload
		data_origin = skb->head + skb->network_header + iph->ihl * 4;
		memcpy(data, data_origin, data_len);

		//NOTE: Encryption function
		aes_crypto_cipher(data, (data_len+padding_len), ENCRYPTION);
		skb_put(skb, padding_len);//forward from tail
		memcpy(data_origin, data, (data_len+padding_len));

		//NOTE: re-checksum
		iph->tot_len = htons(ntohs(iph->tot_len) + padding_len);//'total length' segment in IP
		iph->check = 0;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);//re-checksum for IP
		skb->csum = 0;
		skb->csum = skb_checksum(skb, iph->ihl*4, skb->len - iph->ihl * 4, 0);//re-checksum for skb

		kfree(data);
	}

	return NF_ACCEPT;
}

static int nl4_init(void)
{
	unsigned int ret;

	remote_addr = IP2NUM(REMOTE_IP);

	ret = nf_register_net_hook(&init_net, &nfhk_local_in);
	if (ret < 0) {
        printk("INBOUND Module Register Error.\n");
        return ret;
    }

	ret = nf_register_net_hook(&init_net, &nfhk_local_out);
	if (ret < 0) {
        printk("OUTBOUND Moudle Register Error.\n");
        return ret;
    }

    printh("NL4 Suite Init ...\n");
	return 0;
}

static void nl4_fini(void)
{
	nf_unregister_net_hook(&init_net, &nfhk_local_in);
	nf_unregister_net_hook(&init_net, &nfhk_local_out);
	printh("NL4 Suite Exit ...\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark-PC");
module_init(nl4_init);
module_exit(nl4_fini);