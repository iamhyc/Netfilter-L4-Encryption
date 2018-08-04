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
	.priority = NF_IP_PRI_FIRST
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
	char* payload;
	struct iphdr *iph = NULL;
    // struct tcphdr *tcph = NULL;

	//NOTE: bypass non-linear skb
	if (unlikely(skb_linearize(skb) != 0))
        return NF_ACCEPT;

	iph = ip_hdr(skb);

	if(iph!=NULL && remoteAllowed(iph, INBOUND))
	{
		//a. extract cipher payload
		data_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
		payload = (char *)iph + iph->ihl * 4;

		//b. decrypt the cipher
		aes_crypto_cipher(payload, data_len, DECRYPTION);
		padding_len = get_comp_length(payload, data_len);
		if(padding_len)
		{
			printk("has padding\n");
			skb_trim(skb, skb->len - padding_len);
			// skb->tail -= padding_len; skb->len  -= padding_len;
			iph->tot_len = htons(ntohs(iph->tot_len) - padding_len);
		}

		//c. re-checksum for iph
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
	}

	return NF_ACCEPT;
}

unsigned int nf_hookfn_out(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 payload_len;
	char padding_len;
	char* payload;
	struct iphdr *iph = NULL;
	// struct tcphdr *tcph = NULL;

	//NOTE: bypass non-linear skb
	if (unlikely(skb_linearize(skb) != 0))
        return NF_ACCEPT;

	iph = ip_hdr(skb);

	if(iph!=NULL && remoteAllowed(iph, OUTBOUND))
	{
		//a. padding, expand from tailroom
		payload_len = ntohs(iph->tot_len)  - sizeof(struct iphdr);
		padding_len = COMP_LENGTH(payload_len);

		//b. encrypt the payload
		payload = (char *)iph + iph->ihl*4;
		if(padding_len)
		{
			skb_put(skb, padding_len);
			memset((char *)(payload+payload_len), 0, padding_len);
			payload[payload_len + padding_len - 1] = padding_len;//ANSI X.923 format
		}
		aes_crypto_cipher(payload, (payload_len+padding_len), ENCRYPTION);

		//c. re-checksum for iph
		iph->tot_len = htons(ntohs(iph->tot_len) + padding_len);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
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