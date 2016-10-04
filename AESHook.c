/*
 * @Author: MarkHong
 * @TimeStamp: 20161001TUE0933
 * @Comment: AES Hook on NF_LOCAL_IN & NF_LOCAL_OUT
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include "AESHook.h"
#include <linux/string.h>
#include <linux/kmod.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark-PC");

static struct nf_hook_ops nfhk_local_in;
static struct nf_hook_ops nfhk_local_out;

unsigned int nf_hookfn_in(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}


unsigned int nf_hookfn_out(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}



static int init(void)
{
	printk("AES kexec start ...\n");

	nfhk_local_in.hook = nf_hookfn_in;
	nfhk_local_in.pf = PF_INET;
	nfhk_local_in.hooknum = NF_INET_LOCAL_IN;
	nfhk_local_in.priority = NF_IP_PRI_FIRST;

	nfhk_local_out.hook = nf_hookfn_out;
	nfhk_local_out.pf = PF_INET;
	nfhk_local_out.hooknum = NF_INET_LOCAL_IN;
	nfhk_local_out.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfhk_local_in);
	nf_register_hook(&nfhk_local_out);

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