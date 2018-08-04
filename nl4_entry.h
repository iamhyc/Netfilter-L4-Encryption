#ifndef __NL4_ENTRY_H__
#define __NL4_ENTRY_H__

#include <linux/string.h>
#include "nl4_utility.h" //kernel aes_cbc_256

#define REMOTE_IP "127.0.0.1" //FIXME:rewrite to list (with addr mask)

u32 getIfAddr(const char *if_name)
{
    u32 ipv4 = 0;
    struct net_device* dev;
    struct in_device* pdev;

    dev = dev_get_by_name(&init_net, if_name);
    if(dev && netif_running(dev) && (dev->ip_ptr!=NULL))
    {
        pdev = (struct in_device *)dev->ip_ptr;
        if(pdev->ifa_list)
        {
            ipv4 = pdev->ifa_list->ifa_address;
        }
    }

    return ipv4;
}

void dumpTCP(const char* key, struct iphdr *iph)
{
    char saddr[16], daddr[16];
    struct tcphdr *tcph = (struct tcphdr *)((u8 *)iph + iph->ihl*4);
    NUM2IP(iph->saddr, saddr);
    NUM2IP(iph->daddr, daddr);
    printk("[%s]\
            \n\tSeq: 0x%08x; ACK: 0x%08x\
            \n\tSrc: %s, Dst:%s, %d -> %d\
            \n\tSYN %d; ACK %d; FIN %d; RST %d; PSH %d\n", \
            key,
            ntohs(tcph->seq), ntohs(tcph->ack_seq), \
            saddr, daddr, ntohs(tcph->source), ntohs(tcph->dest), \
            tcph->syn, tcph->ack, tcph->fin, tcph->rst, tcph->psh);
}

void hexDump(char *data, int len, int bound) {
	int cnt = 0;
    char *buffer, *ptr;
    buffer = kmalloc(4096 * sizeof(char), GFP_KERNEL);
    ptr = buffer;

    while(cnt < len)
    {
        sprintf(ptr, "%02x ", data[cnt]&0xFF);
        ptr += 3;
        ++ cnt;

        if(cnt%20==0)
        {
            sprintf(ptr, "\n");
            ++ptr;
        }
    }

    if(bound==INBOUND)
	    printk("[INBOUND]\n%s\n", buffer);
    else
        printk("[OUTBOUND]\n%s\n", buffer);

    kfree(buffer);
}

unsigned int nf_hookfn_in(void *, struct sk_buff *, const struct nf_hook_state *);
unsigned int nf_hookfn_out(void *, struct sk_buff *, const struct nf_hook_state *);

#endif