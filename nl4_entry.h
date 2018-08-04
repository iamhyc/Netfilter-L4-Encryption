#ifndef __NL4_ENTRY_H__
#define __NL4_ENTRY_H__

#define REMOTE_IP "127.0.0.1" //FIXME:rewrite to list (with addr mask)

#define INBOUND     0
#define OUTBOUND    1

#define IPV4A(x)   ((u8 *)x)[0]
#define IPV4B(x)   ((u8 *)x)[1]
#define IPV4C(x)   ((u8 *)x)[2]
#define IPV4D(x)   ((u8 *)x)[3]

#define GET_PPDST(iph)  (__be16 *)((char *)iph + iph->ihl*4 + 2)
#define GET_PDST(iph)   ntohs(*GET_PPDST(iph))
#define GET_PPSRC(iph)  (__be16 *)((char *)iph + iph->ihl*4 + 4)
#define GET_PSRC(iph)   ntohs(*GET_PPSRC(iph))

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

/**
  * @brief  print in kernel with Hex data
  * @param  (char *)data pointer, (int)data length, (char *)description of data
  */
void printkHex(char *data, int data_len, int padding_len, char* pt_mark) {
	int i = 0;
	printk("[%s]length=%d:%d;Data Content: ", pt_mark, data_len, padding_len);
	for (i = 0; i < (data_len+padding_len); i ++) {
		printk("%02x ", data[i] & 0xFF);
	}
	printk("\n");
}

unsigned int nf_hookfn_in(void *, struct sk_buff *, const struct nf_hook_state *);
unsigned int nf_hookfn_out(void *, struct sk_buff *, const struct nf_hook_state *);

#endif