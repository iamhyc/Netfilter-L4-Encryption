

##Introduction

This is a project trying to encrypt **Payload of L3** with *Symmetrical  encryption* on *Netfilter subsystem* of Linux.

Just imagining that the routes could not know what you are actully transmitting, on which protol with what content.

##Method

Source Address of Header of L3

1. skb->nh.iph->saddr && daddr to filter the package

2. Check the protocol from L3#
	
	dport = tcph->dest; //destination port of TCP,

	skb->nh.iph->protocol == IPPROTO_TCP

	skb->nh.iph->protocol == IPPROTO_UDP
3. re-generate the *checksum* of IPv4 with *ip_fast_csum(\* iph, int ihl)*

4. kernel supported *linux/crypto.h* for encryption

