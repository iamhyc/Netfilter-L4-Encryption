
#include "netlink_com.h"


#define MAX_MSGSIZE 1024
void sendnlmsg(char * message);
static int pid; // user process pid
static int err;
static struct sock *nl_sk = NULL;
static int flag = 0;

void sendnlmsg(char *message)
{
    struct sk_buff *skb_1;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen = 0;
    if(!message || !nl_sk)
    {
        return ;
    }

    skb_1 = alloc_skb(len,GFP_KERNEL);
    if(!skb_1)
    {
        printk(KERN_ERR "my_net_link:alloc_skb_1 error\n");
    }

    slen = strlen(message);
    nlh = nlmsg_put(skb_1,0,0,0,MAX_MSGSIZE,0);

    NETLINK_CB(skb_1).pid = 0;
    NETLINK_CB(skb_1).dst_group = 0;

    message[slen]= '\0';
    memcpy(NLMSG_DATA(nlh),message,slen+1);
    printk("my_net_link:send message '%s'.\n",(char *)NLMSG_DATA(nlh));

    netlink_unicast(nl_sk, skb_1, pid, MSG_DONTWAIT);
}

void crypto_netlink_rcv(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char str[100];
    struct completion cmpl;
    int i=10;
    skb = skb_get (__skb);

    if(skb->len >= NLMSG_SPACE(0))
    {
        nlh = nlmsg_hdr(skb);

        memcpy(str, NLMSG_DATA(nlh), sizeof(str));
        printk("Message received:%s\n",str);
        pid = nlh->nlmsg_pid;
        while(i--)
        {
            init_completion(&cmpl);
            wait_for_completion_timeout(&cmpl,3 * HZ);
            sendnlmsg("I am from kernel!");
        }
        flag = 1;
        kfree_skb(skb);
    }
}

// Initialize netlink
int netlink_init(void)
{
  	struct netlink_kernel_cfg cfg = {
		.input = crypto_netlink_rcv,
		.group = 1
	};

    nl_sk = netlink_kernel_create(&init_net, NETLINK_AES, 1, nl_data_ready);

    if(!nl_sk){//create netlink socket error
        return -1;
    }

    printk("netlink socket on.\n");
    return 0;
}  
  
void netlink_fini(void)
{  
    if(nl_sk != NULL){  
        netlink_kernel_release(nl_sk);  
    }  
    printk("NETLINK subsys exited\n");  
}  
