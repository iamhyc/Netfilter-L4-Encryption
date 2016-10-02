/*  
* 安装一个丢弃所有到达的数据包的Netfilter hook函数的示例代码  
*/  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/version.h>  
#include <linux/skbuff.h>  
#include <linux/netfilter.h>  
#include <linux/netfilter_ipv4.h>

#include <memory.h>
#include <openssl/aes.h>
#pragma comment(lib,"libeay32.lib")
  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("Mark-PC");  
  
static struct nf_hook_ops nfho;  
  
unsigned int hook_func(unsigned int hooknum,  
                       struct sk_buff *skb,  
                       const struct net_device *in,  
                       const struct net_device *out,  
                       int (*okfn)(struct sk_buff *))  
{  
    return NF_STOLEN;  
}  
  
static int init(void)  
{  
    printk("kexec test start ...\n");  
  
    nfho.hook = hook_func;  
    nfho.owner = NULL;  
    nfho.pf = PF_INET;  
    nfho.hooknum = NF_INET_LOCAL_OUT;  
    nfho.priority = NF_IP_PRI_FIRST;  
      
    nf_register_hook(&nfho);

    return 0;  
}
  
static void fini(void)
{
    printk("kexec test exit ...\n");
    nf_unregister_hook(&nfho);
}

module_init(init);
module_exit(fini);