#ifndef __NETLINK_COM_H__
#define __NETLINK_COM_H__

#include <asm/types.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>

DEFINE_MUTEX(receive_sem);

#define NETLINK_GENERIC 16/* general netlink */

struct packet_info
{
  __u32 src;
  __u32 dest;
};

int netlink_init(void);
void netlink_fini(void);

#endif