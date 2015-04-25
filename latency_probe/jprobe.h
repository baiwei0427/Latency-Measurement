#ifndef JPROBE_H
#define JPROBE_H

#include <linux/kprobes.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "network.h"

/*
 * Hook inserted to be called before ip_queue_xmit.
 * We use latencyprobe_print_timestamp2 (instead of latencyprobe_print_timestamp) 
 * to print information becanuse ip header is not set up 
 */
static int jip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	latencyprobe_print_timestamp2(skb, "TX ip_queue_xmit\0");
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before ip_output */
static int jip_output(struct sock *sk, struct sk_buff *skb)
{
	latencyprobe_print_timestamp(skb, "TX ip_output\0");
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before dev_queue_xmit */
static int jdev_queue_xmit(struct sk_buff *skb)
{
	latencyprobe_print_timestamp(skb, "TX dev_queue_xmit\0");
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before ip_rcv */
static int jip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	latencyprobe_print_timestamp(skb, "RX ip_rcv\0");
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before ip_local_deliver */
static int jip_local_deliver(struct sk_buff *skb)
{
	latencyprobe_print_timestamp(skb, "RX ip_local_deliver\0");
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before tcp_v4_rcv */
static int jtcp_v4_rcv(struct sk_buff *skb)
{
	latencyprobe_print_timestamp(skb, "RX tcp_v4_rcv\0");
	jprobe_return();
	return 0;
}

static struct jprobe latency_probe_ip_queue_xmit = 
{
	.kp = { .symbol_name = "ip_queue_xmit",},
	.entry = jip_queue_xmit,
};

static struct jprobe latency_probe_ip_output = 
{
	.kp = { .symbol_name	= "ip_output",},
	.entry = jip_output,
};

static struct jprobe latency_probe_dev_queue_xmit = 
{
	.kp = { .symbol_name = "dev_queue_xmit", },
	.entry = jdev_queue_xmit,
};

static struct jprobe  latency_probe_ip_rcv = 
{
	.kp = { .symbol_name = "ip_rcv",},
	.entry = jip_rcv,
};

static struct jprobe  latency_probe_ip_local_deliver = 
{
	.kp = { .symbol_name	= "ip_local_deliver",},
	.entry = jip_local_deliver,
};

static struct jprobe  latency_probe_tcp_v4_rcv = 
{
	.kp = { .symbol_name = "tcp_v4_rcv",},
	.entry = jtcp_v4_rcv,
};

int latencyprobe_jprobe_init(void)
{
	int ret = -ENOMEM;
	
	BUILD_BUG_ON(__same_type(ip_queue_xmit,jip_queue_xmit) == 0);
	BUILD_BUG_ON(__same_type(ip_output,jip_output) == 0);
	BUILD_BUG_ON(__same_type(dev_queue_xmit,jdev_queue_xmit) == 0);
	BUILD_BUG_ON(__same_type(ip_rcv,jip_rcv) == 0);
	BUILD_BUG_ON(__same_type(ip_local_deliver ,jip_local_deliver ) == 0);
	BUILD_BUG_ON(__same_type(tcp_v4_rcv,jtcp_v4_rcv) == 0);
	
	ret = register_jprobe(&latency_probe_ip_queue_xmit);
	if(ret)
	{
		printk(KERN_INFO "Cannot register the hook for ip_queue_xmit\n");
		return ret;
	}
	
	ret = register_jprobe(&latency_probe_ip_output);
	if(ret)
	{
		printk(KERN_INFO "Cannot register the hook for ip_output\n");
		return ret;
	}
	
	ret = register_jprobe(&latency_probe_dev_queue_xmit);
	if(ret)
	{
		printk(KERN_INFO "Cannot register the hook for dev_queue_xmit\n");
		return ret;
	}
	
	ret = register_jprobe(&latency_probe_ip_rcv);
	if(ret)
	{
		printk(KERN_INFO "Cannot register the hook for ip_rcv\n");
		return ret;
	}
	
	ret = register_jprobe(&latency_probe_ip_local_deliver);
	if(ret)
	{
		printk(KERN_INFO "Cannot register the hook for ip_local_deliver\n");
		return ret;
	}
	
	ret = register_jprobe(&latency_probe_tcp_v4_rcv);
	if(ret)
	{
		printk(KERN_INFO "Cannot register the hook for tcp_v4_rcv\n");
		return ret;
	}
	
	return ret;
}

void latencyprobe_jprobe_exit(void)
{
	unregister_jprobe(&latency_probe_ip_queue_xmit);
	unregister_jprobe(&latency_probe_ip_output);
	unregister_jprobe(&latency_probe_dev_queue_xmit);
	unregister_jprobe(&latency_probe_ip_rcv);
	unregister_jprobe(&latency_probe_ip_local_deliver );
	unregister_jprobe(&latency_probe_tcp_v4_rcv);
}

#endif