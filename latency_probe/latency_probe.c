#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/netdevice.h>

/*
 * Hook inserted to be called before ip_queue_xmit.
 * Note: arguments must match ip_queue_xmit()!
 */
static int jip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	ktime_t now=ktime_get();
	struct tcphdr *tcph=tcp_hdr(skb);
	if(ntohs(tcph->source)==5001||ntohs(tcph->dest)==5001)
	{
		printk(KERN_INFO "ip_queue_xmit: %lld\n",now.tv64-skb->tstamp.tv64);
	}
	jprobe_return();
	return 0;
}

/*
 * Hook inserted to be called before ip_output.
 * Note: arguments must match ip_output()!
 */
static int jip_output(struct sock *sk, struct sk_buff *skb)
{
	ktime_t now=ktime_get();
	struct iphdr *iph=ip_hdr(skb);
	struct tcphdr *tcph=NULL;
	
	if(iph->protocol==IPPROTO_TCP)
	{
		tcph=tcp_hdr(skb);
		if(ntohs(tcph->source)==5001||ntohs(tcph->dest)==5001)
		{
			printk(KERN_INFO "ip_output: %lld\n",now.tv64-skb->tstamp.tv64);
		}
	}
	jprobe_return();
	return 0;
}

/*
 * Hook inserted to be called before dev_queue_xmit.
 * Note: arguments must match dev_queue_xmit()!
 */
static int jdev_queue_xmit(struct sk_buff *skb)
{
	ktime_t now=ktime_get();
	struct iphdr *iph=ip_hdr(skb);
	struct tcphdr *tcph=NULL;
	
	if(iph->protocol==IPPROTO_TCP)
	{
		tcph=tcp_hdr(skb);
		if(ntohs(tcph->source)==5001||ntohs(tcph->dest)==5001)
		{
			printk(KERN_INFO "dev_queue_xmit: %lld\n",now.tv64-skb->tstamp.tv64);
		}
	}
	jprobe_return();
	return 0;
}

static struct jprobe  latency_probe_ip_queue_xmit = 
{
	.kp = {
		.symbol_name = "ip_queue_xmit",
	},
	.entry = jip_queue_xmit,
};

static struct jprobe  latency_probe_ip_output = 
{
	.kp = {
		.symbol_name	= "ip_output",
	},
	.entry = jip_output,
};

static struct jprobe  latency_probe_dev_queue_xmit = 
{
	.kp = {
		.symbol_name = "dev_queue_xmit",
	},
	.entry = jdev_queue_xmit,
};

static __init int latencyprobe_init(void)
{
	int ret = -ENOMEM;
	
	BUILD_BUG_ON(__same_type(ip_queue_xmit,jip_queue_xmit) == 0);
	BUILD_BUG_ON(__same_type(ip_output,jip_output) == 0);
	BUILD_BUG_ON(__same_type(dev_queue_xmit,jdev_queue_xmit) == 0);
	
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
	
	printk(KERN_INFO "Latency probe module starts\n");
	return ret;
}

static __exit void latencyprobe_exit(void)
{
	unregister_jprobe(&latency_probe_ip_queue_xmit);
	unregister_jprobe(&latency_probe_ip_output);
	unregister_jprobe(&latency_probe_dev_queue_xmit);
	
	printk(KERN_INFO "Latency probe module stops\n");
}

module_init(latencyprobe_init);
module_exit(latencyprobe_exit);
MODULE_AUTHOR("BAI Wei <baiwei0427@gmail.com>");
MODULE_DESCRIPTION("Latency snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
