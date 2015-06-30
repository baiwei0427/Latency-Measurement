#ifndef JPROBE_H
#define JPROBE_H

#include <linux/kprobes.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "network.h"
#include "log.h"

/*
 * Hook inserted to be called before ip_queue_xmit.
 * We use latencyprobe_timeinterval2 (instead of latencyprobe_timeinterval) because ip header is not set up 
 */
static int jip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	s64 t_sample=latencyprobe_timeinterval2(skb);
	if(t_sample>0)
	{
		latencyprobe_tsum_ip_queue_xmit+=t_sample;
		latencyprobe_sample_ip_queue_xmit++;
	
		if(latencyprobe_sample_ip_queue_xmit>=latencyprobe_tx_sample_thresh)
		{
			unsigned long long result=latencyprobe_tsum_ip_queue_xmit/latencyprobe_sample_ip_queue_xmit;
			latencyprobe_tsum_ip_queue_xmit=0;
			latencyprobe_sample_ip_queue_xmit=0;
			latencyprobe_print_timeinterval("TX ip_queue_xmit", result); 
		}
	}
	
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before ip_output */
static int jip_output(struct sock *sk, struct sk_buff *skb)
{
	s64 t_sample=latencyprobe_timeinterval(skb);
	if(t_sample>0)
	{
		latencyprobe_tsum_ip_output+=t_sample;
		latencyprobe_sample_ip_output++;
	
		if(latencyprobe_sample_ip_output>=latencyprobe_tx_sample_thresh)
		{
			unsigned long long result=latencyprobe_tsum_ip_output/latencyprobe_sample_ip_output;
			latencyprobe_tsum_ip_output=0;
			latencyprobe_sample_ip_output=0;
			latencyprobe_print_timeinterval("TX ip_output", result); 
		}
	}
	
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before dev_queue_xmit */
static int jdev_queue_xmit(struct sk_buff *skb)
{
	s64 t_sample=latencyprobe_timeinterval(skb);
	if(t_sample>0)
	{
		latencyprobe_tsum_dev_queue_xmit+=t_sample;
		latencyprobe_sample_dev_queue_xmit++;
	
		if(latencyprobe_sample_dev_queue_xmit>=latencyprobe_tx_sample_thresh)
		{
			unsigned long long result=latencyprobe_tsum_dev_queue_xmit/latencyprobe_sample_dev_queue_xmit;
			latencyprobe_tsum_dev_queue_xmit=0;
			latencyprobe_sample_dev_queue_xmit=0;
			latencyprobe_print_timeinterval("TX dev_queue_xmit", result); 
		}
	}
	
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before ip_rcv */
static int jip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	s64 t_sample=latencyprobe_timeinterval(skb);
	if(t_sample>0)
	{
		latencyprobe_tsum_ip_rcv+=t_sample;
		latencyprobe_sample_ip_rcv++;
	
		if(latencyprobe_sample_ip_rcv>=latencyprobe_rx_sample_thresh)
		{
			unsigned long long result=latencyprobe_tsum_ip_rcv/latencyprobe_sample_ip_rcv;
			latencyprobe_tsum_ip_rcv=0;
			latencyprobe_sample_ip_rcv=0;
			latencyprobe_print_timeinterval("RX ip_rcv", result); 
		}
	}
	
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before ip_local_deliver */
static int jip_local_deliver(struct sk_buff *skb)
{
	s64 t_sample=latencyprobe_timeinterval(skb);
	if(t_sample>0)
	{
		latencyprobe_tsum_ip_local_deliver+=t_sample;
		latencyprobe_sample_ip_local_deliver++;
	
		if(latencyprobe_sample_ip_local_deliver>=latencyprobe_rx_sample_thresh)
		{
			unsigned long long result=latencyprobe_tsum_ip_local_deliver/latencyprobe_sample_ip_local_deliver;
			latencyprobe_tsum_ip_local_deliver=0;
			latencyprobe_sample_ip_local_deliver=0;
			latencyprobe_print_timeinterval("RX ip_local_deliver", result); 
		}
	}
	
	jprobe_return();
	return 0;
}

/* Hook inserted to be called before tcp_v4_rcv */
static int jtcp_v4_rcv(struct sk_buff *skb)
{
	s64 t_sample=latencyprobe_timeinterval(skb);
	if(t_sample>0)
	{
		latencyprobe_tsum_tcp_v4_rcv+=t_sample;
		latencyprobe_sample_tcp_v4_rcv++;
	
		if(latencyprobe_sample_tcp_v4_rcv>=latencyprobe_rx_sample_thresh)
		{
			unsigned long long result=latencyprobe_tsum_tcp_v4_rcv/latencyprobe_sample_tcp_v4_rcv;
			latencyprobe_tsum_tcp_v4_rcv=0;
			latencyprobe_sample_tcp_v4_rcv=0;
			latencyprobe_print_timeinterval("RX tcp_v4_rcv", result); 
		}
	}
	
	jprobe_return();
	return 0;
}

/*
 * Hook inserted to be called before each receive packet.
 */
static void jtcp_rcv_established(struct sock *sk, struct sk_buff *skb,
				 const struct tcphdr *th, unsigned int len)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	
	if(latencyprobe_filter_packet(ntohs(inet->inet_dport),ntohs(inet->inet_sport)))
	{
		latencyprobe_tsum_rtt+=(tp->srtt_us>>3)*1000;	//us to ms
		latencyprobe_sample_rtt++;
		if(latencyprobe_sample_rtt>=latencyprobe_rtt_sample_thresh)
		{
			unsigned long long result=latencyprobe_tsum_rtt/latencyprobe_sample_rtt;
			latencyprobe_tsum_rtt=0;
			latencyprobe_sample_rtt=0;
			latencyprobe_print_timeinterval("RTT", result); 
		}
	}
	
	jprobe_return();
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

static struct jprobe latency_probe_tcp_rcv_established = 
{
	.kp = { .symbol_name = "tcp_rcv_established",},
	.entry = jtcp_rcv_established,
};

static int latencyprobe_jprobe_init(void)
{
	int ret = -ENOMEM;
	
	BUILD_BUG_ON(__same_type(ip_queue_xmit,jip_queue_xmit) == 0);
	BUILD_BUG_ON(__same_type(ip_output,jip_output) == 0);
	BUILD_BUG_ON(__same_type(dev_queue_xmit,jdev_queue_xmit) == 0);
	BUILD_BUG_ON(__same_type(ip_rcv,jip_rcv) == 0);
	BUILD_BUG_ON(__same_type(ip_local_deliver ,jip_local_deliver ) == 0);
	BUILD_BUG_ON(__same_type(tcp_v4_rcv,jtcp_v4_rcv) == 0);
	BUILD_BUG_ON(__same_type(tcp_rcv_established,jtcp_rcv_established) == 0);
	
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

	ret = register_jprobe(&latency_probe_tcp_rcv_established);
	if(ret)
	{
		printk(KERN_INFO "Cannot register the hook for tcp_rcv_established\n");
		return ret;
	}
	
#ifdef RX
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
#endif
	return ret;
}

static void latencyprobe_jprobe_exit(void)
{
	unregister_jprobe(&latency_probe_ip_queue_xmit);
	unregister_jprobe(&latency_probe_ip_output);
	unregister_jprobe(&latency_probe_dev_queue_xmit);
	unregister_jprobe(&latency_probe_tcp_rcv_established);
	
#ifdef RX
	unregister_jprobe(&latency_probe_ip_rcv);
	unregister_jprobe(&latency_probe_ip_local_deliver );
	unregister_jprobe(&latency_probe_tcp_v4_rcv);
#endif
}

#endif