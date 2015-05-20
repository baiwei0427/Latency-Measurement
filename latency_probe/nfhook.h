#ifndef NFHOOK_H
#define NFHOOK_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#include "network.h"
#include "log.h"

/* The hook fo outgoing packets*/
static struct nf_hook_ops nfhook_outgoing;
/* The hook fo incoming packets*/
static struct nf_hook_ops nfhook_incoming;


static unsigned int latencyprobe_hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{	
	struct iphdr *iph=NULL;	
		
	//Get IP header
	iph=ip_hdr(skb);
	if (unlikely(iph==NULL))
		return NF_ACCEPT;
	
	if(iph->protocol==IPPROTO_TCP) 
	{
		struct tcphdr *tcph=tcp_hdr(skb);
		if(likely(tcph!=NULL))
		{
			if(latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
			{
				latencyprobe_tcp_modify_timestamp(skb,(unsigned int)(ktime_to_ns(ktime_get())>>10));
			}
		}
	}
	
	return NF_ACCEPT;
}

static unsigned int latencyprobe_hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{	
	struct iphdr *iph=NULL;	
	unsigned int rtt=0;
	
	//Get IP header
	iph=ip_hdr(skb);
	if (unlikely(iph==NULL))
		return NF_ACCEPT;
	
	if(iph->protocol==IPPROTO_TCP) 
	{
		struct tcphdr *tcph=tcp_hdr(skb);
		if(likely(tcph!=NULL))
		{
			if(latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
			{
				rtt=latencyprobe_tcp_modify_timestamp(skb,0);
				latencyprobe_tsum_rtt+=rtt*1000;
				latencyprobe_sample_rtt++;
				if(latencyprobe_sample_rtt>=latencyprobe_rtt_sample_thresh)
				{
					unsigned long long result=latencyprobe_tsum_rtt/latencyprobe_sample_rtt;
					latencyprobe_tsum_rtt=0;
					latencyprobe_sample_rtt=0;
					latencyprobe_print_timeinterval("RTT", result); 
				}
			}
		}
	}
	
	return NF_ACCEPT;
}

static int latencyprobe_nfhook_init(void)
{
	nfhook_outgoing.hook=latencyprobe_hook_func_out;                
	nfhook_outgoing.hooknum=NF_INET_LOCAL_OUT;       	
	nfhook_outgoing.pf=PF_INET;                    
	nfhook_outgoing.priority=NF_IP_PRI_FIRST;          
	nf_register_hook(&nfhook_outgoing); 
	
	nfhook_incoming.hook=latencyprobe_hook_func_in;				  
	nfhook_incoming.hooknum=NF_INET_LOCAL_IN;				
	nfhook_incoming.pf=PF_INET;						
	nfhook_incoming.priority=NF_IP_PRI_FIRST;			
	nf_register_hook(&nfhook_incoming);					
}

static void latencyprobe_nfhook_exit(void)
{
	nf_unregister_hook(&nfhook_outgoing); 
	nf_unregister_hook(&nfhook_incoming); 
}

#endif