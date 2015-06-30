#ifndef NETWORK_H
#define NETWORK_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ktime.h>

#include "params.h"


/* Function to filter TCP packets based on port */
static inline int latencyprobe_filter_packet(unsigned short int src_port, unsigned short int dst_port)
{
	return (src_port==latencyprobe_port)||(dst_port==latencyprobe_port);
}

/* Calculate time interval for TCP packets whose IP headers may not be set*/
static s64 latencyprobe_timeinterval2(struct sk_buff *skb)
{
	struct tcphdr *tcph=tcp_hdr(skb);
	ktime_t now;
	s64 result=0;
	
	if(likely(tcph!=NULL))
	{
		if(latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
		{
			now=ktime_get_real();
			if(skb->tstamp.tv64>0)
			{
				result=now.tv64-skb->tstamp.tv64;
				if(likely(result<latencyprobe_max_value))
					return result;
				else
					return 0;
			}
		}
	}
	
	return 0;
}

/* Calculate time interval for TCP packets whose IP headers have been set */
static s64 latencyprobe_timeinterval(struct sk_buff *skb)
{
	struct iphdr *iph=ip_hdr(skb);
	struct tcphdr *tcph=NULL;
	s64 result=0;
	ktime_t now;
	
	if(unlikely(iph==NULL))
		return 0;
	
	/*We only handle tcp packets with source/destination port=5001 */
	if(likely(iph->protocol==IPPROTO_TCP))
	{
		/* We don't use tcp_hdr here because transport_header may not be initialized */
		tcph=(struct tcphdr *)((__u32 *)iph+ iph->ihl);
		if(latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
		{
			now=ktime_get_real();
			if(skb->tstamp.tv64>0)
			{
				result=now.tv64-skb->tstamp.tv64;
				if(likely(result<latencyprobe_max_value))
					return result;
				else
					return 0;
			}
		}
	}
	
	return 0;
}

#endif