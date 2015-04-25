#ifndef NETWORK_H
#define NETWORK_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

inline int latencyprobe_filter_packet(unsigned short int src_port, unsigned short int dst_port)
{
	return (src_port==5001)||(dst_port==5001);
}

/* print timestamp information for TCP packets whose IP header may not be set*/
void latencyprobe_print_timestamp2(struct sk_buff *skb, char *str)
{
	struct tcphdr *tcph=tcp_hdr(skb);
	if(likely(tcph!=NULL))
	{
		if(latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
		{
			ktime_t now=ktime_get();
			printk(KERN_INFO "TX ip_queue_xmit: %lld\n",now.tv64-skb->tstamp.tv64);
		}
	}
}

/* print timestamp information for TCP packets*/
void latencyprobe_print_timestamp(struct sk_buff *skb, char *str)
{
	struct iphdr *iph=ip_hdr(skb);
	struct tcphdr *tcph=NULL;
	ktime_t now;
	
	if(unlikely(iph==NULL))
		return;
	
	/*We only handle tcp packets with source/destination port=5001 */
	if(likely(iph->protocol==IPPROTO_TCP))
	{
		/* We don't use tcp_hdr here because transport_header may not be initialized */
		tcph=(struct tcphdr *)((__u32 *)iph+ iph->ihl);
		if(latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
		{
			now=ktime_get();
			printk(KERN_INFO "%s: %lld\n",str, now.tv64-skb->tstamp.tv64);
		}
	}
}

void latencyprobe_tcp_timestamp_outgoing(struct sk_buff *skb)
{
	
}

void latencyprobe_tcp_timestamp_incoming(struct sk_buff *skb)
{
	
}

#endif