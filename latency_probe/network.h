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
	
	if(likely(tcph!=NULL))
	{
		if(latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
		{
			ktime_t now=ktime_get();
			return now.tv64-skb->tstamp.tv64;
		}
	}
	
	return 0;
}

/* Calculate time interval for TCP packets whose IP headers have been set */
static s64 latencyprobe_timeinterval(struct sk_buff *skb)
{
	struct iphdr *iph=ip_hdr(skb);
	struct tcphdr *tcph=NULL;
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
			now=ktime_get();
			return now.tv64-skb->tstamp.tv64;
		}
	}
	
	return 0;
}

/* return microsecond-granularity timestamp value */
static inline unsigned int get_tsval(void)
{	
	return (unsigned int)(ktime_to_ns(ktime_get())>>10);
}

/* 
 * Modify TCP packets' Timestamp option and get sample RTT value
 * If time>0: modify outgoing TCP packets' Timestamp value
 * Else: modify incoming TCP pakcets' Timestamp echo reply and return RTT
 */
static unsigned int latencyprobe_tcp_modify_timestamp(struct sk_buff *skb, unsigned int time)
{
	struct iphdr *iph=NULL;	//IP  header structure
	struct tcphdr *tcph=NULL;	//TCP header structure
	unsigned int tcph_len=0;	//TCP header length
	unsigned char *tcp_opt=NULL;	//TCP option pointer
	unsigned int *tsecr=NULL;	//TCP Timestamp echo reply pointer
	unsigned int *tsval=NULL;	//TCP Timestamp value pointer
	int tcplen=0;	//Length of TCP
	unsigned char tcp_opt_value=0;	//TCP option pointer value
	unsigned int rtt=0;	//Sample RTT
	unsigned int option_len=0;	//TCP option length
	
	//If we can not modify this packet, return 0
	if (skb_linearize(skb)!= 0) 
	{
		return 0;
	}
	
	//Get IP header
	iph=(struct iphdr *)skb_network_header(skb);
	//Get TCP header on the base of IP header
	tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);
	//Get TCP header length
	tcph_len=(unsigned int)(tcph->doff*4);
	
	//Minimum TCP header length=20(Raw TCP header)+10(TCP Timestamp option)
	if(unlikely(tcph_len<30))
	{
		return 0;
	}
	
	//TCP option offset=IP header pointer+IP header length+TCP header length
	tcp_opt=(unsigned char*)iph+ iph->ihl*4+20;
	
	while(1)
	{
		//If pointer has moved out off the range of TCP option, stop current loop
		if(tcp_opt-(unsigned char*)tcph>=tcph_len)
		{
			break;
		}
		
		//Get value of current byte
		tcp_opt_value=*tcp_opt;
		
		if(tcp_opt_value==1)//No-Operation (NOP)
		{
			//Move to next byte
			tcp_opt++;
		}
		else if(tcp_opt_value==8) //TCP option kind: Timestamp (8)
		{
			if(time>0) //Modify outgoing packets
			{
				//Get pointer to Timestamp value 
				tsval=(unsigned int*)(tcp_opt+2);
				//Modify TCP Timestamp value
				*tsval=htonl(time);
			}
			else //Modify incoming packets
			{
				//Get pointer to Timestamp echo reply (TSecr)
				tsecr=(unsigned int*)(tcp_opt+6);
				//Get one RTT sample
				rtt=get_tsval()-ntohl(*tsecr);
				//printk(KERN_INFO "RTT: %u\n",rtt);
				//Modify TCP TSecr back to jiffies
				//Don't disturb TCP. Wrong TCP timestamp echo reply may reset TCP connections
				*tsecr=htonl(jiffies);
			}
			break;
		}
		else //Other TCP options (e.g. MSS(2))
		{
			//Move to next byte to get length of this TCP option 
			tcp_opt++;
			//Get length of this TCP option
			tcp_opt_value=*tcp_opt;
			option_len=(unsigned int)tcp_opt_value;
			
			//Move to next TCP option
			tcp_opt=tcp_opt+1+(option_len-2);
		}
	}
	
	//TCP length=Total length - IP header length
	tcplen=skb->len-(iph->ihl<<2);
	tcph->check=0;
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,tcplen, iph->protocol,csum_partial((char *)tcph, tcplen, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return rtt;
} 

#endif