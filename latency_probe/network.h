#ifndef NETWORK_H
#define NETWORK_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ktime.h>

/* Function to calculate microsecond-granularity TCP timestamp value */
inline static unsigned int latencyprobe_get_tsval(void)
{	
	return (unsigned int)(ktime_to_ns(ktime_get())>>10);
}

/* Function to filter TCP packets based on port */
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

/* direction =1 (outgoing), 0 (incoming) */
unsigned int latencyprobe_tcp_modify_timestamp(struct sk_buff *skb, unsigned int direction)
{
	struct iphdr *iph=ip_hdr(skb);	//IP  header structure
	struct tcphdr *tcph=tcp_hdr(skb);	//TCP header structure
	unsigned int tcp_header_len=0;	//TCP header length
	unsigned char *tcp_opt=NULL;	 //TCP option pointer
	unsigned int *tsecr=NULL;	//TCP Timestamp echo reply pointer
	unsigned int *tsval=NULL;	//TCP Timestamp value pointer
	int tcplen=0;	//Length of TCP
	unsigned char tcp_opt_value=0;	//TCP option pointer value
	unsigned int rtt=0; //Sample RTT
	unsigned int option_len=0;	//TCP option length
	
	//If we can not modify this packet, return 0
	if (unlikely(skb_linearize(skb)!= 0)) 
	{
		return 0;
	}
	//Filter packets 
	if(!latencyprobe_filter_packet(ntohs(tcph->source),ntohs(tcph->dest)))
	{
		return 0;
	}
	
	//Get TCP header length
	tcp_header_len=(unsigned int)(tcph->doff*4);
	
	//Minimum TCP header length=20(Raw TCP header)+10(TCP Timestamp option)
	if(tcp_header_len<30)
	{
		return 0;
	}
	
	//TCP option offset=IP header pointer+IP header length+TCP header length
	tcp_opt=(unsigned char*)iph+ iph->ihl*4+20;
	
	while(1)
	{
		//If pointer has moved out off the range of TCP option, stop current loop
		if(tcp_opt-(unsigned char*)tcph>=tcp_header_len)
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
			if(direction>0) //Modify outgoing packets
			{
				//Get pointer to Timestamp value 
				tsval=(unsigned int*)(tcp_opt+2);
				//Modify TCP Timestamp value
				*tsval=htonl(latencyprobe_get_tsval());
			}
			else //Modify incoming packets
			{
				//Get pointer to Timestamp echo reply (TSecr)
				tsecr=(unsigned int*)(tcp_opt+6);
				//Get one RTT sample
				rtt=latencyprobe_get_tsval()-ntohl(*tsecr);
				printk(KERN_INFO "RTT: %u\n",rtt);
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
			
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                  tcplen, iph->protocol,
                                  csum_partial((char *)tcph, tcplen, 0));
								  
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return rtt;
} 

#endif