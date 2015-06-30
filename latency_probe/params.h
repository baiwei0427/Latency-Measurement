#ifndef __PARAMS_H__
#define __PARAMS_H__

#include "log.h"

static s64 latencyprobe_max_value;

/* Sum of ip_queue_xmit time interval samples */
static unsigned long long latencyprobe_tsum_ip_queue_xmit;
/* Sum of ip_output time interval samples */
static unsigned long long latencyprobe_tsum_ip_output;
/* Sum of dev_queue_xmit  time interval samples */
static unsigned long long latencyprobe_tsum_dev_queue_xmit;
/* Sum of tc dequeue (hard_start_xmit) time interval samples */
static unsigned long long latencyprobe_tsum_tc_dequeue;
/* Sum of ip_rcv time interval samples */
static unsigned long long latencyprobe_tsum_ip_rcv;
/* Sum of ip_local_deliver time interval samples */
static unsigned long long latencyprobe_tsum_ip_local_deliver;
/* Sum of tcp_v4_rcv time interval samples */
static unsigned long long latencyprobe_tsum_tcp_v4_rcv;

/* Number of time interval samples to ip_queue_xmit */
static int latencyprobe_sample_ip_queue_xmit;
/* Number of time interval samples to ip_output */
static int latencyprobe_sample_ip_output;
/* Number of time interval samples to dev_queue_xmit */
static int latencyprobe_sample_dev_queue_xmit;
/* Number of time interval samples to tc dequeue (hard_start_xmit) */
static int latencyprobe_sample_tc_dequeue;
/* Number of time interval samples to ip_rcv */
static int latencyprobe_sample_ip_rcv;
/* Number of time interval samples to ip_local_deliver */
static int latencyprobe_sample_ip_local_deliver;
/* Number of time interval samples to tcp_v4_rcv */
static int latencyprobe_sample_tcp_v4_rcv;

/* Sum of RTT samples*/
static unsigned long long latencyprobe_tsum_rtt;
/* Number of RTT samples */
static int latencyprobe_sample_rtt;

/* TCP port for filter */
static int latencyprobe_port;
/* We print one TX time information record based on 'latencyprobe_tx_sample_thresh' sample results */ 
static int latencyprobe_tx_sample_thresh;
/* We print one RX time information record based on 'latencyprobe_rx_sample_thresh' sample results */ 
static int latencyprobe_rx_sample_thresh;
/* We print one RTT information record based on 'latencyprobe_rtt_sample_thresh' sample results */
static int latencyprobe_rtt_sample_thresh;

struct latencyprobe_param {
	char name[64];
	int *ptr;
};

/* The following four parameters that can be configured through sysctl */
static struct latencyprobe_param latencyprobe_params[5]={
	{"port\0", &latencyprobe_port},
	{"tx_sample\0", &latencyprobe_tx_sample_thresh},
	{"rx_sample\0", &latencyprobe_rx_sample_thresh},
	{"rtt_sample\0", &latencyprobe_rtt_sample_thresh},
	{"\0", NULL},
};

static struct ctl_table latencyprobe_params_table[5];

static struct ctl_path latencyprobe_params_path[] = {
	{ .procname = "latencyprobe" },
	{ },
};

struct ctl_table_header *latencyprobe_sysctl=NULL;

static int latencyprobe_params_init(void)
{
	int i=0;
	
	latencyprobe_max_value=LLONG_MAX/10000;
	
	latencyprobe_tsum_ip_queue_xmit=0;
	latencyprobe_tsum_ip_output=0;
	latencyprobe_tsum_dev_queue_xmit=0;
	latencyprobe_tsum_tc_dequeue=0;
	latencyprobe_tsum_ip_rcv=0;
	latencyprobe_tsum_ip_local_deliver=0;
	latencyprobe_tsum_tcp_v4_rcv=0;

	latencyprobe_sample_ip_queue_xmit=0;
	latencyprobe_sample_ip_output=0;
	latencyprobe_sample_dev_queue_xmit=0;
	latencyprobe_sample_tc_dequeue=0;
	latencyprobe_sample_ip_rcv=0;
	latencyprobe_sample_ip_local_deliver=0;
	latencyprobe_sample_tcp_v4_rcv=0;

	latencyprobe_tsum_rtt=0;
	latencyprobe_sample_rtt=0;

	latencyprobe_port=80;
	latencyprobe_tx_sample_thresh=10000;
	latencyprobe_rx_sample_thresh=10000;
	latencyprobe_rtt_sample_thresh=10000;

	memset(latencyprobe_params_table, 0, sizeof(latencyprobe_params_table));
	
	for(i = 0; i < 5; i++) 
	{
		//End
		if(latencyprobe_params[i].ptr == NULL)
			break;
		//Initialize entry (ctl_table)
		struct ctl_table *entry = &latencyprobe_params_table[i];
		entry->procname=latencyprobe_params[i].name;
		entry->data=latencyprobe_params[i].ptr;
		entry->mode=0644;
		entry->proc_handler=&proc_dointvec;
		entry->maxlen=sizeof(int);
	}
	
	latencyprobe_sysctl=register_sysctl_paths(latencyprobe_params_path, latencyprobe_params_table);
	if(latencyprobe_sysctl==NULL)
		return -1;
	else	
		return 0;
	return 0;
}

static void latencyprobe_params_exit(void)
{
	if(latencyprobe_sysctl!=NULL)
		unregister_sysctl_table(latencyprobe_sysctl);
}

/*
 * The following two functions are related to 'operation'
 * To clear flow table: echo -n clear > /sys/module/latency_probe/parameters/operation
 * To print flow table: echo -n print > /sys/module/latency_probe/parameters/operation
 */
static int latencyprobe_set_operation(const char *val, struct kernel_param *kp)
{
	/* Clear statistic data */
	if(strncmp(val,"clear\0",5)==0)
	{
		latencyprobe_tsum_ip_queue_xmit=0;
		latencyprobe_tsum_ip_output=0;
		latencyprobe_tsum_dev_queue_xmit=0;
		latencyprobe_tsum_tc_dequeue=0;
		latencyprobe_tsum_ip_rcv=0;
		latencyprobe_tsum_ip_local_deliver=0;
		latencyprobe_tsum_tcp_v4_rcv=0;

		latencyprobe_sample_ip_queue_xmit=0;
		latencyprobe_sample_ip_output=0;
		latencyprobe_sample_dev_queue_xmit=0;
		latencyprobe_sample_tc_dequeue=0;
		latencyprobe_sample_ip_rcv=0;
		latencyprobe_sample_ip_local_deliver=0;
		latencyprobe_sample_tcp_v4_rcv=0;

		latencyprobe_tsum_rtt=0;
		latencyprobe_sample_rtt=0;
		printk(KERN_INFO "Latencyprobe: clear statistic data\n");
	}
	/* Print statistic data */
	else if(strncmp(val,"print\0",5)==0)
	{
		printk(KERN_INFO "Latencyprobe: print statistic data\n");
		
		if(latencyprobe_sample_ip_queue_xmit>0)
			latencyprobe_print_timeinterval("TX ip_queue_xmit", latencyprobe_tsum_ip_queue_xmit/latencyprobe_sample_ip_queue_xmit); 
		
		if(latencyprobe_sample_ip_output>0)
			latencyprobe_print_timeinterval("TX ip_output", latencyprobe_tsum_ip_output/latencyprobe_sample_ip_output); 
		
		if(latencyprobe_sample_dev_queue_xmit>0)
			latencyprobe_print_timeinterval("TX dev_queue_xmit", latencyprobe_tsum_dev_queue_xmit/latencyprobe_sample_dev_queue_xmit); 
		
		if(latencyprobe_sample_tc_dequeue>0)
			latencyprobe_print_timeinterval("TX tc_dequeue", latencyprobe_tsum_tc_dequeue/latencyprobe_sample_tc_dequeue); 
		
		if(latencyprobe_sample_ip_rcv>0)
			latencyprobe_print_timeinterval("RX ip_rcv", latencyprobe_tsum_ip_rcv/latencyprobe_sample_ip_rcv); 
		
		if(latencyprobe_sample_ip_local_deliver>0)
			latencyprobe_print_timeinterval("RX ip_local_deliver", latencyprobe_tsum_ip_local_deliver/latencyprobe_sample_ip_local_deliver); 
		
		if(latencyprobe_sample_tcp_v4_rcv>0)
			latencyprobe_print_timeinterval("RX tcp_v4_rcv", latencyprobe_tsum_tcp_v4_rcv/latencyprobe_sample_tcp_v4_rcv); 
		
		if(latencyprobe_sample_rtt>0)
			latencyprobe_print_timeinterval("RTT", latencyprobe_tsum_rtt/latencyprobe_sample_rtt); 
	}
	else
	{
		printk(KERN_INFO "Latencyprobe: unrecognized operation\n");
	}
	return 0;
}

static int latencyprobe_noget(const char *val, struct kernel_param *kp)
{
	return 0;
}

#endif