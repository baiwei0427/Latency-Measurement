#ifndef __PARAMS_H__
#define __PARAMS_H__

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
	{"tx_sample_thresh\0", &latencyprobe_tx_sample_thresh},
	{"rx_sample\0", &latencyprobe_rx_sample_thresh},
	{"rtt_sample\0", &latencyprobe_rtt_sample_thresh},
	{"\0", NULL},
};

static struct ctl_table latencyprobe_params_table[4];

static struct ctl_path latencyprobe_params_path[] = {
	{ .procname = "latencyprobe" },
	{ },
};
struct ctl_table_header *latencyprobe_sysctl=NULL;

static int latencyprobe_params_init(void)
{
	int i=0;
	
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

	latencyprobe_port=5001;
	latencyprobe_tx_sample_thresh=50;
	latencyprobe_rx_sample_thresh=500;
	latencyprobe_rtt_sample_thresh=500;

	memset(latencyprobe_params_table, 0, sizeof(latencyprobe_params_table));
	
	for(i = 0; i < 5; i++) 
	{
		struct ctl_table *entry = &latencyprobe_params_table[i];
		//End
		if(latencyprobe_params[i].ptr == NULL)
			break;
		//Initialize entry (ctl_table)
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
}

static void latencyprobe_params_exit(void)
{
	if(latencyprobe_sysctl!=NULL)
		unregister_sysctl_table(latencyprobe_sysctl);
}

#endif