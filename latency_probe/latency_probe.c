#include <linux/kernel.h>
#include <linux/module.h>

/* TC module */
#include "sch_multiq.h"
/* jprobe hooks */
#include "jprobe.h"
/* Netfilter hooks */
#include "nfhook.h"

static __init int latencyprobe_init(void)
{
	/* Register jprobe hooks */
	latencyprobe_jprobe_init();
	/* Start TC qdisc */
	latencyprobe_multiq_init();
	/* Register netfilter hooks */
	latencyprobe_nfhook_init();
	
	printk(KERN_INFO "Latency probe module starts\n");
	return 0;
}

static __exit void latencyprobe_exit(void)
{
	/* Unregister jprobe hooks */
	latencyprobe_jprobe_exit();
	/* Uninstall TC qdisc */
	latencyprobe_multiq_exit();
	/* Unregister netfilter hooks */
	latencyprobe_nfhook_exit();
	
	printk(KERN_INFO "Latency probe module stops\n");
}

module_init(latencyprobe_init);
module_exit(latencyprobe_exit);
MODULE_AUTHOR("BAI Wei <baiwei0427@gmail.com>");
MODULE_DESCRIPTION("Latency snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");