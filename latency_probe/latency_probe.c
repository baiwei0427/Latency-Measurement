#include <linux/kernel.h>
#include <linux/module.h>

/* TC module */
#include "sch_multiq.h"
/* jprobe hooks */
#include "jprobe.h"
/* params and sysctl */
#include "params.h"

module_param_call(operation, latencyprobe_set_operation, latencyprobe_noget, NULL, S_IWUSR); //Write permission by owner

static __init int latencyprobe_init(void)
{
	/* Initialize sysctl */
	latencyprobe_params_init();
	/* Register jprobe hooks */
	latencyprobe_jprobe_init();
	/* Start TC qdisc */
	latencyprobe_multiq_init();

	printk(KERN_INFO "Latencyprobe: the kernel module starts\n");
	return 0;
}

static __exit void latencyprobe_exit(void)
{
	/* Unregister jprobe hooks */
	latencyprobe_jprobe_exit();
	/* Uninstall TC qdisc */
	latencyprobe_multiq_exit();
	/* Remove sysctl */
	latencyprobe_params_exit();

	printk(KERN_INFO "Latencyprobe: the kernel module stops\n");
}

module_init(latencyprobe_init);
module_exit(latencyprobe_exit);
MODULE_AUTHOR("BAI Wei <baiwei0427@gmail.com>");
MODULE_DESCRIPTION("Latency snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
