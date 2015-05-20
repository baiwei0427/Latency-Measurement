#ifndef LOG_H
#define LOG_H

static inline void latencyprobe_print_timeinterval(char *name, unsigned long long t)
{
	printk(KERN_INFO "Latencyprobe: %s %llu ns\n", name,t);
}

#endif