/*
 * ekm.c
 *
 *  Created on: Aug 23, 2015
 *      Author: francis
 */

#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"

#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/ekm.h"

DEFINE_TRACE(ekm_lucky_int);

#define EKM_DEV_NAME "ekm"

#define EKM_IOCTL	_IO(0xF6, 0x91)

static char *secret = "SuperSecret";

static ssize_t
ekm_read(struct file *file, char __user *buf, size_t size, loff_t *off)
{
	struct task_struct *task = get_current();
	printk("ekm_read task=%p pid=%d\n", task, task->pid);
	if (buf) {
		char **dst = (void *)buf;
		*dst = (void *) secret;
	}

	return 0;
}

struct ekm_info {
	char *src;
	char *dst;
	int len;
};

struct ekm_item {
	int val1;
	int val2;
	int val3;
	struct list_head lst;
};

static LIST_HEAD(ekm_list);

void ekm_alloc()
{

}

void ekm_traverse()
{

}

void ekm_free()
{

}

long ekm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	//struct ekm_info *info = (void *) arg;
	if (printk_ratelimit()) {
		printk("ekm_ioctl\n");
	}
	//memcpy(info->dst, info->src, info->len);
	trace_ekm_lucky_int(42);

	switch (cmd) {
	EKM_ADD:
		break;
	EKM_RM:
		break;
	EKM_PRINT:
		break;
	}

	return 0;
}

/*
 * File operations available on this device.
 */
static const struct file_operations ekm_fops = {
	.owner		= THIS_MODULE,
	.read 		= ekm_read,
	.unlocked_ioctl	= ekm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= ekm_ioctl,
#endif
};

/*
 * Description of our special device.
 */
static struct miscdevice ekm_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = EKM_DEV_NAME,
	.fops = &ekm_fops,
	.mode = 0666,
};

/*
 * Unfortunately, Eclipse seems to dislike __init label. Ignore the syntax
 * warning for init and exit functions.
 */
static int __init ekm_init(void)
{
	/*
	 * The following wrapper call make sure the tracepoints are registered,
	 * even if the module is not signed.
	 */
	(void) wrapper_lttng_fixup_sig(THIS_MODULE);

	misc_register(&ekm_dev);
	printk("EKM loaded\n");
	return 0;
}
module_init(ekm_init);

static void __exit ekm_exit(void)
{
	misc_deregister(&ekm_dev);
	printk("EKM removed\n");
}
module_exit(ekm_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Put Your Name Here");
MODULE_DESCRIPTION("Ericsson Kernel Module");
