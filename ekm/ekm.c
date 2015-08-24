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

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/ekm.h"

DEFINE_TRACE(ekm_foo);

#define EKM_DEV_NAME "ekm"

/*
 * File operations available on this device.
 */
static const struct file_operations ekm_fops = {
	.owner		= THIS_MODULE,
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
static int __init ekm_init(void) {
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
