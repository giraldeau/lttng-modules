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
#include <linux/types.h>

#include "../wrapper/tracepoint.h"
#include "../wrapper/kallsyms.h"
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

void hexdump(char *buf, int length)
{
    int rows = length / 8;
    int row;
    int i;

    for (row = 0; row < rows; row++) {
        int off = row * 8;
        printk("%08x ", off);
        for (i = off; i < off + 8; i++) {
            printk("%02x ", buf[i] & 0xFF);
        }
        printk("\n");
    }
}

/*
 * Description of our special device.
 */
static struct miscdevice ekm_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = EKM_DEV_NAME,
	.fops = &ekm_fops,
	.mode = 0666,
};

static void fn(void)
{
	char *sym = "do_open";
	unsigned long virt = kallsyms_lookup_funcptr(sym);
	phys_addr_t phys = virt_to_phys((void *)virt);

	printk("virt=%lx phys=%llx offset=%llx\n", virt, phys, virt - phys);

	hexdump((void *) virt, 64);
	printk("done\n");
}

/*
 * Unfortunately, Eclipse seems to dislike __init label. Ignore the syntax
 * warning for init and exit functions.
 */
static int __init ekm_init(void) {
	/*
	 * The following wrapper call make sure the tracepoints are registered,
	 * even if the module is not signed.
	 */
	//(void) wrapper_lttng_fixup_sig(THIS_MODULE);


	fn();
	return 0;

	printk("EKM loaded\n");
	/*
	misc_register(&ekm_dev);
	printk("EKM loaded\n");
	return 0;
	*/
}
module_init(ekm_init);

static void __exit ekm_exit(void)
{
	//misc_deregister(&ekm_dev);
	printk("EKM removed\n");
}
module_exit(ekm_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Put Your Name Here");
MODULE_DESCRIPTION("Ericsson Kernel Module");
