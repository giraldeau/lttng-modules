/*
 * lttng-list-raw.c
 *
 *  Created on: Nov 16, 2015
 *      Author: francis
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include "lttng-events.h"
#include "lttng-tracer.h"

#define LTTNG_DEV_NAME "lttng_list_raw"

static int started = 0;
static int last_entry = 0;

static
void *tp_list_start(struct seq_file *m, loff_t *pos)
{
	struct lttng_probe_desc *probe_desc;
	struct lttng_probe_desc *probe_last;
	struct list_head *probe_list;
	int iter = 0, i;

	if (!started) {
		struct new_utsname *uts = utsname();
		seq_printf(m, "{\n");
		seq_printf(m, " \"linux\": {\n");
		seq_printf(m, "  \"sysname\": \"%s\",\n", uts->sysname);
		seq_printf(m, "  \"nodename\": \"%s\",\n", uts->nodename);
		seq_printf(m, "  \"release\": \"%s\",\n", uts->release);
		seq_printf(m, "  \"version\": \"%s\",\n", uts->version);
		seq_printf(m, "  \"machine\": \"%s\",\n", uts->machine);
		seq_printf(m, "  \"domainname\": \"%s\"\n },\n", uts->domainname);
		seq_printf(m, " \"lttng\": {\n");
		seq_printf(m, "  \"version\": \"%d.%d.%d\" \n },\n",
				LTTNG_MODULES_MAJOR_VERSION,
				LTTNG_MODULES_MINOR_VERSION,
				LTTNG_MODULES_PATCHLEVEL_VERSION);
		seq_printf(m, " \"events\": [\n");
		started = 1;
		last_entry = 0;
	}

	lttng_lock_sessions();
	probe_list = lttng_get_probe_list_head();
	probe_last = list_last_entry(probe_list, struct lttng_probe_desc, head);
	list_for_each_entry(probe_desc, probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			last_entry = (probe_desc == probe_last) &&
					(i == (probe_desc->nr_events - 1));
			if (iter++ >= *pos)
				return (void *) probe_desc->event_desc[i];
		}
	}
	/* End of list */
	return NULL;
}

static
void *tp_list_next(struct seq_file *m, void *p, loff_t *ppos)
{
	struct lttng_probe_desc *probe_desc;
	struct lttng_probe_desc *probe_last;
	struct list_head *probe_list;
	int iter = 0, i;

	(*ppos)++;
	probe_list = lttng_get_probe_list_head();
	probe_last = list_last_entry(probe_list, struct lttng_probe_desc, head);
	list_for_each_entry(probe_desc, probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			last_entry = (probe_desc == probe_last) &&
					(i == (probe_desc->nr_events - 1));
			if (iter++ >= *ppos)
				return (void *) probe_desc->event_desc[i];
		}
	}
	/* End of list */
	return NULL;
}

static
void tp_list_stop(struct seq_file *m, void *p)
{
	lttng_unlock_sessions();

	if (!p) {
		seq_printf(m, " ]\n}\n");
		started = 0;
	}
}

static const char *atype_names[] = {
		"integer",
		"enum",
		"array",
		"sequence",
		"string",
		"unkown",
};

static inline
const char *atype_name(enum abstract_types atype)
{
	if (atype > NR_ABSTRACT_TYPES) {
		atype = NR_ABSTRACT_TYPES;
	}
	return atype_names[atype];
}

static
int tp_list_show(struct seq_file *m, void *p)
{
	const struct lttng_event_desc *probe_desc = p;
	int i;

	seq_printf(m, " {\n  \"name\": \"%s\",\n", probe_desc->name);
	seq_printf(m, "  \"fields\": [\n");
	for (i = 0; i < probe_desc->nr_fields; i++) {
		seq_printf(m, "    { \"name\": \"%s\", \"atype\": \"%s\"",
				probe_desc->fields[i].name,
				atype_name(probe_desc->fields[i].type.atype));
		if (i == (probe_desc->nr_fields - 1)) {
			seq_printf(m, " }\n");
		} else {
			seq_printf(m, " },\n");
		}
	}
	if (last_entry) {
		seq_printf(m, "  ]\n }\n");
	} else {
		seq_printf(m, "  ]\n },\n");
	}
	return 0;
}

static
const struct seq_operations lttng_list_raw_seq_ops = {
		.start = tp_list_start,
		.next = tp_list_next,
		.stop = tp_list_stop,
		.show = tp_list_show,
};

static
int lttng_list_raw_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &lttng_list_raw_seq_ops);
}

/*
 * File operations available on this device.
 */
const struct file_operations raw_fops = {
		.owner = THIS_MODULE,
		.open = lttng_list_raw_open,
		.read = seq_read,
		.llseek = seq_lseek,
		.release = seq_release,
};

/*
 * Description of our special device.
 */
static struct miscdevice lttng_list_raw_dev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = LTTNG_DEV_NAME,
		.fops = &raw_fops,
		.mode = 0666,
};

static int __init lttng_list_raw_init(void)
{
	misc_register(&lttng_list_raw_dev);
	printk("lttng_list_raw loaded\n");
	return 0;
}
module_init(lttng_list_raw_init);

static void __exit lttng_list_raw_exit(void)
{
	misc_deregister(&lttng_list_raw_dev);
	printk("lttng_list_raw removed\n");
}
module_exit(lttng_list_raw_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("Raw access to lttng events");
