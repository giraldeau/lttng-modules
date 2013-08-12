/*
 * addons/lttng-modsign.c
 *
 * Add X.509 certificate used to sign lttng modules
 *
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/module.h>
#include "wrapper/kallsyms.h"

extern __initdata const u8 lttng_modsign_certificate_list[];
extern __initdata const u8 lttng_modsign_certificate_list_end[];

/*
 * We need to make sure ccache doesn't cache the .o file as it doesn't notice
 * if modsign.pub changes.
 */
static __initdata const char annoy_ccache[] = __TIME__ "foo";

static
struct key *(*find_keyring)(const char *name, bool perm);

/*
 * Load the compiled-in keys
 */
static int load_module_signing_keys(struct key *keyring)
{
	key_ref_t key;
	const u8 *p, *end;
	size_t plen;

	pr_notice("Loading module verification certificates\n");

	end = lttng_modsign_certificate_list_end;
	p = lttng_modsign_certificate_list;
	while (p < end) {
		/* Each cert begins with an ASN.1 SEQUENCE tag and must be more
		 * than 256 bytes in size.
		 */
		if (end - p < 4)
			goto dodgy_cert;
		if (p[0] != 0x30 &&
		    p[1] != 0x82)
			goto dodgy_cert;
		plen = (p[2] << 8) | p[3];
		plen += 4;
		if (plen > end - p)
			goto dodgy_cert;

		key = key_create_or_update(make_key_ref(keyring, 1),
					   "asymmetric",
					   NULL,
					   p,
					   plen,
					   (KEY_POS_ALL & ~KEY_POS_SETATTR) |
					   KEY_USR_VIEW,
					   KEY_ALLOC_NOT_IN_QUOTA);
		if (IS_ERR(key))
			pr_err("MODSIGN: Problem loading in-kernel X.509 certificate (%ld)\n",
			       PTR_ERR(key));
		else
			pr_notice("MODSIGN: Loaded cert '%s'\n",
				  key_ref_to_ptr(key)->description);
		p += plen;
	}

	return 0;

dodgy_cert:
	pr_err("MODSIGN: Problem parsing in-kernel X.509 certificate list\n");
	return 0;
}


void find_kallsyms(void)
{
	struct key *keyring;

	find_keyring = (void *) kallsyms_lookup_funcptr("find_keyring_by_name");
	printk("find_keyring = %p\n", find_keyring);
	if (!find_keyring) {
		printk("kallsyms failed\n");
		return;
	}
	keyring = find_keyring(".module_sign", true);
	if (!keyring)
		return;
	printk("find_kallsyms %p %s\n", keyring, keyring->type->name);

	load_module_signing_keys(keyring);
}

void find_normal(void)
{
	struct key *key;

	key = request_key(&key_type_keyring, ".module_sign", NULL);
	printk("find_normal %p\n", key);
}

static int __init lttng_modsign_init(void)
{
	find_kallsyms();
	//find_normal();
	printk("%s loaded\n", THIS_MODULE->name);
	return -1;
}

static void __exit lttng_modsign_exit(void)
{
	printk("%s unloaded\n", THIS_MODULE->name);
	return;
}

module_init(lttng_modsign_init);
module_exit(lttng_modsign_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng network tracer");
