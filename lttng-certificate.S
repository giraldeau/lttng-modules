/*
 * lttng-modsign.S
 *
 *  Created on: 2013-08-12
 *      Author: francis
 */

.section ".rodata"
.globl lttng_modsign_certificate_list;
.globl lttng_modsign_certificate_list_end;

lttng_modsign_certificate_list:
	.incbin "signing_key.x509"
lttng_modsign_certificate_list_end:
