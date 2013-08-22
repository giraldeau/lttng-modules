#
# Makefile for the LTT objects.
#

ifneq ($(KERNELRELEASE),)
ifneq ($(CONFIG_TRACEPOINTS),)

obj-m += lttng-ring-buffer-client-discard.o
obj-m += lttng-ring-buffer-client-overwrite.o
obj-m += lttng-ring-buffer-metadata-client.o
obj-m += lttng-ring-buffer-client-mmap-discard.o
obj-m += lttng-ring-buffer-client-mmap-overwrite.o
obj-m += lttng-ring-buffer-metadata-mmap-client.o

obj-m += lttng-tracer.o
lttng-tracer-objs :=  lttng-events.o lttng-abi.o \
			lttng-probes.o lttng-context.o \
			lttng-context-pid.o lttng-context-procname.o \
			lttng-context-prio.o lttng-context-nice.o \
			lttng-context-vpid.o lttng-context-tid.o \
			lttng-context-vtid.o lttng-context-ppid.o \
			lttng-context-vppid.o lttng-calibrate.o \
			lttng-context-hostname.o lttng-context-callstack.o \
			wrapper/random.o

obj-m += lttng-statedump.o
lttng-statedump-objs := lttng-statedump-impl.o wrapper/irqdesc.o \
			wrapper/fdtable.o
lttng-statedump-defsyms = socket_file_ops

ifeq ($(CONFIG_MODULE_SIG),y)

AFLAGS_lttng-certificate.o := -Wa,-I$(PWD)
obj-m += lttng-modsign.o
lttng-modsign-objs += lttng-signature.o lttng-certificate.o

$(obj)/lttng-certificate.o: $(obj)/signing_key.x509
 
$(obj)/signing_key.priv $(obj)/signing_key.x509: x509.genkey
	openssl req -new -nodes -utf8 -"sha512" -days 36500 \
	    -batch -x509 -config $(obj)/x509.genkey \
	    -outform DER -out $(obj)/signing_key.x509 \
	    -keyout $(obj)/signing_key.priv 2>&1

$(obj)/x509.genkey:
	@echo Generating X.509 key generation config
	@echo  >$(obj)/x509.genkey "[ req ]"
	@echo >>$(obj)/x509.genkey "default_bits = 4096"
	@echo >>$(obj)/x509.genkey "distinguished_name = req_distinguished_name"
	@echo >>$(obj)/x509.genkey "prompt = no"
	@echo >>$(obj)/x509.genkey "string_mask = utf8only"
	@echo >>$(obj)/x509.genkey "x509_extensions = myexts"
	@echo >>$(obj)/x509.genkey
	@echo >>$(obj)/x509.genkey "[ req_distinguished_name ]"
	@echo >>$(obj)/x509.genkey "O = LTTng"
	@echo >>$(obj)/x509.genkey "CN = signing key"
	@echo >>$(obj)/x509.genkey "emailAddress = info@lttng.org"
	@echo >>$(obj)/x509.genkey
	@echo >>$(obj)/x509.genkey "[ myexts ]"
	@echo >>$(obj)/x509.genkey "basicConstraints=critical,CA:FALSE"
	@echo >>$(obj)/x509.genkey "keyUsage=digitalSignature"
	@echo >>$(obj)/x509.genkey "subjectKeyIdentifier=hash"
	@echo >>$(obj)/x509.genkey "authorityKeyIdentifier=keyid"

endif # CONFIG_MODULE_SIG

ifneq ($(CONFIG_HAVE_SYSCALL_TRACEPOINTS),)
lttng-tracer-objs += lttng-syscalls.o probes/lttng-probe-user.o
endif # CONFIG_HAVE_SYSCALL_TRACEPOINTS

ifneq ($(CONFIG_PERF_EVENTS),)
lttng-tracer-objs += $(shell \
	if [ $(VERSION) -ge 3 \
		-o \( $(VERSION) -eq 2 -a $(PATCHLEVEL) -ge 6 -a $(SUBLEVEL) -ge 33 \) ] ; then \
		echo "lttng-context-perf-counters.o" ; fi;)
endif # CONFIG_PERF_EVENTS

obj-m += probes/
obj-m += lib/
obj-m += addons/

include $(src)/defsyms.mk

#KBUILD_EXTRA_SYMBOLS += $(src)/defsyms.symvers
#LDFLAGS_MODULE += -T $(src)/lttng-net.defsyms

# FIXME: the file is not cleaned
#clean-files := addons/lttng-addons.defsyms

endif # CONFIG_TRACEPOINTS

else # KERNELRELEASE
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
	CFLAGS = $(EXTCFLAGS)
	MODSECKEY = $(PWD)/signing_key.priv
	MODPUBKEY = $(PWD)/signing_key.x509

		
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) MODSECKEY=$(MODSECKEY) MODPUBKEY=$(MODPUBKEY) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

%.i: %.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@

endif # KERNELRELEASE
