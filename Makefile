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
			lttng-context-hostname.o wrapper/random.o \
			lttng-context-callstack.o \
			probes/lttng.o

obj-m += lttng-statedump.o
lttng-statedump-objs := lttng-statedump-impl.o wrapper/irqdesc.o \
			wrapper/fdtable.o
lttng-statedump-defsyms = socket_file_ops

ifneq ($(CONFIG_HAVE_SYSCALL_TRACEPOINTS),)
lttng-tracer-objs += lttng-syscalls.o probes/lttng-probe-user.o
endif # CONFIG_HAVE_SYSCALL_TRACEPOINTS

ifneq ($(CONFIG_PERF_EVENTS),)
lttng-tracer-objs += $(shell \
	if [ $(VERSION) -ge 3 \
		-o \( $(VERSION) -eq 2 -a $(PATCHLEVEL) -ge 6 -a $(SUBLEVEL) -ge 33 \) ] ; then \
		echo "lttng-context-perf-counters.o" ; fi;)
endif # CONFIG_PERF_EVENTS

lttng-tracer-objs += $(shell \
	if [ $(VERSION) -eq 3 -a $(PATCHLEVEL) -ge 15 -a $(SUBLEVEL) -ge 0 ] ; then \
		echo "lttng-tracepoint.o" ; fi;)

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

		
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

%.i: %.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@
endif # KERNELRELEASE
