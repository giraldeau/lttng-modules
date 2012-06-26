#
# Makefile for the LTT probes.
# Only build from the package top-level directory. Never use with make directly.

ifneq ($(KERNELRELEASE),)
ifneq ($(CONFIG_TRACEPOINTS),)

ccflags-y += -I$(PWD)/addons

obj-m += lttng-probe-addons.o
obj-m += lttng-addons.o
lttng-addons-objs += lttng-net.o lttng-packet.o
lttng-addons-defsyms = inet_family_ops

include $(src)/../defsyms.mk

ldflags-y := -T $(src)/lttng-addons.defsyms

endif

else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
	CFLAGS = $(EXTCFLAGS)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	/sbin/depmod -a

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

%.i: %.c
        $(MAKE) -C $(KERNELDIR) M=$(PWD) $@

endif
