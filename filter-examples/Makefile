ifneq ($(KERNELRELEASE),)
ifneq ($(CONFIG_TRACEPOINTS),)

ccflags-y += -I$(PWD)/filter-examples/include

lttngprofile-objs += profile.o rculfhash.o rculfhash-mm-chunk.o wfcqueue.o

obj-m := lttngprofile.o

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

