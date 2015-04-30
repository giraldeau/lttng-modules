ifneq ($(KERNELRELEASE),)
ifneq ($(CONFIG_TRACEPOINTS),)

ccflags-y += -I$(PWD)/filter-examples/include

obj-m += lttngprofile.o 
obj-m += net_filt_tp.o
#net_filt_tp-objs += ../lttng-tracepoint.o
#net_filt_tp-objs += ../lttng-tracer.o

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

