#!/bin/bash

if [ $# -lt 1 ]
then
        echo "Usage : $0 [load|unload|reload]"
        exit
fi

load_modules() {
	echo "loading lttng-addons"
	sudo modprobe lttng-modsign
	sudo modprobe lttng-probe-addons
	sudo modprobe lttng-addons
	sudo modprobe lttng-syscall-entry
	#sudo modprobe lttng-mmap
	sudo modprobe lttng-ttwu
}

unload_modules() {
	echo "unloading lttng-addons"
	sudo rmmod lttng-probe-addons
	sudo rmmod lttng-ttwu
	sudo rmmod lttng-addons
	sudo rmmod lttng-syscall-entry
	#sudo rmmod lttng-mmap
	sudo rmmod lttng-modsign
}

reload_modules() {
	unload_modules
	load_modules
}

case "$1" in
load)
	load_modules
    ;;
unload)
	unload_modules
    ;;
reload)
	reload_modules
    ;;
*) echo "unkown command $1"
   ;;
esac

