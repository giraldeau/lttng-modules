#!/bin/bash

if [ $# -lt 1 ]
then
        echo "Usage : $0 [load|unload|reload]"
        exit
fi

load_modules() {
	echo "loading lttng-addons"
	sudo modprobe lttng-probe-addons
	sudo modprobe lttng-packet
	sudo modprobe lttng-ttwu
}

unload_modules() {
	echo "unloading lttng-addons"
	sudo rmmod lttng-probe-addons
	sudo rmmod lttng-ttwu
	sudo rmmod lttng-packet
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

