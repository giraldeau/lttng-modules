#!/bin/bash

if [ $# -lt 1 ]
then
        echo "Usage : $0 [load|unload|reload]"
        exit
fi

modules="lttng-probe-addons lttng-packet lttng-ttwu lttng-elv"

virt_what=$(which virt-what)

if [ -z "$virt_what" ]; then
	echo "Warning: virt-what not found, required to load the right vmsync module"
	echo "sudo apt-get install virt-what"
else
	if [ "$(sudo virt-what)" = "kvm" ]; then
		vmsync="lttng-vmsync-guest"
	else
		vmsync="lttng-vmsync-host"
	fi
	modules="$modules $vmsync"
fi

manage_modules() {
	op=$1
	for mod in $modules; do
		sudo $op $mod
	done
}

case "$1" in
load)
	manage_modules modprobe
    ;;
unload)
	manage_modules rmmod
    ;;
reload)
	manage_modules rmmod
	manage_modules modprobe
    ;;
*) echo "unkown command $1"
   ;;
esac

