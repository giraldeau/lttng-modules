#!/bin/sh

sudo rmmod lttng-probe-addons
sudo rmmod lttng-addons
sudo modprobe lttng-addons
sudo modprobe lttng-probe-addons
sudo dmesg -c
