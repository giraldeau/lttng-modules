#!/bin/bash

sudo rmmod lttngprofile 2> /dev/null

set -e

sudo dmesg -c > /dev/null
sudo insmod lttngprofile.ko
sudo dmesg -c
