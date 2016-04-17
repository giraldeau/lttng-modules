#!/usr/bin/env python

from fabric.api import task, run, env, sudo, local, cd, settings
import time

@task
def setup():
    run("mkdir -p repo/lttng-modules-dev.git")
    run("git init --bare repo/lttng-modules-dev.git")
    ctx = {
        'user': env.user,
        'host': env.host,
        'repo': 'repo/lttng-modules-dev.git',
    }
    with settings(warn_only=True):
        local("git remote remove tst-%(host)s" % ctx)
    local("git remote add tst-%(host)s ssh://%(user)s@%(host)s/home/%(user)s/%(repo)s" % ctx)
    local("git push tst-%(host)s master" % {'host': env.host})
    run("rm -rf lttng-modules-dev")
    run("git clone repo/lttng-modules-dev.git lttng-modules-dev")

@task
def deploy():
    branch = "fgraph"
    local("git push tst-%(host)s %(branch)s" % {'host': env.host, 'branch': branch})
    with cd("lttng-modules-dev"):
        run("git checkout %(branch)s" % {'branch': branch})
        run("git pull")
        run("make -j12")
        sudo("make modules_install")
        sudo("depmod -a")
        run("sync")

@task
def check():
    sudo("dmesg -c > /dev/null")
    sudo("modprobe lttng-fgraph")
    time.sleep(1)
    sudo("rmmod lttng-fgraph")
    sudo("dmesg -c")
