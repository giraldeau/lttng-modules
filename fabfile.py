#!/usr/bin/env python

from fabric.api import task, run, env, sudo, local, cd, settings, execute
import time, os

@task
def setup():
    run("mkdir -p repo/lttng-modules-dev.git")
    run("git init --bare repo/lttng-modules-dev.git")
    ctx = {
        'user': env.user,
        'host': env.host,
        'branch': 'fgraph',
        'repo': 'repo/lttng-modules-dev.git',
    }
    with settings(warn_only=True):
        local("git remote remove tst-%(host)s" % ctx)
    local("git remote add tst-%(host)s ssh://%(user)s@%(host)s/home/%(user)s/%(repo)s" % ctx)
    local("git push tst-%(host)s master" % ctx)
    run("rm -rf lttng-modules-dev")
    run("git clone repo/lttng-modules-dev.git lttng-modules-dev")
    with cd("lttng-modules-dev"):
        run("git checkout origin/%(branch)s" % ctx)
        run("git checkout -b fgraph")
    run("git config --global user.email test@example.com")
    run("git config --global user.name test")

@task
def deploy():
    branch = "fgraph"
    local("git push -f tst-%(host)s %(branch)s" % {'host': env.host, 'branch': branch})
    with cd("lttng-modules-dev"):
        run("git fetch origin fgraph")
        run("git reset --hard FETCH_HEAD")
        run("make -j12")
        sudo("make modules_install")
        sudo("depmod -a")
        run("sync")

def go(fn):
    sudo("dmesg -c > /dev/null")
    sudo("modprobe lttng-fgraph")
    try:
        fn()
    except Exception as e:
        print(e)
    sudo("rmmod lttng-fgraph")
    sudo("dmesg -c")

@task
def check():
    go(lambda: time.sleep(0.01))

def do_stat(repeat):
    for i in range(repeat):
        print("stat {}".format(i))
        run("stat $HOME > /dev/null")

@task
def check_stat():
    go(lambda: do_stat(0))
    go(lambda: do_stat(1))

@task
def stress():
    for i in range(10):
        execute(check)
