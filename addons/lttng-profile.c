/*
 * Copyright (C) 2015 Francois Doray <francois.doray@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Inspired from https://github.com/giraldeau/perfuser-modules,
 * by Francis Giraldeau.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/types.h>

#include "../wrapper/trace-clock.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/vmalloc.h"
#include "lttng-addons-abi.h"

#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(syscall_latency);

static struct proc_dir_entry *lttng_profile_proc_dentry;

struct process_key_t {
  pid_t tgid;
} __attribute__((__packed__));

struct process_val_t {
  pid_t tgid;
  uint64_t latency_threshold;
  struct hlist_node hlist;
  struct rcu_head rcu;
};

struct thread_key_t {
  pid_t pid;
} __attribute__((__packed__));


struct thread_val_t {
  pid_t pid;
  uint64_t sys_entry_ts;
  int sys_id;
  struct hlist_node hlist;
  struct rcu_head rcu;
};

/* map<process_key_t, process_val_t> */
static DEFINE_HASHTABLE(process_map, 3);

/* map<thread_key_t, thread_val_t> */
static DEFINE_HASHTABLE(thread_map, 3);

/*
 * RCU-related functions.
 */
static void free_process_val_rcu(struct rcu_head *rcu)
{
  kfree(container_of(rcu, struct process_val_t, rcu));
}

static void free_thread_val_rcu(struct rcu_head *rcu)
{
  kfree(container_of(rcu, struct thread_val_t, rcu));
}

static struct process_val_t*
find_process(struct process_key_t *key, u32 hash)
{
  struct process_val_t *val;

  hash_for_each_possible_rcu(process_map, val, hlist, hash) {
    if (key->tgid == val->tgid) {
      return val;
    }
  }
  return NULL;
}

static struct process_val_t*
find_current_process(void)
{
  u32 hash;
  struct process_key_t process_key;

  process_key.tgid = get_current()->tgid;
  hash = jhash(&process_key, sizeof(process_key), 0);

  return find_process(&process_key, hash);
}

static struct thread_val_t*
find_thread(struct thread_key_t *key, u32 hash)
{
  struct thread_val_t *val;

  hash_for_each_possible_rcu(thread_map, val, hlist, hash) {
    if (key->pid == val->pid) {
      return val;
    }
  }
  return NULL;
}

/*
 * Utility functions.
 */
static void process_unregister(pid_t tgid)
{
  u32 hash;
  struct process_key_t key;
  struct process_val_t *val;

  key.tgid = tgid;
  hash = jhash(&key, sizeof(key), 0);

  rcu_read_lock();
  val = find_process(&key, hash);
  if (val) {
    hash_del_rcu(&val->hlist);
    call_rcu(&val->rcu, free_process_val_rcu);
    // TODO: add verbose option
    //printk("lttng_profile unregister process %d\n", tgid);
  }
  rcu_read_unlock();
}

/*
 * Probes.
 */
static void syscall_entry_probe(
    void *__data, struct pt_regs *regs, long id)
{
  u32 hash;
  struct process_val_t *process_val;
  struct thread_key_t thread_key;
  struct thread_val_t *thread_val;
  struct task_struct *task = get_current();
  uint64_t sys_entry_ts = trace_clock_read64();

  // Check whether the process is registered to receive signals.
  rcu_read_lock();
  process_val = find_current_process();

  if (process_val == NULL) {
    rcu_read_unlock();
    return;
  }

  // Keep track of the timestamp of this syscall entry.
  thread_key.pid = task->pid;
  hash = jhash(&thread_key, sizeof(thread_key), 0);
  thread_val = find_thread(&thread_key, hash);

  if (thread_val != NULL) {
    thread_val->sys_entry_ts = sys_entry_ts;
    thread_val->sys_id = id;
    rcu_read_unlock();
    return;
  }

  rcu_read_unlock();

  thread_val = kzalloc(sizeof(struct thread_val_t), GFP_KERNEL);
  thread_val->pid = task->pid;
  thread_val->sys_entry_ts = sys_entry_ts;
  thread_val->sys_id = id;
  hash_add_rcu(thread_map, &thread_val->hlist, hash);
}

static void syscall_exit_probe(
    void *__data, struct pt_regs *regs, long ret)
{
  u32 hash;
  struct process_val_t *process_val;
  struct thread_key_t thread_key;
  struct thread_val_t *thread_val;
  struct task_struct *task = get_current();
  uint64_t latency_threshold = 0;
  uint64_t sys_entry_ts = 0;
  uint64_t sys_exit_ts = trace_clock_read64();
  int sys_id;

  // Check whether the process is registered to receive signals.
  rcu_read_lock();
  process_val = find_current_process();

  if (process_val == NULL) {
    rcu_read_unlock();
    return;
  }

  latency_threshold = process_val->latency_threshold;

  // Get the timestamp of the syscall entry.
  thread_key.pid = task->pid;
  hash = jhash(&thread_key, sizeof(thread_key), 0);
  thread_val = find_thread(&thread_key, hash);

  if (thread_val == NULL) {
    rcu_read_unlock();
    return;
  }

  sys_entry_ts = thread_val->sys_entry_ts;
  sys_id = thread_val->sys_id;

  rcu_read_unlock();

  // Check whether the system call was longer than the threshold.
  if (sys_exit_ts - sys_entry_ts < latency_threshold) {
    return;
  }

  // Send the signal.
  send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);

  // Log event.
  trace_syscall_latency(sys_entry_ts, sys_exit_ts - sys_entry_ts, sys_id);
}

static void sched_process_exit_probe(
    void *__data, struct task_struct *p)
{
  // TODO: Cleanup threads...

  // If this is the main thread of a process, unregister the process.
  if (p->pid == p->tgid) {
    process_unregister(p->tgid);
  }
}
/*
 * Module ioctl interface.
 */
long lttng_profile_module_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg)
{
  u32 hash;
  struct process_key_t key;
  struct process_val_t *val;
  struct lttng_profile_module_msg msg;
  struct task_struct *task = get_current();
  int ret = 0;
  void __user *umsg = (void *) arg;

  if (cmd != LTTNG_PROFILE_MODULE_IOCTL)
    return -ENOIOCTLCMD;

  if (copy_from_user(&msg, umsg, sizeof(msg)))
    return -EFAULT;

  key.tgid = task->tgid;
  hash = jhash(&key, sizeof(key), 0);

  switch(msg.cmd) {
  case LTTNG_PROFILE_MODULE_REGISTER:
    /* check if already registered */
    rcu_read_lock();
    val = find_process(&key, hash);
    if (val) {
      rcu_read_unlock();
      break;
    }
    rcu_read_unlock();
    /* do registration */
    val = kzalloc(sizeof(struct process_val_t), GFP_KERNEL);
    val->tgid = key.tgid;
    val->latency_threshold = msg.latency_threshold;
    hash_add_rcu(process_map, &val->hlist, hash);
    // TODO: add verbose option
    //printk("lttng_profile_module_ioctl register %d\n", task->tgid);
    break;
  case LTTNG_PROFILE_MODULE_UNREGISTER:
    process_unregister(task->tgid);
    break;
  default:
    ret = -ENOTSUPP;
    break;
  }

  return ret;
}

static const struct file_operations lttng_profile_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = lttng_profile_module_ioctl,
#ifdef CONFIG_COMPAT
  .compat_ioctl = lttng_profile_module_ioctl,
#endif
};

/*
 * Module life cycle.
 */
static void probes_unregister(void)
{
  lttng_wrapper_tracepoint_probe_unregister(
      "sys_enter", syscall_entry_probe, NULL);
  lttng_wrapper_tracepoint_probe_unregister(
      "sys_exit", syscall_exit_probe, NULL);
  lttng_wrapper_tracepoint_probe_unregister(
      "sched_process_exit", sched_process_exit_probe, NULL);
}

int __init lttng_profile_init(void)
{
  int ret = 0;

  wrapper_vmalloc_sync_all();

  lttng_profile_proc_dentry = proc_create_data(LTTNG_PROFILE_PROC,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
      NULL, &lttng_profile_fops, NULL);

  if (!lttng_profile_proc_dentry) {
    printk(KERN_ERR "Error creating lttng_profile control file\n");
    ret = -ENOMEM;
    goto error;
  }

  // Register probes.
  if (lttng_wrapper_tracepoint_probe_register(
        "sys_enter", syscall_entry_probe, NULL) < 0 ||
      lttng_wrapper_tracepoint_probe_register(
        "sys_exit", syscall_exit_probe, NULL) < 0 ||
      lttng_wrapper_tracepoint_probe_register(
        "sched_process_exit", sched_process_exit_probe, NULL) < 0)
  {
    printk("tracepoint_probe_register failed, returned %d\n", ret);
    goto error;
  }

  printk("LTTng-profile module loaded successfully.\n");

  return ret;

error:
  if (lttng_profile_proc_dentry)
    remove_proc_entry(LTTNG_PROFILE_PROC, NULL);

  probes_unregister();

  return ret;
}
module_init(lttng_profile_init);

void __exit lttng_profile_exit(void)
{
  struct process_val_t *process_val;
  struct thread_val_t *thread_val;
  int bkt;

  if (lttng_profile_proc_dentry)
    remove_proc_entry(LTTNG_PROFILE_PROC, NULL);

  probes_unregister();

  rcu_read_lock();
  hash_for_each_rcu(process_map, bkt, process_val, hlist) {
    hash_del_rcu(&process_val->hlist);
    call_rcu(&process_val->rcu, free_process_val_rcu);
  }
  hash_for_each_rcu(thread_map, bkt, thread_val, hlist) {
    hash_del_rcu(&thread_val->hlist);
    call_rcu(&thread_val->rcu, free_thread_val_rcu);
  }
  rcu_read_unlock();
  synchronize_rcu();
}
module_exit(lttng_profile_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francois Doray");
MODULE_DESCRIPTION("LTTng-profile module.");
MODULE_VERSION("0.0.1");
