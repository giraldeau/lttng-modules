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

#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/vmalloc.h"
#include "module_abi.h"

#include <linux/bpf.h>
#include <linux/filter.h>
#include <trace/bpf_trace.h>
#include <asm/syscall.h>

#define CREATE_TRACE_POINTS
#include <trace/events/latency_tracker.h>

static struct proc_dir_entry *lttngprofile_proc_dentry;

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

/* Global definitions */
struct bpf_prog *prog;
 
/* The actual eBPF prog instructions */
static struct bpf_insn insn_prog[] = { 
    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0), /* r2 = bctx (which is therefore arg1, and thus, latency) */
    BPF_LD_IMM64(BPF_REG_3, 10000), /* r3 = 100000 ns (Threshold) */
    BPF_JMP_REG(BPF_JGT, BPF_REG_2, BPF_REG_3, 3),
    BPF_LD_IMM64(BPF_REG_0, 0), /* FALSE */
    BPF_EXIT_INSN(),
    BPF_LD_IMM64(BPF_REG_0, 1), /* TRUE */
    BPF_EXIT_INSN(),
};

static void  *u64_to_ptr(__u64 val){
    return (void *) (unsigned long) val;
}
 
static __u64 ptr_to_u64(void *ptr){
    return (__u64) (unsigned long) ptr;
}
 
unsigned int run_bpf_filter(struct bpf_prog *prog1, struct bpf_context *ctx){
    rcu_read_lock();
    u64 ret = BPF_PROG_RUN(prog1, (void*) ctx);
    rcu_read_unlock();
    return ret;
}
 
/* Inititlize and prepare the eBPF prog */
unsigned int init_ebpf_prog(void)
{
    int ret = 0;
    char bpf_log_buf[1024];
    unsigned int insn_count = sizeof(insn_prog) / sizeof(struct bpf_insn);

    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_UNSPEC,
        .insns = ptr_to_u64((void*) insn_prog),
        .insn_cnt = insn_count,
        .license = ptr_to_u64((void *) "GPL"),
        .log_buf = ptr_to_u64(bpf_log_buf),
        .log_size = 1024,
        .log_level = 1,
    };

    prog = bpf_prog_alloc(bpf_prog_size(attr.insn_cnt), GFP_USER);
    if (!prog)
        return -ENOMEM;
    prog->jited = false;
    prog->orig_prog = NULL;
    prog->len = attr.insn_cnt;

    if (memcpy(prog->insnsi, u64_to_ptr(attr.insns), prog->len * sizeof(struct bpf_insn)) != 0)
        atomic_set(&prog->aux->refcnt, 1);
    prog->aux->is_gpl_compatible = true;

    /* We skip verification for now */

    /* ready for JIT */
    bpf_prog_select_runtime(prog);
    printk("prog jited? : %d\n", prog->jited);

    return 0;
}

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
    printk("lttngprofile unregister process %d\n", tgid);
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
  uint64_t latency = 0;
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

/*
  if (sys_exit_ts - sys_entry_ts < latency_threshold) {
    return;
  }
*/

    latency = sys_exit_ts - sys_entry_ts;

    /* Prepare BPF context*/
    struct bpf_context bctx = {};
    bctx.arg1 = (u64) latency;

    /* Run the filter to decide */
    unsigned int res = 0;
    res = run_bpf_filter(prog, &bctx);
    if (res == 1){
        return;
    }

  // Send the signal.
  //send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);

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
long lttngprofile_module_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg)
{
  u32 hash;
  struct process_key_t key;
  struct process_val_t *val;
  struct lttngprofile_module_msg msg;
  struct task_struct *task = get_current();
  int ret = 0;
  void __user *umsg = (void *) arg;

  if (cmd != LTTNGPROFILE_MODULE_IOCTL)
    return -ENOIOCTLCMD;

  if (copy_from_user(&msg, umsg, sizeof(struct lttngprofile_module_msg)))
    return -EFAULT;

  key.tgid = task->tgid;
  hash = jhash(&key, sizeof(key), 0);

  switch(msg.cmd) {
  case LTTNGPROFILE_MODULE_REGISTER:
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
    printk("lttngprofile_module_ioctl register %d\n", task->tgid);
    break;
  case LTTNGPROFILE_MODULE_UNREGISTER:
    process_unregister(task->tgid);
    break;
  default:
    ret = -ENOTSUPP;
    break;
  }

  return ret;
}

static const struct file_operations lttngprofile_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = lttngprofile_module_ioctl,
#ifdef CONFIG_COMPAT
  .compat_ioctl = lttngprofile_module_ioctl,
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

int __init lttngprofile_init(void)
{
  int ret = 0;

    /* Prepare eBPF prog*/
    ret = init_ebpf_prog();
  (void) wrapper_lttng_fixup_sig(THIS_MODULE);
  wrapper_vmalloc_sync_all();

  lttngprofile_proc_dentry = proc_create_data(LTTNGPROFILE_PROC,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
      NULL, &lttngprofile_fops, NULL);

  if (!lttngprofile_proc_dentry) {
    printk(KERN_ERR "Error creating lttngprofile control file\n");
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
  if (lttngprofile_proc_dentry)
    remove_proc_entry(LTTNGPROFILE_PROC, NULL);

  probes_unregister();

  return ret;
}
module_init(lttngprofile_init);

void __exit lttngprofile_exit(void)
{
  struct process_val_t *process_val;
  struct thread_val_t *thread_val;
  int bkt;

  if (lttngprofile_proc_dentry)
    remove_proc_entry(LTTNGPROFILE_PROC, NULL);

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

    /*Free BPF stuff*/
    bpf_prog_free(prog);
    printk("Freed bpf prog\n");
}
module_exit(lttngprofile_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Suchakra");
MODULE_DESCRIPTION("LTTng-profile eBPF module.");
MODULE_VERSION("0.0.1");
