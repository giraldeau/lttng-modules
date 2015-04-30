/*
 * net_filt_tp.c
 *
 * A filtered version of netif_receive_skb
 *
 * Copyright (C) 2014 Suchakra Sharma <suchakrapani.sharma@polymtl.ca>
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
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <trace/bpf_trace.h>
#include <asm/syscall.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <uapi/linux/time.h>
//#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include "../wrapper/tracepoint.h"

#define CREATE_TRACE_POINTS
#include <trace/events/net_filt.h>

#define BPF 0
#define SIMPLE 1
#define NOFILT 0

/* Procfs stuff */
#define MAX_LEN	16000000
static struct proc_dir_entry *proc_entry;
static char *accum_time;
u64 len = 0;

static int ebpf_proc_show(struct seq_file *m, void *v) {
    seq_printf(m, accum_time);
    return 0;
}

static int ebpf_proc_open(struct inode *inode, struct  file *file) {
    return single_open(file, ebpf_proc_show, NULL);
}

static const struct file_operations ebpf_proc_fops = {
    .owner = THIS_MODULE,
    .open = ebpf_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/* Timing stuff */ 
atomic_t count = ATOMIC_INIT(0);

#if 1
/* Global definitions */
struct bpf_prog *prog;

/* The actual eBPF prog instructions */
static struct bpf_insn insn_prog[] = { 
    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0), /* r2 = &bctx (which is therefore &arg1, and thus, &dev->name) */
    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, 0), /* r3 = *(dev->name) */
    BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_1, 8), /* r4 = (u64) 28524, which is "lo" */
    BPF_JMP_REG(BPF_JEQ, BPF_REG_3, BPF_REG_4, 3), /* compare arg1 and arg2 */
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

/* We don't need maps for now, keep for later*/
void bpf_map_free_deferred(struct work_struct *work)
{
    struct bpf_map *map = container_of(work, struct bpf_map, work);

    /* implementation dependent freeing */
    map->ops->map_free(map);
}

void bpf_map_put(struct bpf_map *map)
{
    if (atomic_dec_and_test(&map->refcnt)) {
        INIT_WORK(&map->work, bpf_map_free_deferred);
        schedule_work(&map->work);
    }
}

static void free_used_maps(struct bpf_prog_aux *aux)
{
    int i;

    for (i = 0; i < aux->used_map_cnt; i++)
        bpf_map_put(aux->used_maps[i]);

    kfree(aux->used_maps);
}

/* Filter runs. See bpf() syscall for more info */
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

    //TODO eBPF Verifier - find a way to get it working
    // char *sym_name = "bpf_check";
    // unsigned long sym_addr = kallsyms_lookup_name(sym_name);
    // int (*bpf_check)(struct bpf_prog*, union bpf_attr*) = (int (*)(struct bpf_prog*, union bpf_attr*) ) sym_addr;
    // ret = bpf_check(prog, &attr);

    // ready for JIT
    bpf_prog_select_runtime(prog);
    printk("prog jited? : %d\n", prog->jited);

    return 0;
}

#endif
static
void filt_handler(void* __data, struct sk_buff *skb)
{
    struct timespec begin, end, diff;
    char dev_name[] = "lo";
    struct net_device *dev;
    dev = (struct net_device*) skb->dev;
    struct bpf_context bctx = {};
    bctx.arg1 = (u64) dev->name;
    bctx.arg2 = (u64) 28524;		// int value for "lo"

    // tic
    getrawmonotonic(&begin);
#if (NOFILT)
    trace_netif_receive_skb_filter(skb);

#elif (SIMPLE)
    if (memcmp(dev->name, dev_name, 2) == 0)
    {
        trace_net_filt(skb);
    }
#elif (BPF)
    unsigned int ret = 0;
    ret = run_bpf_filter(prog, &bctx);
    if (ret == 1){
        trace_net_filt(skb);
    }
#endif

    // toc
    getrawmonotonic(&end);
    diff = timespec_sub(end, begin);
    atomic_inc(&count);
    //sprintf(accum_time + strlen(accum_time), "%d\t%lu.%09lu\n", atomic_read(&count), diff.tv_sec, diff.tv_nsec);
    sprintf(accum_time + strlen(accum_time), "%d\t%lu\n", atomic_read(&count), diff.tv_nsec);
}


static int __init net_filt_init(void)
{
    int ret = 0;

#if (SIMPLE)
    printk("SIMPLE RUN\n");

#elif (BPF)
    printk("BPF RUN\n");

    /* Prepare eBPF prog*/
    ret = init_ebpf_prog();
#endif

    /* Init procfs entry */
    accum_time = (char*) vmalloc(MAX_LEN);
    memset(accum_time, 0, MAX_LEN);
    proc_entry = proc_create("eBPFtimer", 0, NULL, &ebpf_proc_fops);

    if (proc_entry == NULL)
    {
        ret = -1;
        vfree(accum_time);
        printk(KERN_INFO "eBPFtimer could not be created\n");
    }
    else
    {
        printk(KERN_INFO "eBPFtimer created.\n");
    }

    (void) wrapper_lttng_fixup_sig(THIS_MODULE);

    ret = lttng_wrapper_tracepoint_probe_register("netif_receive_skb",
            filt_handler, NULL);
    if (ret)
        goto error;

    printk("net_filt loaded\n");
    return 0;


error:
    return ret;
}

static void __exit net_filt_exit(void)
{
    int ret;

#if (BPF)
    free_used_maps(prog->aux);
    printk("Freed maps\n");
    bpf_prog_free(prog);
    printk("Freed bpf prog\n");
#endif

    /* Remove procfs entry */
    remove_proc_entry("eBPFtimer", NULL);
    printk(KERN_INFO "eBPFtimer removed\n");
    vfree(accum_time);

    ret = lttng_wrapper_tracepoint_probe_unregister("netif_receive_skb",
            filt_handler, NULL);

    printk("net_filt unloaded\n");
    return;
}

module_init(net_filt_init);
module_exit(net_filt_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Suchakra Sharma <suchakrapani.sharma@polymtl.ca>");
MODULE_DESCRIPTION("LTTng filtered netif_receive_skb event");
