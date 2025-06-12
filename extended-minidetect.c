#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Imran Khairuddin");
MODULE_DESCRIPTION("Extended Minidetect with Rootkit Checking Enhancements");

#define MAX_LOG 4096
static char logbuf[MAX_LOG];
static size_t loglen = 0;

#define log(fmt, ...) \
    do { \
        int n = snprintf(logbuf + loglen, MAX_LOG - loglen, fmt, ##__VA_ARGS__); \
        loglen += (n > 0 ? n : 0); \
        printk(KERN_INFO "minidetect: " fmt, ##__VA_ARGS__); \
    } while (0)

static int detect_hidden_modules(void)
{
    struct module *mod;
    int found = 0;

    list_for_each_entry(mod, THIS_MODULE->list.prev, list) {
        if (!mod->name || !mod->sect_attrs) {
            log("[ALERT] Hidden module detected!\n");
            found++;
        }
    }

    // Check if THIS_MODULE is unlinked
    if (THIS_MODULE->list.prev == &THIS_MODULE->list || THIS_MODULE->list.next == &THIS_MODULE->list) {
        log("[ALERT] THIS_MODULE appears to be unlinked from module list!\n");
        found++;
    }

    return found;
}

static int detect_hidden_tasks(void)
{
    struct task_struct *task;
    int count = 0;

    for_each_process(task) {
        if (task->flags & 0x10000000) {
            log("[ALERT] Hidden task: PID %d, Name %s\n", task->pid, task->comm);
            count++;
        }
    }
    return count;
}

static int detect_syscall_hooks(void)
{
    unsigned long *sys_call_table;
    unsigned long sys_read_addr;
    int hooked = 0;

    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    sys_read_addr = kallsyms_lookup_name("ksys_read");

    if (sys_call_table && sys_read_addr) {
        if ((unsigned long)sys_call_table[__NR_read] != sys_read_addr) {
            log("[ALERT] sys_read hook detected!\n");
            hooked++;
        }
    } else {
        log("[WARN] Could not resolve syscall table or ksys_read\n");
    }

    return hooked;
}

static int detect_tcp_seq_hook(void)
{
    void *tcp4_seq_show = (void *)kallsyms_lookup_name("tcp4_seq_show");
    struct seq_operations *tcp_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp_seq_ops");
    int found = 0;

    if (tcp4_seq_show && tcp_seq_ops) {
        if (tcp_seq_ops->show != tcp4_seq_show) {
            log("[ALERT] tcp4_seq_show is hooked!\n");
            found++;
        }
    } else {
        log("[WARN] Could not resolve tcp4_seq_show or tcp_seq_ops\n");
    }

    return found;
}

static int detect_hidden_sockets(void)
{
    struct sock *sk;
    struct inet_sock *inet;
    int count = 0;

    read_lock(&tcp_hashinfo.lock);
    for (int i = 0; i < tcp_hashinfo.ehash_mask + 1; i++) {
        struct inet_ehash_bucket *head = &tcp_hashinfo.ehash[i];
        struct hlist_nulls_node *node;

        sk_nulls_for_each(sk, node, &head->chain) {
            if (sk && sk->sk_state == TCP_ESTABLISHED) {
                inet = inet_sk(sk);
                if (!inet->inet_num || !inet->inet_dport) {
                    log("[ALERT] Hidden socket: Local Port %u\n", ntohs(inet->inet_sport));
                    count++;
                }
            }
        }
    }
    read_unlock(&tcp_hashinfo.lock);
    return count;
}

// /proc interface
#define PROC_NAME "minidetect_status"
static struct proc_dir_entry *proc_file;

static ssize_t proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    if (*ppos > 0 || count < loglen)
        return 0;

    if (copy_to_user(buf, logbuf, loglen))
        return -EFAULT;

    *ppos = loglen;
    return loglen;
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read,
};

static int __init minidetect_rootkit_init(void)
{
    loglen = 0;

    log("Initializing Rootkit Detection Module\n");
    detect_hidden_modules();
    detect_hidden_tasks();
    detect_syscall_hooks();
    detect_tcp_seq_hook();
    detect_hidden_sockets();

    proc_file = proc_create(PROC_NAME, 0444, NULL, &proc_fops);
    if (!proc_file)
        log("[ERROR] Failed to create /proc/%s\n", PROC_NAME);
    else
        log("Created /proc/%s for status\n", PROC_NAME);

    return 0;
}

static void __exit minidetect_rootkit_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    log("Exiting Rootkit Detection Module\n");
}

module_init(minidetect_rootkit_init);
module_exit(minidetect_rootkit_exit);
