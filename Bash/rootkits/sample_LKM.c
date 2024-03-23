#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <asm/paravirt.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

unsigned long *__sys_call_table;

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
#endif
#endif

static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;
    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void unprotect_memory(void) {
    write_cr0_forced(read_cr0() & (~ 0x10000));
    printk(KERN_NOTICE "systemctl:level1\n");
}

static inline void protect_memory(void) {
    write_cr0_forced(read_cr0() | (0x10000)) ;
    printk(KERN_NOTICE "systemctl:level0\n");
}

static unsigned long *get_syscall_table(void) {

#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    int retrn;
    retrn = register_kprobe(&kp);
    if (retrn < 0) {
        printk(KERN_INFO "systemctl:failed - returned %d\n", retrn);
        return NULL;
    }
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    __sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    return __sys_call_table; 
#else
    return NULL;
#endif

}

static int __init app_init(void) {
    printk(KERN_INFO "systemctl:init\n");

    /* do things here */

    __sys_call_table = get_syscall_table();
    if (__sys_call_table != NULL) {
        printk(KERN_INFO "systemctl:syscall found at %p\n", __sys_call_table);
    } else {
        printk(KERN_ERR "systemctl:call table not found\n");
    }

    printk(KERN_INFO "systemctl:ready\n");

    return 0;
}

static void __exit app_exit(void) {
    printk(KERN_INFO "systemctl:exit\n");
}

module_init(app_init);
module_exit(app_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Me");
MODULE_DESCRIPTION("This is just an LKM");
MODULE_VERSION("0.0.0.1");
MODULE_INFO(intree, "Y");
