#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched/task.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/memremap.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yunjie Deng");
MODULE_DESCRIPTION("SMC CALL TEST");

#define DEVICE_NAME "LKM_device"
#define CLASS_NAME "LKM_class"
#define IOCTL_EBPF _IO('a', 1)
#define IOCTL_PTRACE _IO('a', 2)
#define IOCTL_LD_PRELOAD _IO('a', 3)

// static struct kprobe kp_ioctl;

static int major_number;
static struct class*  LKM_class  = NULL;
static struct device* LKM_device = NULL;
static uint64_t ret = 0;

// #define PAGE_SIZE 4096
#define PAGE_SHITF 12
#define PAGE_MASK ((1UL << PAGE_SHITF) - 1)
#define ENTRY_SHIFT 9
#define ENTRY_MASK ((1UL << ENTRY_SHIFT) - 1)

#define bits(v, l, h) (((v) >> (l)) & ((1U << ((h) - (l) + 1)) - 1))

typedef struct pair {
    uint64_t p1, p2;
} PAIR;

PAIR val;

static void dump_memory(uint64_t* addr) {
    int i;
    for (i = 0 ; i < 0x8000 / sizeof(uint64_t) ; i += 4) {
        printk("<0x%llx>: %016llx %016llx %016llx %016llx\n",
            (uint64_t)(addr+i), addr[i], addr[i+1], addr[i+2], addr[i+3]);
    }
}

// int kp_ioctl_pre(struct kprobe *p, struct pt_regs *regs) {
//     printk(KERN_INFO "Intercepted ioctl %d: fd=%ld, cmd=%ld, arg=%ld\n",
//            current->pid, regs->regs[0], regs->regs[1], regs->regs[2]);
//     return 0;
// }

static uintptr_t get_ttbr0_el1_by_pid(pid_t target_pid)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long ttbr0_el1;

    if (target_pid != -1) {
        // Find the task_struct for the given PID
        pid_struct = find_get_pid(target_pid);
        if (!pid_struct) {
            pr_err("Failed to get pid_struct for PID %d\n", target_pid);
            return -ESRCH;
        }

        // Get task_struct from pid_struct
        task = pid_task(pid_struct, PIDTYPE_PID);
        if (!task) {
            pr_err("Failed to get task_struct for PID %d\n", target_pid);
            return -ESRCH;
        }
    }
    else {
        task = current;
    }

    // Access the mm_struct directly
    mm = task->mm;
    if (!mm) {
        pr_err("Failed to get mm_struct for PID %d\n", target_pid);
        return -EINVAL;
    }

    // Get the physical address of the PGD base, equivalent to TTBR0_EL1
    ttbr0_el1 = virt_to_phys(mm->pgd);
    pr_info("TTBR0_EL1 (PGD base) for PID %d: 0x%lx\n", target_pid, ttbr0_el1);

    return ttbr0_el1;
}

static uintptr_t read_ttbr0_el1(void) {
    uintptr_t ttbr0, ttbr1;
    asm volatile("mrs %0, TTBR0_EL1" : "=r" (ttbr0));
    asm volatile("mrs %0, TTBR1_EL1" : "=r" (ttbr1));
    printk("TTBR0_EL1: 0x%lx TTBR1_EL1: 0x%lx", ttbr0, ttbr1);
    return ttbr0;
}

static uintptr_t read_tcr_el1(void) {
    uintptr_t tcr;
    asm volatile("mrs %0, TCR_EL1" : "=r" (tcr));
    printk("TCR_EL1: 0x%lx TG0: 0x%lx T0SZ: 0x%lx", 
        tcr, bits(tcr, 14, 15), bits(tcr, 0, 5));
    return tcr;
}

uintptr_t v2p(uintptr_t va) {
    volatile unsigned long par;
    unsigned long ret;

    asm volatile (
        "at s1e0r, %0\n"
        "isb\n"
        "mrs %0, par_el1\n"
        "isb\n"
        : "=r" (par)
        : "r" (va)
        : "memory"
    );

    // printk("[WTF] 0x%lx 0x%lx", va, par);

    if (par & 0x1) {
        ret = -1;
    }
    else {
        ret = (par & (~PAGE_MASK) | (va & PAGE_MASK));
        ret &= 0x0000ffffffffffff;
    }

    // printk("[WTF] 0x%lx 0x%lx", va, ret);

    return ret;
}

#define get_bit_range_value(number, start, end) (( (number) >> (end) ) & ( (1L << ( (start) - (end) + 1) ) - 1) )

uint64_t read_ttbr_core(uint64_t ttbr0, uint64_t IA) {
	uint64_t offset, phys_DA, table_base, OA;
	table_base = ttbr0;
	offset = get_bit_range_value(IA, 47, 39) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = get_bit_range_value(IA, 38, 30) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = get_bit_range_value(IA, 29, 21) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = get_bit_range_value(IA, 20, 12) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = IA & 0xfff;
	OA = (table_base & 0xfffffffff000) | offset;

    printk("OA 0x%lx", OA);
	
	return OA;
}

int unmapva(uintptr_t ttbr0, uintptr_t va) {
    int i;
    uintptr_t level_base;
    uintptr_t tcr;
    uintptr_t phys_addr;
    int levels[] = {39, 30, 21, 12};  // L1, L2, L3 shifts for 4KB granularity

    if (!ttbr0) {
        ttbr0 = read_ttbr0_el1();
    }

    level_base = ttbr0 & ~PAGE_MASK;
    
    for (i = 0; i < 4; i++) {
        uint64_t offset = ((va >> levels[i]) & ENTRY_MASK) << 3;
        printk("[unmapva] Level %d [%d:%d] base: 0x%lx offset: 0x%lx", 
            i, levels[i]+8, levels[i], level_base, offset);
        uint64_t *entry_ptr = (uint64_t *)phys_to_virt(level_base + offset);
        uint64_t entry = *entry_ptr;
        printk("[unmapva] Level %d Entry 0x%lx", i, entry);

        if ((entry & 0x3) == 0x3) { // Table Descriptor
            printk("[unmapva] Descriptor at level %d", i);
            level_base = entry & ~PAGE_MASK;
            if (i == 3) { // Last level
                *entry_ptr = 0x0; // entry & 
                flush_tlb_all();
                asm volatile (
                    "dc civac, %0\n"   // Clean and invalidate the cache line
                    "tlbi vae1, %1\n"
                    "tlbi vmalle1\n"
                    "dsb ish\n"        // Ensure completion of data cache operation
                    "isb\n"            // Ensure instruction synchronization
                    : : "r" (entry_ptr), "r" ( ((uint64_t)entry_ptr)>>12 ) : "memory"
                );
                printk("[unmapva] Current entry: 0x%lx", *entry_ptr);
                return entry;
            }
        } else if ((entry & 0x3) == 0x1) { // Block Descriptor
            printk("[unmapva] [ERROR] Unsupport to unmap block");
            // phys_addr = (entry & ~((1UL << levels[i + 1]) - 1)) | (va & ((1UL << levels[i + 1]) - 1));
            return 0;
        } else {
            return 0;  // entry & 0x1 == 0
        }
    }
    printk("[unmapva] [ERROR] Unable to unmapva 0x%lx", va);
    return 0;
}

uintptr_t translate_va_to_pa(uintptr_t ttbr0, uintptr_t va) {
    int i;
    uintptr_t level_base;
    uintptr_t tcr;
    uintptr_t _ttbr0;
    uintptr_t phys_addr;
    int levels[] = {39, 30, 21, 12};  // L1, L2, L3 shifts for 4KB granularity

    if (!ttbr0) {
        ttbr0 = read_ttbr0_el1();
        _ttbr0 = get_ttbr0_el1_by_pid(current->pid);
        printk("[translate_va_to_pa] ttbr0: 0x%llx 0x%llx", ttbr0, _ttbr0);
    }
    tcr = read_tcr_el1();

    level_base = ttbr0 & ~PAGE_MASK;
    
    for (i = 0; i < 4; i++) {
        uint64_t offset = ((va >> levels[i]) & ENTRY_MASK) << 3;
        printk("[translate_va_to_pa] Level %d [%d:%d] base: 0x%lx offset: 0x%lx", 
            i, levels[i]+8, levels[i], level_base, offset);
        uint64_t *entry_ptr = (uint64_t *)phys_to_virt(level_base + offset);
        uint64_t entry = *entry_ptr;
        printk("[translate_va_to_pa] Level %d Entry 0x%lx", i, entry);

        if ((entry & 0x3) == 0x3) { // Table Descriptor
            printk("[translate_va_to_pa] Descriptor at level %d", i);
            level_base = entry & ~PAGE_MASK;
        } else if ((entry & 0x3) == 0x1) { // Block Descriptor
            printk("[translate_va_to_pa] Block at level %d", i);
            phys_addr = (entry & ~((1UL << levels[i + 1]) - 1)) | (va & ((1UL << levels[i + 1]) - 1));
            return phys_addr;
        } else {
            return -1;  // entry & 0x1 == 0
        }
    }

    phys_addr = level_base & 0x0000ffffffffffff | (va & PAGE_MASK);
    return phys_addr;
}

extern int target_pid;

struct kbase_ioctl_cs_queue_kick {
  __u64 buffer_gpu_addr;
};

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    uintptr_t ttbr0, phys_addr, buffer_gpu_addr;
    struct kbase_ioctl_cs_queue_kick* ptr;
    unsigned long sctlr;
    void *mem;

    // Read SCTLR_EL1
    asm volatile("mrs %0, sctlr_el1" : "=r" (sctlr));
    // Clear the PAN bit
    sctlr &= ~(1 << 22); // Assuming PAN is bit 22 (check your architecture)
    // Write back to SCTLR_EL1
    asm volatile("msr sctlr_el1, %0" : : "r" (sctlr) : "memory");

    printk("[IOCTL] cmd: %x", cmd);
    switch (cmd) {
        case IOCTL_EBPF:
        {
            ret = copy_from_user(&val, (void*)arg, sizeof(val));
            printk("[IOCTL_EBPF] pid: %lld buffer_gpu_addr: 0x%llx", val.p1, val.p2);
            ttbr0 = get_ttbr0_el1_by_pid(val.p1);
            phys_addr = translate_va_to_pa(ttbr0, val.p2);
            printk("[IOCTL_EBPF] phys_addr: 0x%lx", phys_addr);
            dump_memory(phys_to_virt(phys_addr));
            dump_memory(phys_to_virt(0x4124000));
            break;
        }
        case IOCTL_PTRACE:
        {
            ret = copy_from_user(&val, (void*)arg, sizeof(val));
            printk("[IOCTL_PTRACE] tracer pid = %d tracee pid = %lld", 
                current->pid, val.p1);
            ttbr0 = get_ttbr0_el1_by_pid(val.p1);
            // val.p2 = user's virtual address
            // user virt -> phys -> kernel virt
            printk("[IOCTL_PTRACE] user arg: 0x%llx ttbr0: 0x%llx", val.p2, ttbr0);
            phys_addr = translate_va_to_pa(ttbr0, val.p2);
            printk("[IOCTL_PTRACE] phys: 0x%lx", phys_addr); 
            ptr = phys_to_virt(phys_addr);
            printk("[IOCTL_PTRACE] kernel virt: 0x%llx val: 0x%llx", 
                (uint64_t)ptr, ptr->buffer_gpu_addr); 
            // user virt 
            // buffer_gpu_addr = ptr->buffer_gpu_addr;
            buffer_gpu_addr = 0x7fdfffe9d000;
            printk("[IOCTL_PTRACE] buffer_gpu_addr: 0x%lx", buffer_gpu_addr);
            phys_addr = translate_va_to_pa(ttbr0, buffer_gpu_addr);
            printk("[IOCTL_PTRACE] buffer_gpu_addr phys: 0x%lx", phys_addr);
            dump_memory(phys_to_virt(phys_addr));
            break;
        }
        case IOCTL_LD_PRELOAD:
        {
            // target_pid = current->pid;
            printk("[IOCTL_LD_PRELOAD] decode %d %d", 
                aarch64_insn_is_ldr_reg(0xf9400003),
                aarch64_insn_is_ldr_reg(0x030040f9));
            // *(uint64_t *)(0xbeef) = 0;
            // ret = copy_from_user(&val, (void*)arg, sizeof(val));
            // printk("[IOCTL_LD_PRELOAD] p1: 0x%llx p2: 0x%llx", val.p1, val.p2);
            // if (val.p2) {
            //     phys_addr = translate_va_to_pa(0, val.p2);
            //     printk("0x%lx", phys_addr);
            //     ttbr0 = read_ttbr0_el1();
            //     phys_addr = read_ttbr_core(ttbr0, val.p2);
            //     printk("Unmap %p 0x%lx", val.p2, 0x8000);
            //     unmapva(ttbr0, val.p2);
            // }
            // printk("AT instruction result: 0x%lx", v2p(0x7fdfffe9d000));
            break;
        }
        default:
            break;
    }
    printk("=====================================================");
    return 0;
}

static struct file_operations fops = {
    .unlocked_ioctl = device_ioctl,
};

static int __init LKM_init(void) {
    int ret;

    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk("Failed to register a major number\n");
        return major_number;
    }
    LKM_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(LKM_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk("Failed to create device class\n");
        return PTR_ERR(LKM_class);
    }
    LKM_device = device_create(LKM_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(LKM_device)) {
        class_destroy(LKM_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk("Failed to create the device\n");
        return PTR_ERR(LKM_device);
    }
    printk("LKM device created successfully\n");

    // kp_ioctl.pre_handler = kp_ioctl_pre;
    // kp_ioctl.symbol_name = "__arm64_compat_sys_ioctl";
    // ret = register_kprobe(&kp_ioctl);
    if (ret < 0) {
        printk(KERN_ERR "[%d] Failed to register kprobe\n", ret);
    }
    
    asm volatile(
        "ldr w0, =0xc8000001\n"
        "smc #0\n"
        "mov %[_ret_], x0"
        : [_ret_]"=r"(ret) ::
        "w0"
    );
    printk(KERN_INFO "Init! SMC CALL: %d\n", ret);
    return 0;
}

static void __exit LKM_exit(void) {
    device_destroy(LKM_class, MKDEV(major_number, 0));
    class_unregister(LKM_class);
    class_destroy(LKM_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    // unregister_kprobe(&kp_ioctl);
    pr_info("LKM device removed successfully\n");
    printk(KERN_INFO "Goodbye!\n");
}
module_init(LKM_init);
module_exit(LKM_exit);
