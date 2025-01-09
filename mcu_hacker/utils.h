// Functions about address translation

#define MOLE_PAGE_OFFSET ((1UL << PAGE_SHIFT) - 1)
#define ENTRY_SHIFT 9
#define ENTRY_MASK ((1UL << ENTRY_SHIFT) - 1)

// #define dbg_printk(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define dbg_printk(fmt, ...)

#define bits(v, l, h) (((v) >> (l)) & ((1U << ((h) - (l) + 1)) - 1))

static void dump_memory(uint64_t* addr, int size) {
    int i;
    printk("========\n");
    for (i = 0 ; i < size / sizeof(uint64_t) ; i += 4) {
        printk("<0x%lx>: %016lx %016lx %016lx %016lx\n",
        addr+i, addr[i], addr[i+1], addr[i+2], addr[i+3]);
    }
    printk("========\n");
}

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
    dbg_printk("TTBR0_EL1: 0x%lx TTBR1_EL1: 0x%lx", ttbr0, ttbr1);
    return ttbr0;
}

static uintptr_t read_tcr_el1(void) {
    uintptr_t tcr;
    asm volatile("mrs %0, TCR_EL1" : "=r" (tcr));
    dbg_printk("TCR_EL1: 0x%lx TG0: 0x%lx T0SZ: 0x%lx", 
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

    if (par & 0x1) {
        ret = -1;
    }
    else {
        ret = (par & (~MOLE_PAGE_OFFSET) | (va & MOLE_PAGE_OFFSET));
        ret &= 0x0000ffffffffffff;
    }

    return ret;
}

#define get_bit_range_value(number, start, end) (( (number) >> (end) ) & ( (1L << ( (start) - (end) + 1) ) - 1) )

uint64_t read_ttbr_core(uint64_t ttbr0, uint64_t IA) {
	uint64_t offset, phys_DA, table_base, OA;
	table_base = ttbr0;
	offset = get_bit_range_value(IA, 47, 39) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    dbg_printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = get_bit_range_value(IA, 38, 30) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    dbg_printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = get_bit_range_value(IA, 29, 21) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    dbg_printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = get_bit_range_value(IA, 20, 12) << 3;
	phys_DA = (table_base & 0xfffffffff000) | offset;

    dbg_printk("phys_DA 0x%lx offset 0x%lx next_base: 0x%lx", 
        phys_DA, offset, *(uint64_t*)phys_to_virt(phys_DA));
	
	table_base = *(uint64_t*)phys_to_virt(phys_DA);
	if ((table_base & 0x1) == 0) return 0;
	offset = IA & 0xfff;
	OA = (table_base & 0xfffffffff000) | offset;

    dbg_printk("OA 0x%lx", OA);
	
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

    level_base = ttbr0 & ~MOLE_PAGE_OFFSET;
    
    for (i = 0; i < 4; i++) {
        uint64_t offset = ((va >> levels[i]) & ENTRY_MASK) << 3;
        dbg_printk("[unmapva] Level %d [%d:%d] base: 0x%lx offset: 0x%lx", 
            i, levels[i]+8, levels[i], level_base, offset);
        uint64_t *entry_ptr = (uint64_t *)phys_to_virt(level_base + offset);
        uint64_t entry = *entry_ptr;
        dbg_printk("[unmapva] Level %d Entry 0x%lx", i, entry);

        if ((entry & 0x3) == 0x3) { // Table Descriptor
            dbg_printk("[unmapva] Descriptor at level %d", i);
            level_base = entry & ~MOLE_PAGE_OFFSET;
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
                dbg_printk("[unmapva] Current entry: 0x%lx", *entry_ptr);
                return entry;
            }
        } else if ((entry & 0x3) == 0x1) { // Block Descriptor
            dbg_printk("[unmapva] [ERROR] Unsupport to unmap block");
            // phys_addr = (entry & ~((1UL << levels[i + 1]) - 1)) | (va & ((1UL << levels[i + 1]) - 1));
            return 0;
        } else {
            return 0;  // entry & 0x1 == 0
        }
    }
    dbg_printk("[unmapva] [ERROR] Unable to unmapva 0x%lx", va);
    return 0;
}

static uintptr_t translate_va_to_pa(uintptr_t ttbr0, uintptr_t va) {
    int i;
    uintptr_t level_base;
    uintptr_t tcr;
    uintptr_t _ttbr0;
    uintptr_t phys_addr;
    int levels[] = {39, 30, 21, 12};  // L1, L2, L3 shifts for 4KB granularity

    if (!ttbr0) {
        ttbr0 = read_ttbr0_el1();
        _ttbr0 = get_ttbr0_el1_by_pid(current->pid);
        dbg_printk("[translate_va_to_pa] ttbr0: 0x%llx 0x%llx", ttbr0, _ttbr0);
    }
    tcr = read_tcr_el1();

    level_base = ttbr0 & ~MOLE_PAGE_OFFSET;
    
    for (i = 0; i < 4; i++) {
        uint64_t offset = ((va >> levels[i]) & ENTRY_MASK) << 3;
        dbg_printk("[translate_va_to_pa] Level %d [%d:%d] base: 0x%lx offset: 0x%lx", 
            i, levels[i]+8, levels[i], level_base, offset);
        uint64_t *entry_ptr = (uint64_t *)phys_to_virt(level_base + offset);
        uint64_t entry = *entry_ptr;
        dbg_printk("[translate_va_to_pa] Level %d Entry 0x%lx", i, entry);

        if ((entry & 0x3) == 0x3) { // Table Descriptor
            dbg_printk("[translate_va_to_pa] Descriptor at level %d", i);
            level_base = entry & ~MOLE_PAGE_OFFSET;
        } else if ((entry & 0x3) == 0x1) { // Block Descriptor
            dbg_printk("[translate_va_to_pa] Block at level %d", i);
            phys_addr = (entry & ~((1UL << levels[i + 1]) - 1)) | (va & ((1UL << levels[i + 1]) - 1));
            return phys_addr;
        } else {
            return -1;  // entry & 0x1 == 0
        }
    }

    phys_addr = level_base & 0x0000ffffffffffff | (va & MOLE_PAGE_OFFSET);
    return phys_addr;
}
