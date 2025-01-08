#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h> // included for __init and __exit macros
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
#include <linux/delay.h>
#include <linux/time.h>
#include <mali_kbase.h>

#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yunjie Deng");
MODULE_DESCRIPTION("SMC CALL TEST");

#define DEVICE_NAME "MCU_HACKER_device"
#define CLASS_NAME "MCU_HACKER_class"

#define IOCTL_MCU_READ _IO('s', 0)
#define IOCTL_MCU_WRITE _IO('s', 1)
#define IOCTL_CHECK _IO('s', 2)

static int major_number;
static struct class *MCU_HACKER_class = NULL;
static struct device *MCU_HACKER_device = NULL;
static uint64_t ret = 0;

// #define PAGE_SIZE 4096
// #define PAGE_SHIFT 12

typedef struct GPU_BUFFER {
	uint64_t base;
	uint64_t size;
	uint64_t input;
} GPU_BUFFER;

typedef struct LKM_BUFS {
	int num_bufs;
	GPU_BUFFER bufs[];
} LKM_BUFS;

int kbase_mmu_insert_pages(struct kbase_device *kbdev,
			   struct kbase_mmu_table *mmut, u64 vpfn,
			   struct tagged_addr *phys, size_t nr,
			   unsigned long flags, int as_nr, int const group_id,
			   enum kbase_caller_mmu_sync_info mmu_sync_info);

struct kbase_device *kbase_find_device(int minor);

void *kbase_mmu_dump(struct kbase_context *kctx, int nr_pages);

int mmu_get_pgd_at_level(struct kbase_device *kbdev,
			 struct kbase_mmu_table *mmut, u64 vpfn, int level,
			 phys_addr_t *out_pgd, bool *newly_created_pgd,
			 u64 *dirty_pgds);

int mmu_get_bottom_pgd(struct kbase_device *kbdev, struct kbase_mmu_table *mmut,
		       u64 vpfn, phys_addr_t *out_pgd, bool *newly_created_pgd,
		       u64 *dirty_pgds);

static u32 csf_doorbell_offset(int doorbell_nr)
{
	WARN_ON(doorbell_nr < 0);
	WARN_ON(doorbell_nr >= CSF_NUM_DOORBELL);

	return CSF_HW_DOORBELL_PAGE_OFFSET +
	       (doorbell_nr * CSF_HW_DOORBELL_PAGE_SIZE);
}

// phys_addr_t mcu_pgd, data_buffer;

static struct tagged_addr phys[1 << 15]; // 128 MB
static size_t page_num = 0;
static struct kbase_device *kbdev;

static void read_ocl_buffer(LKM_BUFS **p_lkm_bufs, unsigned long arg)
{
	// Copy the buffer info from user space (LD_PRELOAD)
	int i;
	int num_bufs = 0;
	copy_from_user(&num_bufs, (void *)arg, sizeof(int));
	*p_lkm_bufs = kmalloc(sizeof(LKM_BUFS) + num_bufs * sizeof(GPU_BUFFER),
			      GFP_KERNEL);
	LKM_BUFS *lkm_bufs = *p_lkm_bufs;
	lkm_bufs->num_bufs = num_bufs;

	if (num_bufs == 0)
		return;

	dbg_printk("num_bufs %d addr: 0x%lx func: 0x%lx\n", num_bufs, lkm_bufs,
		   kbase_mmu_insert_pages);
	copy_from_user(lkm_bufs->bufs, (void *)arg + sizeof(LKM_BUFS),
		       num_bufs * sizeof(GPU_BUFFER));

	// Count the number of page we need
	size_t num_pages;
	for (i = 0; i < num_bufs; ++i) {
		dbg_printk(
			"[%d] virt_base: 0x%lx phys_base: 0x%lx size: 0x%lx input: %d\n",
			i, lkm_bufs->bufs[i].base, v2p(lkm_bufs->bufs[i].base),
			lkm_bufs->bufs[i].size, lkm_bufs->bufs[i].input);
		num_pages += (lkm_bufs->bufs[i].size >> PAGE_SHIFT);
	}
}

// typedef void (*program_cs_t)(struct kbase_device *kbdev,
// 		struct kbase_queue *queue, bool ring_csg_doorbell);

static int program_cs_pre(struct kprobe *p, struct pt_regs *regs)
{
	printk(KERN_INFO "Pre-handler: function %s\n", p->symbol_name);
	return 0; // Return 0 to allow normal execution
}

static int xxx_pre(struct kprobe *p, struct pt_regs *regs)
{
	printk(KERN_INFO "[%d] Pre-handler: function %s\n", current->pid,
	       p->symbol_name);
	dump_stack();
	return 0; // Return 0 to allow normal execution
}

struct kprobe kp = { .symbol_name = "program_cs",
		     .pre_handler = program_cs_pre };
struct kprobe kp2 = { .symbol_name = "kbase_csf_ring_doorbell",
		      .pre_handler = xxx_pre };
// program_cs_t program_cs_t_addr = NULL;

// void mcu_hacker_lookup_name(struct kbase_device *kbdev,
// 		struct kbase_queue *queue, bool ring_csg_doorbell) {
//     if (!program_cs_t_addr) {
//         register_kprobe(&kp);
//         program_cs_t_addr = (program_cs_t)kp.addr;
//         unregister_kprobe(&kp);
//     }
//     if (program_cs_t_addr == NULL) {
//         printk(KERN_ERR "moye: failed to find kallsyms_lookup_name\n");
//         return 0;
//     }
//     return program_cs_t_addr(name);
// }

static void map_to_mcu(LKM_BUFS *lkm_bufs, u64 mcu_va_base)
{
	// Reference:
	// .src/linux/drivers/gpu/arm/bifrost/csf/mali_kbase_csf_firmware.c:
	//     kbase_csf_firmware_mcu_shared_mapping_init()
	// .src/linux/drivers/gpu/arm/bifrost/csf/mali_kbase_csf.c:
	//     gpu_mmap_user_io_pages()

	page_num = 0;
	int i;
	int num_bufs = lkm_bufs->num_bufs;
	if (num_bufs == 0)
		return;
	size_t offset;
	size_t insert_num = 0;
	for (i = 0; i < num_bufs; ++i) {
		dbg_printk("[Buffer] base: 0x%lx size: 0x%lx input: %ld",
			   lkm_bufs->bufs[i].base, lkm_bufs->bufs[i].size,
			   lkm_bufs->bufs[i].input);
		if (!lkm_bufs->bufs[i].input) {
			dbg_printk(
				"[WARNING] Buffer 0x%lx is not input buffer!!!",
				lkm_bufs->bufs[i].base);
			// continue;
		}
		size_t upper_bound;
		upper_bound = lkm_bufs->bufs[i].size;
		// If the buffer does not start from the beginning of page, add one more page mapping.
		if (lkm_bufs->bufs[i].base & 0xfff)
			upper_bound += 0x1000;
		// upper_bound = 0x1000;
		offset = 0;
		while (offset < upper_bound) {
			size_t virt_addr = lkm_bufs->bufs[i].base + offset;
			size_t phys_addr = v2p(virt_addr);
			if (phys_addr == -1) {
				printk("[ERROR] No mapping...");
			}
			struct page *p = pfn_to_page(PHYS_PFN(phys_addr));
			phys[page_num++] = as_tagged(page_to_phys(p));
			// dbg_printk("virt: 0x%lx phys: 0x%lx page: 0x%lx", virt_addr, phys_addr, phys[page_num-1]);
			// dump_memory(phys_to_virt(phys_addr), 0x100);
			offset += 0x1000;
		}
	}

	// Convert virt to phys to fit mali's API
	// Note that v2p is CPU's address translation,
	//   we assume that the GPU's and the CPU's virtual address are same.
	// Such case is general in mali GPU
	// struct tagged_addr *phys = kmalloc_array(num_pages, sizeof(*phys), GFP_KERNEL);

	dbg_printk("page_num: %d", page_num);

	// Call kbase_mmu_insert_pages
	phys_addr_t pgd = 0;
	bool newly_created_pgd = false;
	u64 dirty_pgds = 0;
	// u64 mcu_va_base = 0x40a0000; // already mapped
	// u64 mcu_va_base = 0x06000000;

	// mmu_get_bottom_pgd(kbdev, &kbdev->csf.mcu_mmu, mcu_va_base, &pgd, &newly_created_pgd, &dirty_pgds);
	// dbg_printk("pgd: 0x%lx newly_created_pgd: %d dirty_pgds: 0x%lx", pgd, newly_created_pgd, dirty_pgds);

	const enum kbase_caller_mmu_sync_info mmu_sync_info = CALLER_MMU_SYNC;
	unsigned long mem_flags = KBASE_REG_GPU_RD;
	// KBASE_REG_GPU_CACHED | KBASE_REG_SHARE_BOTH | KBASE_REG_MEMATTR_INDEX(AS_MEMATTR_INDEX_SHARED);
	if (kbdev->system_coherency == COHERENCY_NONE) {
		dbg_printk("[YES] COHERENCY_NONE");
		mem_flags |= //KBASE_REG_GPU_CACHED | KBASE_REG_CPU_CACHED |
			KBASE_REG_SHARE_IN;
	} else {
		dbg_printk("[NO] COHERENCY_NONE");
		mem_flags |= KBASE_REG_SHARE_BOTH |
			     KBASE_REG_MEMATTR_INDEX(AS_MEMATTR_INDEX_SHARED);
	}
	mem_flags |= KBASE_REG_GPU_WR;
	ret = kbase_mmu_insert_pages(kbdev, &kbdev->csf.mcu_mmu,
				     mcu_va_base >> PAGE_SHIFT, phys, page_num,
				     mem_flags, MCU_AS_NR,
				     KBASE_MEM_GROUP_CSF_IO, mmu_sync_info);
	dbg_printk(
		"kbase_mmu_insert_pages: Mapping phys to mcu_va with 0x%lx return value %d",
		mcu_va_base, ret);

	dbg_printk("mmu_base: 0x%lx 0x%lx", kbdev->csf.mcu_mmu.pgd,
		   kbdev->csf.mcu_mmu.kctx);

	// phys_addr_t l0_pgd, l1_pgd, l2_pgd, l3_pgd;

	// mmu_get_pgd_at_level(kbdev, &kbdev->csf.mcu_mmu, mcu_va_base, 0, &l0_pgd, &newly_created_pgd, &dirty_pgds);
	// dbg_printk("l0_pgd: 0x%lx newly_created_pgd: %d dirty_pgds: 0x%lx", l0_pgd, newly_created_pgd, dirty_pgds);

	// dump_memory(phys_to_virt(l0_pgd), 0x1000);

	// mmu_get_pgd_at_level(kbdev, &kbdev->csf.mcu_mmu, mcu_va_base, 1, &l1_pgd, &newly_created_pgd, &dirty_pgds);
	// dbg_printk("l1_pgd: 0x%lx newly_created_pgd: %d dirty_pgds: 0x%lx", l1_pgd, newly_created_pgd, dirty_pgds);

	// dump_memory(phys_to_virt(l1_pgd), 0x1000);

	// mmu_get_pgd_at_level(kbdev, &kbdev->csf.mcu_mmu, mcu_va_base, 2, &l2_pgd, &newly_created_pgd, &dirty_pgds);
	// dbg_printk("l2_pgd: 0x%lx newly_created_pgd: %d dirty_pgds: 0x%lx", l2_pgd, newly_created_pgd, dirty_pgds);

	// dump_memory(phys_to_virt(l2_pgd), 0x1000);

	// mmu_get_pgd_at_level(kbdev, &kbdev->csf.mcu_mmu, mcu_va_base, 3, &l3_pgd, &newly_created_pgd, &dirty_pgds);
	// dbg_printk("l3_pgd: 0x%lx newly_created_pgd: %d dirty_pgds: 0x%lx", l3_pgd, newly_created_pgd, dirty_pgds);

	// dump_memory(phys_to_virt(l3_pgd), 0x1000);

	// mmu_get_bottom_pgd(kbdev, &kbdev->csf.mcu_mmu, mcu_va_base, &pgd, &newly_created_pgd, &dirty_pgds);
	// dbg_printk("pgd: 0x%lx newly_created_pgd: %d dirty_pgds: 0x%lx", pgd, newly_created_pgd, dirty_pgds);

	// mcu_pgd = pgd;
	// data_buffer = ((uint64_t*)phys)[0];
}

void fw_dma_sync(struct kbase_device *kbdev, u32 offset, bool read)
{
	struct kbase_csf_firmware_interface *interface =
		kbdev->csf.shared_interface;
	u32 page_num = offset >> PAGE_SHIFT;
	u32 offset_in_page = offset & ~PAGE_MASK;
	struct page *target_page = as_page(interface->phys[page_num]);

	if (read) {
		kbase_sync_single_for_device(
			kbdev, kbase_dma_addr(target_page) + offset_in_page,
			sizeof(u32), DMA_BIDIRECTIONAL);
	} else {
		kbase_sync_single_for_cpu(
			kbdev, kbase_dma_addr(target_page) + offset_in_page,
			sizeof(u32), DMA_BIDIRECTIONAL);
	}
}

static void mcu_read(u64 mcu_va_base, u64 size)
{
	int i;

	struct kbase_csf_firmware_interface *interface =
		kbdev->csf.shared_interface;
	void *mcu_mapping = interface->kernel_map;

	u64 t = 0;
	// Write start and end
	u32 *begin, *end;
	begin = mcu_mapping + 0x94000;
	end = mcu_mapping + 0x94004;

	fw_dma_sync(kbdev, 0x94000, false);
	fw_dma_sync(kbdev, 0x94004, false);
	dbg_printk("[BEFORE] begin: 0x%lx end: 0x%lx\n", *begin, *end);
	*begin = mcu_va_base;
	*end = mcu_va_base + size;
	dbg_printk("[AFTER ] begin: 0x%lx end: 0x%lx\n", *begin, *end);

	// /* Add doorbell kick code at here */
	kbase_reg_write(kbdev, csf_doorbell_offset(23), 1);
	t = ktime_get_ns();

	dbg_printk("[kbase_reg_write] Done...");

	while (1) {
		dbg_printk("[CHECK] begin: 0x%lx end: 0x%lx", *begin, *end);
		fw_dma_sync(kbdev, 0x94000, true);
		fw_dma_sync(kbdev, 0x94004, true);
		if (READ_ONCE(*begin) == 0) { // Finished
			dbg_printk("[WAIT] %lld",
				   (ktime_get_ns() - t) / 1000 / 1000);
			u32 magic_1, magic_2;
			magic_1 = *(u32 *)(mcu_mapping + 0x94008);
			magic_2 = *(u32 *)(mcu_mapping + 0x9400c);
			dbg_printk("magic_value: 0x%x 0x%x\n", magic_1,
				   magic_2);

			/*
			dbg_printk("Page compare...");
			for (i = 0; i < page_num; ++i) {
				void *mcu_mem = mcu_mapping + 0x95000;
				printk("Page %d compare result: [%d]", i,
					   memcmp(mcu_mem + 0x1000 * i,
						  phys_to_virt(
							  ((size_t *)phys)[i]),
						  4096));
				//dump_memory(mcu_mapping + 0x95000, 0x100);
			}*/
			break;
		}
	}
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int i;
	// Find mali device kbdev
	struct kbase_csf_firmware_interface *interface =
		kbdev->csf.shared_interface;
	void *mcu_mapping = interface->kernel_map;

	dbg_printk("[IOCTL] cmd: %x", cmd);
	switch (cmd) {
	case IOCTL_MCU_READ: {
		u64 mcu_va_base = 0x04200000;

		LKM_BUFS *lkm_bufs;
		read_ocl_buffer(&lkm_bufs, arg);
		if (lkm_bufs->num_bufs == 0)
			break;
		// map_to_mcu(lkm_bufs, mcu_va_base);

		size_t chunk_sz = 0x50000;
		LKM_BUFS *chunk_buf = kmalloc(
			sizeof(LKM_BUFS) + 1 * sizeof(GPU_BUFFER), GFP_KERNEL);
		chunk_buf->num_bufs = 1;
		u64 t_map = 0, t_copy = 0, t_temp = 0;

		for (i = 0; i < lkm_bufs->num_bufs; ++i) {
			size_t remaining = lkm_bufs->bufs[i].size;
			size_t current_base = lkm_bufs->bufs[i].base;
			while (remaining >= chunk_sz) {
				chunk_buf->bufs[0].base = current_base;
				chunk_buf->bufs[0].size = chunk_sz;
				chunk_buf->bufs[0].input = 1;
				map_to_mcu(chunk_buf, mcu_va_base);

        //t_copy = ktime_get_ns();
				mcu_read(mcu_va_base, chunk_sz);
        //t_copy = ktime_get_ns() - t_copy;
        //printk("[COPY] %lld", t_copy / 1000);


				remaining -= chunk_sz;
				current_base += chunk_sz;
			}
			if (remaining) {
				chunk_buf->bufs[0].base = current_base;
				chunk_buf->bufs[0].size = remaining;
				chunk_buf->bufs[0].input = 1;
				map_to_mcu(chunk_buf, mcu_va_base);
				mcu_read(mcu_va_base, chunk_sz);
			}
		}
		printk("[TIME] Map: %lld Copy: %lld", t_map / 1000 / 1000, t_copy / 1000 / 1000);

		kfree(lkm_bufs);

		// uint64_t ttbr0 = read_ttbr0_el1();
		// dbg_printk("CS_BUFFER 0x%lx 0x%lx 0x%lx\n",
		//     v2p(0x7fdfffe9d000), read_ttbr_core(ttbr0, 0x7fdfffe9d000), translate_va_to_pa(ttbr0, 0x7fdfffe9d000));

		// kbase_pm_set_policy(kbdev, &kbase_pm_coarse_demand_policy_ops);

		break;
	}
	case IOCTL_MCU_WRITE: {
		u32 *src_start = mcu_mapping + 0x94010;
		u32 *src_end = mcu_mapping + 0x94014;
		u32 *dst_start = mcu_mapping + 0x94018;

		u32 *evil_mem = mcu_mapping + 0x94800;
		for (i = 0; i < 0x800 / sizeof(u32); ++i) {
			evil_mem[i] = i;
		}

		u64 mcu_va_base = 0x04100000;

		LKM_BUFS *lkm_bufs;
		read_ocl_buffer(&lkm_bufs, arg);
		map_to_mcu(lkm_bufs, mcu_va_base);

		*src_start = 0x04094800;
		*src_end = 0x04095000;
		*dst_start = mcu_va_base;

		break;
	}
	case IOCTL_CHECK: {
		struct kbase_csf_firmware_interface *interface =
			kbdev->csf.shared_interface;
		void *mcu_mapping = interface->kernel_map;

		u32 *begin, *end;
		begin = mcu_mapping + 0x94000;
		end = mcu_mapping + 0x94004;

		u32 *src_start = mcu_mapping + 0x94010;
		u32 *src_end = mcu_mapping + 0x94014;
		u32 *dst_start = mcu_mapping + 0x94018;

		dbg_printk(
			"[CHECK ] begin: 0x%lx end: 0x%lx src_start: 0x%lx src_end: 0x%lx dst_start: 0x%lx\n",
			*begin, *end, *src_start, *src_end, *dst_start);

		if (*begin == 0 && *end == 0) { // Finished
			u32 magic_1, magic_2;
			magic_1 = *(u32 *)(mcu_mapping + 0x94008);
			magic_2 = *(u32 *)(mcu_mapping + 0x9400c);
			dbg_printk("magic_value: 0x%x 0x%x\n", magic_1,
				   magic_2);

			dbg_printk("Page compare...");
			for (i = 0; i < page_num; ++i) {
				void *mcu_mem = mcu_mapping + 0x95000;
				dbg_printk("Page %d compare result: [%d]", i,
					   memcmp(mcu_mem + 0x1000 * i,
						  phys_to_virt(
							  ((size_t *)phys)[i]),
						  4096));
				// dump_memory(mcu_mapping + 0x95000, 0x100);
			}
		} else {
			return 1;
		}

		// if (mcu_pgd) {
		//     dbg_printk("DUMP MCU_PGD");
		//     dump_memory(phys_to_virt(mcu_pgd), 0x1000);
		//     mcu_pgd = 0;
		// }

		// if (data_buffer) {
		//     dbg_printk("DUMP DATA BUFFER");
		//     dump_memory(phys_to_virt(data_buffer), 0x1000);
		//     data_buffer = 0;
		// }
	}
	default:
		break;
	}
	dbg_printk("=====================================================");
	return 0;
}

static struct file_operations fops = {
	.unlocked_ioctl = device_ioctl,
};

static int __init MCU_HACKER_init(void)
{
	int ret;
  int i;
	if (!kbdev) {
		for (i = 0; i < 256; ++i) {
			kbdev = kbase_find_device(i);
			if (kbdev) {
				dbg_printk("[MINOR %d] kbdev: 0x%lx", i, kbdev);
				break;
			}
		}
	}

	major_number = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_number < 0) {
		dbg_printk("Failed to register a major number\n");
		return major_number;
	}
	MCU_HACKER_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(MCU_HACKER_class)) {
		unregister_chrdev(major_number, DEVICE_NAME);
		dbg_printk("Failed to create device class\n");
		return PTR_ERR(MCU_HACKER_class);
	}
	MCU_HACKER_device =
		device_create(MCU_HACKER_class, NULL, MKDEV(major_number, 0),
			      NULL, DEVICE_NAME);
	if (IS_ERR(MCU_HACKER_device)) {
		class_destroy(MCU_HACKER_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		dbg_printk("Failed to create the device\n");
		return PTR_ERR(MCU_HACKER_device);
	}
	dbg_printk("MCU_HACKER device created successfully\n");

	// printk("Register kprobe: %d %d", register_kprobe(&kp), register_kprobe(&kp2));

	return 0;
}

static void __exit MCU_HACKER_exit(void)
{
	device_destroy(MCU_HACKER_class, MKDEV(major_number, 0));
	class_unregister(MCU_HACKER_class);
	class_destroy(MCU_HACKER_class);
	unregister_chrdev(major_number, DEVICE_NAME);
	pr_info("MCU_HACKER device removed successfully\n");

	// unregister_kprobe(&kp); unregister_kprobe(&kp2);
	printk(KERN_INFO "Kprobe unregistered\n");

	dbg_printk(KERN_INFO "Goodbye!\n");
}
module_init(MCU_HACKER_init);
module_exit(MCU_HACKER_exit);
