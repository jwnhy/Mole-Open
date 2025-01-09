#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <CL/cl.h>
#include <setjmp.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define HOOK_STR "* [MoleAttack] "

// #define TEST
#ifdef TEST
#define dbg_fprintf(out, fmt, ...) fprintf(out, fmt, ##__VA_ARGS__)
static void dump_memory(uint64_t* addr, int size) {
    fprintf(stdout, "========\n");
    for (int i = 0 ; i < size / sizeof(uint64_t) ; i += 4) {
        fprintf(stdout, "<0x%lx>: %016lx %016lx %016lx %016lx\n",
        addr+i, addr[i], addr[i+1], addr[i+2], addr[i+3]);
    }
    fprintf(stdout, "========\n");
}
#else
#define dbg_fprintf(fmt, ...)
#define dump_memory(addr, size) 
#endif

#define IOCTL_MCU_READ _IO('s', 0)
#define IOCTL_MCU_WRITE _IO('s', 1)
#define IOCTL_CHECK _IO('s', 2)

#define DEVICE_PATH "/dev/MCU_HACKER_device"

static pid_t pid;
static size_t total_size;

typedef struct GPU_BUFFER {
	uint64_t base;
	uint64_t size;
	uint64_t input;
} GPU_BUFFER;

typedef struct LKM_BUFS {
	int num_bufs;
	GPU_BUFFER bufs[];
} LKM_BUFS;

typedef struct OCL_BUFFER {
	cl_mem ocl_buf;
	cl_mem_flags flags;
	int clean;
} OCL_BUFFER;

static OCL_BUFFER ocl_buf[4096];
static int i_ocl_buf;

static GPU_BUFFER buf[4096];
static int i_buf;

static GPU_BUFFER input_buf[4096];
static int i_input_buf;

static GPU_BUFFER output_buf[4096];
static int i_output_buf;

static void load_functions() __attribute__ ((constructor (666)));

static cl_command_queue (*real_clCreateCommandQueue)(
	cl_context, cl_device_id, cl_command_queue_properties, cl_int *);
static cl_mem (*real_clCreateBuffer)(cl_context, cl_mem_flags, size_t, void *,
				     cl_int *) = NULL;
static cl_int (*real_clEnqueueReadBuffer)(cl_command_queue, cl_mem, cl_bool,
					  size_t, size_t, void *, cl_uint,
					  const cl_event *, cl_event *) = NULL;
static cl_int (*real_clEnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_bool,
					   size_t, size_t, const void *,
					   cl_uint, const cl_event *,
					   cl_event *) = NULL;

static int load_flag = 0;

static void load_functions()
{
	pid = getpid();
	real_clCreateCommandQueue = dlsym(RTLD_NEXT, "clCreateCommandQueue");
	real_clCreateBuffer = dlsym(RTLD_NEXT, "clCreateBuffer");
	real_clEnqueueReadBuffer = dlsym(RTLD_NEXT, "clEnqueueReadBuffer");
	real_clEnqueueWriteBuffer = dlsym(RTLD_NEXT, "clEnqueueWriteBuffer");

	load_flag = 1;
}

#ifdef HACK
static uint64_t cl_to_gpu(cl_mem cl_buf)
{
	// int offset[] = {0x10, 0xd8, 0x38,  0x10, 0x20};
	int offset[] = { 0x120, 0x8, 0x10 };
	uint64_t base = (uint64_t)cl_buf;
	for (int i = 0; i < sizeof(offset) / sizeof(offset[0]); ++i) {
		base = *(uint64_t *)(base + offset[i]);
	}
	dbg_fprintf(stdout, "cl_mem 0x%lx gpu_buf 0x%lx\n", cl_buf, base);
	return base;
}


static cl_command_queue global_cmd_queue = NULL;

cl_command_queue clCreateCommandQueue(cl_context context, cl_device_id device,
				      cl_command_queue_properties properties,
				      cl_int *errcode_ret)
{

	cl_command_queue queue = real_clCreateCommandQueue(
		context, device, properties, errcode_ret);
	dbg_fprintf(stdout, HOOK_STR "clCreateCommandQueue called with context: %p, device: %p, properties: 0x%lx\n", (void *)context, (void *)device, properties);
	global_cmd_queue = queue;
	// if (queue) {
	//     dbg_fprintf(stdout, HOOK_STR "clCreateCommandQueue returned command queue: %p\n", (void *)queue);
	// } else if (errcode_ret) {
	//     dbg_fprintf(stdout, HOOK_STR "clCreateCommandQueue failed with error: %d\n", *errcode_ret);
	// }
	if (i_buf) {
		dbg_fprintf(stdout, "clCreateBuffer before clCreateCommandQueue !!!\n");
		for (int i = 0 ; i < i_buf ; ++ i) {
			if (ocl_buf[i].flags | CL_MEM_USE_HOST_PTR) {
				char tmp = 0;
				int ret = real_clEnqueueReadBuffer(global_cmd_queue, ocl_buf[i].ocl_buf, 0, 0, 1,
									&tmp, 0, NULL, NULL);
				assert(ret == 0);
				clFinish(global_cmd_queue);
			}
		}
	}
	return queue;
}

cl_mem clCreateBuffer(cl_context context, cl_mem_flags flags, size_t size,
		      void *host_ptr, cl_int *errcode_ret)
{
	cl_mem cl_buf = real_clCreateBuffer(context, flags, size, host_ptr,
					    errcode_ret);
	// if (host_ptr != NULL) {
	// 	dbg_fprintf(stdout, HOOK_STR "[NOTE] clCreateBuffer with non-null host-ptr\n");
	// }
	dbg_fprintf(stdout, HOOK_STR "clCreateBuffer flags: 0x%lx size: 0x%lx host_ptr: 0x%lx errcode: %d\n",
			flags, size, host_ptr, errcode_ret ? *errcode_ret : "[NO CODE]");
	if (cl_buf) {
		buf[i_buf].base = cl_to_gpu(cl_buf);
		buf[i_buf].size = size;
		dbg_fprintf(stdout, HOOK_STR "clCreateBuffer Base: 0x%lx Size: 0x%lx\n",
				buf[i_buf].base, buf[i_buf].size);
		i_buf++;
		ocl_buf[i_ocl_buf].ocl_buf = cl_buf;
		ocl_buf[i_ocl_buf].flags = flags;
		i_ocl_buf++;
		if (global_cmd_queue) {
			if (flags | CL_MEM_USE_HOST_PTR == 0) {
				char tmp = 0;
				int ret = real_clEnqueueReadBuffer(global_cmd_queue, cl_buf, 0, 0, 1,
									&tmp, 0, NULL, NULL);
				assert(ret == 0);
				clFinish(global_cmd_queue);
			}
		}
		else {
			dbg_fprintf(stdout, HOOK_STR "NULL global_cmd_queue!\n");
		}
		// dump_memory(buf[i_buf-1].base, size);
		// dbg_fprintf(stdout, HOOK_STR "clCreateBuffer Bye!\n");
	}
	else {
		dbg_fprintf(stdout, HOOK_STR "clCreateBuffer error code: %d\n", *errcode_ret);
	}
	return cl_buf;
}

cl_int clEnqueueReadBuffer(cl_command_queue queue, cl_mem buffer,
			   cl_bool blocking, size_t offset, size_t size,
			   void *ptr, cl_uint num_events,
			   const cl_event *event_list, cl_event *event)
{
	cl_int ret =
		real_clEnqueueReadBuffer(queue, buffer, blocking, offset, size,
					 ptr, num_events, event_list, event);
	clFinish(queue);
	uint64_t base = cl_to_gpu(buffer);
	dbg_fprintf(
		stdout,
		HOOK_STR
		"[OUTPUT] clEnqueueReadBuffer Base: 0x%lx Offset: 0x%lx Size: 0x%lx\n",
		base, offset, size);
	for (int i = 0; i < i_buf; ++ i) {
		if (buf[i].base == base) {
			ocl_buf[i].clean = 0;
		}
	}
	// dump_memory(base, 0x100);
	return ret;
}

static void buf_to_lkmbuf(GPU_BUFFER *buf_array, size_t size,
			  LKM_BUFS **p_lkm_bufs)
{
	*p_lkm_bufs = malloc(sizeof(LKM_BUFS) + size * sizeof(GPU_BUFFER));
	LKM_BUFS *lkm_bufs = *p_lkm_bufs;
	lkm_bufs->num_bufs = size;
	memcpy(lkm_bufs->bufs, buf_array, sizeof(GPU_BUFFER) * size);
}

cl_int clEnqueueWriteBuffer(cl_command_queue queue, cl_mem buffer,
			    cl_bool blocking, size_t offset, size_t size,
			    const void *ptr, cl_uint num_events,
			    const cl_event *event_list, cl_event *event)
{
	clFinish(queue);

	cl_int ret =
		real_clEnqueueWriteBuffer(queue, buffer, blocking, offset, size,
					  ptr, num_events, event_list, event);

	dbg_fprintf(
		stdout,
		HOOK_STR
		"clEnqueueWriteBuffer Base: 0x%lx Size: 0x%lx Blocking: %d\n",
		cl_to_gpu(buffer), size, blocking);
	clFinish(queue);

	uint64_t base = cl_to_gpu(buffer);
	input_buf[i_input_buf].base = base + offset;
	input_buf[i_input_buf].size = size;
	input_buf[i_input_buf].input = 1;
	// uint64_t start = base + offset, end = start + size;
	// for (int i = 0; i < i_input_buf; ++i) {
	// 	uint64_t _start = input_buf[i].base,
	// 		 _end = _start + input_buf[i].size;
	// 	if ((_start <= start && start < _end) ||
	// 	    (start <= _start && _start <= end)) {
	// 		dbg_fprintf(
	// 			stdout,
	// 			HOOK_STR
	// 			"[WARNING] Buffer Overlaping... Buf1: 0x%lx-0x%lx Buf2: 0x%lx-0x%lx\n",
	// 			start, end, _start, _end);
	// 	}
	// }
	i_input_buf++;

	for (int i = 0; i < i_buf; ++ i) {
		if (buf[i].base == base) {
			if (buf[i].input == 1) fprintf(stdout, "[WARNING] Write to same buffer multiple times...\n");
			buf[i].input = 1;
			if (ocl_buf[i].flags | CL_MEM_USE_HOST_PTR) {
				dbg_fprintf(stdout, "[WARNING] Write to a CL_MEM_USE_HOST_PTR buffer\n");
			}
			ocl_buf[i].clean = 1;
		}
	}

	int nfd = open(DEVICE_PATH, O_RDWR);
	assert(nfd != -1);

	// Read all input buffers
	LKM_BUFS *lkm_bufs;
	buf_to_lkmbuf(input_buf, i_input_buf, &lkm_bufs);

	//dbg_fprintf(stdout, "[%d] fd = %d dev_name = %s i_input_buf = %d\n",
	//	    getpid(), nfd, DEVICE_PATH, i_input_buf);
	if (i_input_buf > 0)
		if (ioctl(nfd, IOCTL_MCU_READ, lkm_bufs) == -1) {
			perror("Failed to call ioctl");
			close(nfd);
			return -1;
		}

	for (int i = 0; i < i_input_buf; ++i) {
		dbg_fprintf(stdout, "[%d] 0x%lx 0x%lx\n", i,
			    lkm_bufs->bufs[i].base, lkm_bufs->bufs[i].size);
		if (lkm_bufs->bufs[i].input) {
			dump_memory(lkm_bufs->bufs[i].base, 0x100);
			total_size += lkm_bufs->bufs[i].size;
		}
	}
	dbg_fprintf(stdout, "[NOTE] total_size = 0x%lx\n", total_size);

	// Only operate once
	i_input_buf = 0;

	free(lkm_bufs);

	// for (int i = 0 ; i < 10 ; ++ i)
	//     dbg_fprintf(stdout, HOOK_STR "0x%x\n", *(int*)(base+i*4));
	return ret;
}
#endif
