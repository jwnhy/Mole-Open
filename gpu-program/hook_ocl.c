#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <CL/cl.h>
#include <time.h>
#include <setjmp.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <assert.h>
#include <time.h>
#include "v2p.h"
#include "crypto.c"

#define HOOK_STR "* [OPENCL_HOOK] "

#ifdef HACK
static char* mode_str = "[Hack]";
#else
static char* mode_str = "[Normal]";
#endif

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
double ocl_w_buf_time, mcu_r_buf_time, strongbox_in_time, strongbox_ex_time;
static struct timespec strongbox_start, strongbox_end;
static struct timespec total_start, total_end;
static struct timespec start, end;

static double time_milliseconds(struct timespec start, struct timespec end) {
	long seconds = end.tv_sec - start.tv_sec;
    long nanoseconds = end.tv_nsec - start.tv_nsec;
    return seconds * 1000.0 + nanoseconds / 1000000.0;
}

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

static char logmsg[1024*1024];

static void load_functions() __attribute__ ((constructor (666)));
static void save_logmsg() __attribute__ ((destructor (888)));

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
	clock_gettime(CLOCK_MONOTONIC, &total_start);

	pid = getpid();
	real_clCreateCommandQueue = dlsym(RTLD_NEXT, "clCreateCommandQueue");
	real_clCreateBuffer = dlsym(RTLD_NEXT, "clCreateBuffer");
	real_clEnqueueReadBuffer = dlsym(RTLD_NEXT, "clEnqueueReadBuffer");
	real_clEnqueueWriteBuffer = dlsym(RTLD_NEXT, "clEnqueueWriteBuffer");

	load_flag = 1;
}

static void save_logmsg() {
#ifdef HACK
	clock_gettime(CLOCK_MONOTONIC, &strongbox_start);
	for (int i = 0 ; i < i_buf ; ++ i) {
		if (ocl_buf[i].clean)
			memset(buf[i].base, buf[i].size, 0);
	}
	clock_gettime(CLOCK_MONOTONIC, &strongbox_end);
	strongbox_in_time += time_milliseconds(strongbox_start, strongbox_end);
#endif
	
	clock_gettime(CLOCK_MONOTONIC, &total_end);
	double total_time = time_milliseconds(total_start, total_end);
	
	char log_path[256];
	sprintf(log_path, "/home/radxa/csfparser/gpu-program/hook_ocl.log");

	char procname[256], cmdline[256];
	memset(procname, sizeof(procname), 0);
	memset(cmdline, sizeof(cmdline), 0);
    ssize_t len;
	len = readlink("/proc/self/exe", procname, sizeof(procname) - 1);
	procname[len] = '\0';

	FILE* cmd_file = fopen("/proc/self/cmdline", "r");
	// len = fscanf(cmd_file, "%s", cmdline);
	len = fread(cmdline, 1, sizeof(cmdline) - 1, cmd_file);
	cmdline[len] = 0;
	fclose(cmd_file);

	FILE* f = fopen(log_path, "a+");
	fprintf(f, "%s %s %s\n%lf %lf %lf %lf %lf\n", 
		mode_str, procname, cmdline, 
		total_time, ocl_w_buf_time, mcu_r_buf_time, strongbox_in_time, strongbox_ex_time
	);
	fclose(f);
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

	clock_gettime(CLOCK_MONOTONIC, &strongbox_start);
	char *cipher = malloc(size+16);
	int cipher_len = aes_128_encrypt(base+offset, size, cipher);
	sha256(cipher, cipher_len);
	free(cipher);
	clock_gettime(CLOCK_MONOTONIC, &strongbox_end);
	strongbox_in_time += time_milliseconds(strongbox_start, strongbox_end);

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
	clock_gettime(CLOCK_MONOTONIC, &start);

	cl_int ret =
		real_clEnqueueWriteBuffer(queue, buffer, blocking, offset, size,
					  ptr, num_events, event_list, event);

	dbg_fprintf(
		stdout,
		HOOK_STR
		"clEnqueueWriteBuffer Base: 0x%lx Size: 0x%lx Blocking: %d\n",
		cl_to_gpu(buffer), size, blocking);
	clFinish(queue);
	clock_gettime(CLOCK_MONOTONIC, &end);
	double t = 0.0;
	t = time_milliseconds(start, end);
	ocl_w_buf_time += t;

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

	clock_gettime(CLOCK_MONOTONIC, &strongbox_start);
	char *cipher = malloc(size+16);
	int cipher_len = aes_128_encrypt(base+offset, size, cipher);
	clock_gettime(CLOCK_MONOTONIC, &strongbox_end);
	strongbox_ex_time += time_milliseconds(strongbox_start, strongbox_end);

	clock_gettime(CLOCK_MONOTONIC, &strongbox_start);
	sha256(cipher, cipher_len);
	aes_128_decrypt(cipher, cipher_len, cipher);
	clock_gettime(CLOCK_MONOTONIC, &strongbox_end);
	free(cipher);
	strongbox_in_time += time_milliseconds(strongbox_start, strongbox_end);

	i_input_buf++;


	for (int i = 0; i < i_buf; ++ i) {
		if (buf[i].base == base) {
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
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	if (i_input_buf > 0)
		if (ioctl(nfd, IOCTL_MCU_READ, lkm_bufs) == -1) {
			perror("Failed to call ioctl");
			close(nfd);
			return -1;
		}

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	size_t total_size = 0;
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
	t = time_milliseconds(start, end);
	mcu_r_buf_time += t;

	// for (int i = 0 ; i < 10 ; ++ i)
	//     dbg_fprintf(stdout, HOOK_STR "0x%x\n", *(int*)(base+i*4));
	return ret;
}
#endif
