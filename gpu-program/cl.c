#include <CL/cl.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#define BUFFER_SIZE 4096
#define VALUE 0xdeadbeef

jmp_buf jump_buffer;
uint32_t *read_buffer;
uint32_t *host_buffer;
uint32_t *c_buf, *c_buf_a, *c_buf_b;

void segfault_handler(int sig) {
    siglongjmp(jump_buffer, 1);
}

int is_valid_pointer(uintptr_t address) {
    if (address == 0) return 0;
    volatile uint32_t *ptr = (volatile uint32_t *)address;
    if (!sigsetjmp(jump_buffer, 1)) {
        uint32_t value = *ptr;
        (void)value;
        return 1;
    } else {
        return 0;
    }
}

uint64_t vis[4096];
int i_vis;
uint64_t ptrs[4096];
int i_ptrs;

void init_vis() {
    i_vis = 0;
    memset(vis, 0, sizeof(vis));
}

int is_vis(uint64_t addr) {
    for (int i = 0 ; i < i_vis ; ++ i) {
        if (addr == vis[i]) 
            return 1;
    }
    return 0;
}

typedef struct trace_pair {
    uint64_t addr;
    int offset;
} trace_pair;

trace_pair stack[64];
int i_stack;
int path[64][64];
int i_path;
int found;

int in_stack(int val) {
    for (int i = 0 ; i < i_stack ; ++ i)
        if (stack[i].addr == val)
            return 1;
    return 0;
}

static inline int in_range(uint64_t start, uint64_t end, uint64_t val) {
    return start <= val && val < end;
}

int find_signature(void *_buf, int bytes, uint64_t signature, int depth, int max_depth) {
    if (depth >= max_depth) return 0;
    uint64_t* buf = _buf;
    for (int i = 0 ; i < bytes / 8 ; ++ i) {
        uint64_t val = buf[i];
        // Address like 0xaaaabf937410 is cpu program address
        // Address like 0x7fdfffe5b080 is gpu address
        if (val == signature && ((uint64_t)_buf >> 36) != 0xaaa) 
        {
            printf("Signature at 0x%lx Depth: %d\n", (uint64_t)(_buf+i*8), depth);
            for (int j = 0 ; j < i_stack ; ++ j) {
                printf("%d 0x%lx 0x%x\n", j, stack[j].addr, stack[j].offset);
                path[i_path][j] = stack[j].offset;
            }
            path[i_path][i_stack] = -1;
            i_path ++;
            return 1;
        }
        if (is_valid_pointer(val) && !in_stack(val)/*!is_vis(val)*/) {
            // vis[i_vis++] = val;
            trace_pair temp;
            temp.addr = (uint64_t)_buf;
            temp.offset = i * 8;
            stack[i_stack++] = temp;
            int found = find_signature((void*)val, bytes, signature, depth+1, max_depth);
            i_stack --;
            if (found) return 1;
        }
    }
    return 0;
}

void buf_sig(cl_mem clbuf, uint64_t sig) {
    printf("Find 0x%lx in CL Buffer\n", sig);
    for (int i = 0 ; i <= 10; ++ i) {
        int found;
        init_vis();
        found = find_signature(clbuf, 1024, sig, 0, i);
        // if (found) break;
    }
}

static uint64_t cl_to_gpu(cl_mem cl_buf) {
    int offset[] = {0x120, 0x8, 0x10};
    uint64_t base = (uint64_t)cl_buf;
    for (int i = 0 ; i < sizeof(offset)/sizeof(offset[0]) ; ++ i) {
        base = *(uint64_t*)(base+offset[i]);
    }
    printf("cl_mem 0x%lx gpu_buf 0x%lx\n", cl_buf, base);
    return base;
}

void dump_mem(void *_buf, unsigned sz) {
    uint64_t* buf = _buf;
    const int c = 4;
    for (int i = 0 ; i < sz/8/4 ; ++ i) {
        for (int j = 0 ; j < c ; ++ j) {
            uint64_t addr = buf[i*4+j];
            printf("%016lx ", (uint64_t)addr);
            if (is_valid_pointer(addr) && !is_vis(addr)) {
                ptrs[i_ptrs++] = addr;
            }
        }
        printf("\n");
    }
}

const char* kernelSource = 
"__kernel void vector_add(__global const int* a, __global const int* b, __global int* result) { \n"
"    int id = get_global_id(0); \n"
"    result[id] = a[id] + b[id]; \n"
"}\n";

int main() {
    struct sigaction sa;
    sa.sa_handler = segfault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGSEGV, &sa, NULL);

    // Initialize OpenCL platform, device, context, and queue
    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;
    cl_context context = NULL;
    cl_command_queue command_queue = NULL;
    cl_int ret;
    size_t globalSize;

    // Get platform and device info
    ret = clGetPlatformIDs(1, &platform_id, NULL);
    ret = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_DEFAULT, 1, &device_id, NULL);

    // Create OpenCL context
    context = clCreateContext(NULL, 1, &device_id, NULL, NULL, &ret);

    // Create command queue
    command_queue = clCreateCommandQueue(context, device_id, 0, &ret);

    // Create a buffer of size 4096 bytes
    cl_mem buffer = clCreateBuffer(context, CL_MEM_READ_WRITE, BUFFER_SIZE, NULL, &ret);
    cl_mem buffer_a = clCreateBuffer(context, CL_MEM_READ_WRITE, BUFFER_SIZE, NULL, &ret);
    cl_mem buffer_b = clCreateBuffer(context, CL_MEM_READ_WRITE, BUFFER_SIZE, NULL, &ret);
    cl_mem buffer__ = clCreateBuffer(context, CL_MEM_READ_WRITE, BUFFER_SIZE, NULL, &ret);
    cl_mem buffer_c = clCreateBuffer(context, CL_MEM_READ_WRITE, BUFFER_SIZE, NULL, &ret);
    cl_mem buffer_d = clCreateBuffer(context, CL_MEM_READ_WRITE, BUFFER_SIZE, NULL, &ret);

    // Build the kernel
    cl_program program = clCreateProgramWithSource(context, 1, &kernelSource, NULL, NULL);
    clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
    cl_kernel kernel = clCreateKernel(program, "vector_add", NULL);
    // cl_kernel kernel__ = clCreateKernel(program, "vector_add", NULL);
    // printf("[0x%lx] [0x%lx]\n", kernel, kernel__);
    // assert(0);

    c_buf = (uint32_t *)malloc(BUFFER_SIZE);
    c_buf_a = (uint32_t *)malloc(BUFFER_SIZE);
    c_buf_b = (uint32_t *)malloc(BUFFER_SIZE);

    // buffer = buffer_a + buffer_b
    memset(c_buf, 0x0, BUFFER_SIZE);
    memset(c_buf_a, 0x11, BUFFER_SIZE);
    memset(c_buf_b, 0x22, BUFFER_SIZE);

    clSetKernelArg(kernel, 0, sizeof(cl_mem), &buffer_a);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &buffer_b);
    clSetKernelArg(kernel, 2, sizeof(cl_mem), &buffer);

    ret = clEnqueueWriteBuffer(command_queue, buffer_a, CL_TRUE, 0, BUFFER_SIZE, c_buf_a, 0, NULL, NULL);
    ret = clEnqueueWriteBuffer(command_queue, buffer_b, CL_TRUE, 0, BUFFER_SIZE, c_buf_b, 0, NULL, NULL);

    globalSize = 1024;
    ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, &globalSize, NULL, 0, NULL, NULL);

    ret = clEnqueueReadBuffer(command_queue, buffer, CL_TRUE, 0, BUFFER_SIZE, c_buf, 0, NULL, NULL);

    for (int i = 0 ; i < BUFFER_SIZE / 4 ; ++ i) {
        // printf("0x%x\n", c_buf[i]);
        assert(c_buf[i] == 0x33333333);
    }

    // buffer__ = buffer_c + buffer_d
    memset(c_buf, 0x0, BUFFER_SIZE);
    memset(c_buf_a, 0x44, BUFFER_SIZE);
    memset(c_buf_b, 0x55, BUFFER_SIZE);

    clSetKernelArg(kernel, 0, sizeof(cl_mem), &buffer_c);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &buffer_d);
    clSetKernelArg(kernel, 2, sizeof(cl_mem), &buffer__);
    
    ret = clEnqueueWriteBuffer(command_queue, buffer_c, CL_TRUE, 0, BUFFER_SIZE, c_buf_a, 0, NULL, NULL);
    ret = clEnqueueWriteBuffer(command_queue, buffer_d, CL_TRUE, 0, BUFFER_SIZE, c_buf_b, 0, NULL, NULL);

    globalSize = 1024;
    ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, &globalSize, NULL, 0, NULL, NULL);

    ret = clEnqueueReadBuffer(command_queue, buffer__, CL_TRUE, 0, BUFFER_SIZE, c_buf, 0, NULL, NULL);

    for (int i = 0 ; i < BUFFER_SIZE / 4 ; ++ i) {
        // printf("0x%x\n", c_buf[i]);
        assert(c_buf[i] == 0x99999999);
    }

    // buf_sig(buffer_a, 0x1111111111111111);
    // buf_sig(buffer_b, 0x2222222222222222);
    // buf_sig(buffer  , 0x3333333333333333);
    // buf_sig(buffer_c, 0x4444444444444444);
    // buf_sig(buffer_d, 0x5555555555555555);
    // buf_sig(buffer__, 0x9999999999999999);

    for (int i = 0 ; i < i_path ; ++ i) {
        for (int j = 0 ; path[i][j] != -1 ; ++ j) {
            printf("0x%x ", path[i][j]);
        }
        printf("\n");
    }

    printf("0x7fdfffe9d000: 0x%lx\n", *(uint64_t*)0x7fdfffe9d000);

    cl_to_gpu(buffer_a);
    cl_to_gpu(buffer_b);
    cl_to_gpu(buffer);
    cl_to_gpu(buffer_c);
    cl_to_gpu(buffer_d);
    cl_to_gpu(buffer__);

    return 0;

    // Create host buffer and initialize with 0xDEADBEEF every 4 bytes
    host_buffer = (uint32_t *)malloc(BUFFER_SIZE);
    for (int i = 0; i < BUFFER_SIZE / 4; i++) {
        host_buffer[i] = VALUE;
    }

    // Write the buffer to the device
    ret = clEnqueueWriteBuffer(command_queue, buffer, CL_TRUE, 0, BUFFER_SIZE, host_buffer, 0, NULL, NULL);

    // Read the buffer back from the device to verify
    read_buffer = (uint32_t *)malloc(BUFFER_SIZE);
    ret = clEnqueueReadBuffer(command_queue, buffer, CL_TRUE, 0, BUFFER_SIZE, read_buffer, 0, NULL, NULL);

    // Verify the buffer content
    int success = 1;
    for (int i = 0; i < BUFFER_SIZE / 4; i++) {
        if (read_buffer[i] != VALUE) {
            printf("Error at index %d: expected 0x%x, got 0x%x\n", i, VALUE, read_buffer[i]);
            success = 0;
        }
    }

    if (success) {
        printf("Buffer validation successful. All values are 0x%x\n", VALUE);
    }

    // dump_mem(buffer, 1024);
    for (int i = 0 ; i <= 10; ++ i) {
        memset(vis, 0, sizeof(vis));
        int found = find_signature(buffer, 256, 0xdeadbeefdeadbeef, 0, i);
        // if (found) break;
    }
    printf("[CPU BUFFER] host_buffer 0x%lx read_buffer 0x%lx\n", host_buffer, read_buffer);

    // Cleanup
    free(host_buffer);
    free(read_buffer);
    clReleaseMemObject(buffer);
    clReleaseCommandQueue(command_queue);
    clReleaseContext(context);

    return 0;
}
