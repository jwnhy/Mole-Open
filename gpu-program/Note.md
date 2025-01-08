# Compile and Install OpenCV

* 
    ```
    git clone https://github.com/opencv/opencv.git
    cd opencv
    git checkout 71d3237
    mkdir build
    cd build
    # debug
    cmake -DWITH_OPENCL=ON -DCMAKE_BUILD_TYPE=Debug ..
    # release
    cmake -DWITH_OPENCL=ON ..
    # -j6 is good for rock 5 itx
    make -j6
    sudo make install
    sudo ldconfig
    ```

# OpenCL error when use OpenCV

* Error info
    ```
    OpenCL program build log: imgproc/resize
    Status -11: CL_BUILD_PROGRAM_FAILURE
    -D INTER_LINEAR -D depth=0 -D T=uchar3 -D T1=uchar -D WT=int3 -D convertToWT=convert_int3 -D convertToDT=convert_uchar3_sat -D cn=3 -D INTER_RESIZE_COEF_BITS=11
    <built-in>:170:9: error: expected member name or ';' after declaration specifiers
    int32_t depth;             /**< The image depth. */
    ~~~~~~~ ^
    <built-in>:2:15: note: expanded from here
    #define depth 0
                ^

    <built-in>:170:8: error: expected ';' at end of declaration list
    int32_t depth;             /**< The image depth. */
        ^

    error: Compiler frontend failed (error code 62)

    terminate called after throwing an instance of 'cv::Exception'
    what():  OpenCV(4.5.1) ../modules/core/src/matrix.cpp:466: error: (-215:Assertion failed) _step >= minstep in function 'Mat'

    Aborted
    ```

* Solution: https://github.com/opencv/opencv/issues/24435

* Actual reason: I didn't add `-L/usr/local/lib -L/usr/local/share` when compiling opencv program. As a result, the opencv program use system's opencv as default rather than the newest installed opencv.

* Updated: Add include directory `/usr/local/include/opencv4` to use our own compiled OpenCV and use `pkg-config` without cflags: `pkg-config --libs opencv4`

# LD_PRELOAD cannot hook the opencl APIs called by opencv

* In the file `opencv/modules/core/src/opencl/runtime/opencl_core.cpp`, the function `GetProcAddress()` always reads the symbol in `libOpenCL.so` or `libOpenCL.so.1`, which bypasses our `LD_PRELOAD` library.

* Solution: Replace the return statement in `GetProcAddress()` with `return dlsym(RTLD_DEFAULT, name);`.

# Face detection

Copy `<opencv_path>/data/haarcascades/haarcascade_frontalface_default.xml` to current directory

# Good code to decode instruction

* linux/arch/arm64/include/asm/insn.h

# Evaluation:

* Darknet (yolo example)

    * https://github.com/sowson/darknet.git

* Rodinia
    
    * 
    ```
    git clone https://github.com/JuliaParallel/rodinia.git
    cd opencl
    vi Makefile
    # Modify "BENCHMARKS := $(sort $(filter-out $(wildcard _*/),$(dir $(wildcard */))))" -> 
    # "BENCHMARKS := nn/ pathfinder/ lud/ hotspot3D/ lavaMD/ gaussian/"
    make
    # Then you can run the benchmark like `cd gaussian && bash run`
    ```

* Lenet

    * https://github.com/GokulNC/DarkNet-Classifier-LeNet-MNIST

    * https://github.com/cvdfoundation/mnist?tab=readme-ov-file (MNIST Dataset)

* Squeezenet

    * https://github.com/azuryl/squeezenet-darknet-model

* Mobilenet

    * 

# CS Buffer

* Function: `void program_cs(struct kbase_device *kbdev, struct kbase_queue *queue, bool ring_csg_doorbell)`

    * Code details: `.src/linux/drivers/gpu/arm/bifrost/csf/mali_kbase_csf_scheduler.c`

    * Multiple call to `kbase_csf_firmware_cs_input()`. 
    
        * Code details: `.src/linux/drivers/gpu/arm/bifrost/csf/mali_kbase_csf_firmware.c`

        * Just write the value to `kbdev->csf.global_iface.groups[group->csg_nr].streams[csi_index].input`

    * `program_cs_trace_cfg()`

    * `kbase_csf_ring_cs_kernel_doorbell()`

        * `kbase_csf_firmware_csg_output()`

        * `kbase_csf_firmware_csg_input_mask()`

        * `kbase_csf_ring_csg_doorbell()`

            * `kbase_csf_ring_csg_slots_doorbell()`

                * `kbase_csf_firmware_global_output()`

                * `kbase_csf_firmware_global_input_mask()`

                * `kbase_csf_ring_doorbell()` --- Use kprobe to hook it

                    * `kbase_reg_write(kbdev, csf_doorbell_offset(doorbell_nr), (u32)1);`

* 
    ```
    void kbase_csf_firmware_cs_input(
        const struct kbase_csf_cmd_stream_info *const info, const u32 offset,
        const u32 value)
    {
        const struct kbase_device * const kbdev = info->kbdev;

        dev_dbg(kbdev->dev, "cs input w: reg %08x val %08x\n", offset, value);
        input_page_write(info->input, offset, value);
    }
    ```