import os
import subprocess
import time

hook_so = "/home/radxa/csfparser/gpu-program/hook_ocl.so"
normal_so = "/home/radxa/csfparser/gpu-program/normal_ocl.so"
LD_PRELOAD_HACK = f"LD_PRELOAD={hook_so}"
LD_PRELOAD_NORMAL = f"LD_PRELOAD={normal_so}"

LD_PRELOAD_LIST = [LD_PRELOAD_HACK, LD_PRELOAD_NORMAL]

batch = 2

def run_rodinia():
    rodinia_path = "/home/radxa/gpu-rodinia/opencl/"
    benchmarks = ["nn", "hotspot3D", "pathfinder", "lud", "gaussian", "lavaMD"]
    # benchmarks = ["lavaMD"]

    for b in benchmarks:
        dir = rodinia_path + b
        os.chdir(dir)
        print(b, os.getcwd())
        # os.environ['LD_PRELOAD'] = '/home/radxa/csfparser/gpu-program/hook_ocl.so'
        with open("run") as f:
            run_cmd = f.read().strip("\n")
        
        for LD_PRELOAD in LD_PRELOAD_LIST:
            for i in range(batch):
                t = time.time()
                # subprocess.run(f"{LD_PRELOAD} {rodinia_path+b}/{run_cmd}", cwd=dir)#, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                os.system(f"{LD_PRELOAD} {run_cmd}")
                print(f"Time: {time.time() - t}")

def run_nerual_networks():
    neural_networks = [
        "lenet",
        "squeezenet",
        "mobilenet",
        "yolo"
    ]

    os.chdir("/home/radxa/darknet/")
    dir = "/home/radxa/darknet/"
    for n in neural_networks:
        print(n)
        # os.environ['LD_PRELOAD'] = '/home/radxa/csfparser/gpu-program/hook_ocl.so'

        with open(f"run_{n}") as f:
            run_cmd = f.read().strip("\n")

        for LD_PRELOAD in LD_PRELOAD_LIST:
            for i in range(batch):
                t = time.time()
                # subprocess.run(f"{LD_PRELOAD} {run_cmd}", cwd=dir, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                os.system(f"{LD_PRELOAD} {run_cmd}")
                print(f"Time: {time.time() - t}")
            
run_rodinia()
# run_nerual_networks()