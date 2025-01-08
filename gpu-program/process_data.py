import numpy as np

benchmarks = ["nn", "hotspot3D", "pathfinder", "lud", "gaussian", "lavaMD"] #, "darknet_lenet"], "darknet_squeezenet", "darknet_mobilenet", "darknet_yolo"]

runtime = [[[], []] for i in range(len(benchmarks))]

with open("hook_ocl.log") as f:
    contents = f.readlines()
    num_data = len(contents) >> 1
    for i in range(num_data):
        info = contents[i*2].strip().split(" ")
        data = contents[i*2+1].strip().split(" ")
        data = [float(d) for d in data]
        
        type_idx = 0xbeef
        if info[0].find("[Hack]") != -1:
            type_idx = 1
        elif info[0].find("[Normal]") != -1:
            type_idx = 0
        else:
            assert(0, "Wrong...")
        bench_idx = 0xbeef
        for j in range(len(benchmarks)):
            if info[-1].find(benchmarks[j]) != -1:
                bench_idx = j
                break
        runtime[bench_idx][type_idx].append(data)

print("Normal")
for i in range(len(benchmarks)):
    data = np.array(runtime[i][0])
    # print(data)
    avg = np.mean(data[:, 0])
    std = np.std(data[:, 0])
    print(f"{benchmarks[i]} {avg} {std}")

print("Attack")
for i in range(len(benchmarks)):
    data = np.array(runtime[i][1])
    # print(data)
    avg_data = []
    std_data = []
    for j in range(len(data[0])):
        avg_data.append(np.mean(data[:, j]))
        std_data.append(np.std(data[:, j]))
    # print(f"{benchmarks[i]} {avg_data} {std_data}")
    total_time = avg_data[0]
    mcu_time = avg_data[2]
    exclude_time = avg_data[4]
    tee_time = total_time - exclude_time - mcu_time
    tee_mcu_time = total_time - exclude_time
    print(f"{benchmarks[i]}")
    print(f"GPU TEE Total: {tee_time:.2f} TEE+MCU: {tee_mcu_time:.2f} MCU Time: {mcu_time:.2f} Overhead: {(mcu_time / tee_time)*100:.2f}%")

# print(runtime)