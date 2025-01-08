CXX := g++
CXXFLAGS := -g -Wall
INCLUDES := -isystem /usr/local/include/opencv4
LDLIBS := -ldl -lOpenCL
LDFLAGS := -L/usr/local/lib -L/usr/local/share

SOURCES := $(wildcard cv_*.cpp)
TARGETS := $(SOURCES:.cpp=)

all: $(TARGETS) hook cl

%: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ `pkg-config --libs opencv4` $(LDFLAGS) $(LDLIBS) $(INCLUDES)

hook: hook_ocl.c
	gcc -DHACK -shared -g -fPIC -o hook_ocl.so hook_ocl.c -ldl -lOpenCL -lssl -lcrypto
	gcc -shared -g -fPIC -o normal_ocl.so hook_ocl.c -ldl -lOpenCL -lssl -lcrypto

cl: cl.c
	gcc -o cl -g cl.c -lOpenCL

.PHONY: run
run:
	# sudo dmesg -c
	sudo LD_PRELOAD=./hook_ocl.so ./cv_edge > user.log
	# LD_PRELOAD=./hook_ocl.so ./cv_face
	# LD_PRELOAD=./hook_ocl.so ./cl
	# sudo /home/radxa/ebpf-hook/iotracer/minimal ./cv_edge
	sudo dmesg -c > kernel.log

.PHONY: mod
ins:
	sudo dmesg -c
	sudo insmod ~/mcu_hacker.ko

rm:
	sudo rmmod mcu_hacker.ko
	sudo dmesg -c

trace: ptrace_sys.c
	gcc -pthread -g ptrace_sys.c -o ptrace_sys

.PHONY: clean
clean:
	rm $(TARGETS) cl hook_ocl.so