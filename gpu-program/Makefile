CXX := g++
CXXFLAGS := -g -Wall
INCLUDES := -isystem /usr/local/include/opencv4
LDLIBS := -ldl -lOpenCL
LDFLAGS := -L/usr/local/lib -L/usr/local/share

all: hook cl

hook: hook_ocl.c
	gcc -DHACK -shared -g -fPIC -o hook_ocl.so hook_ocl.c -ldl -lOpenCL -lssl -lcrypto

cl: cl.c
	gcc -o cl -g cl.c -lOpenCL

.PHONY: mod
ins:
	sudo dmesg -c
	sudo insmod ~/mcu_hacker.ko

rm:
	sudo rmmod mcu_hacker.ko
	sudo dmesg -c

.PHONY: clean
clean:
	rm $(TARGETS) cl hook_ocl.so