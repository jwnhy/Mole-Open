obj-m += LKM.o

ccflags-y += -Wno-unused-variable -w

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

ins:
	sudo insmod LKM.ko

rm:
	sudo rmmod LKM

mod:
	sudo insmod LKM.ko
	sudo ./a.out
	sudo rmmod LKM
	sudo dmesg -c

reload:
	sudo rmmod LKM
	sudo insmod LKM.ko
	sudo dmesg -c

note:
	# cat /proc/kallsyms
	# cat /sys/kernel/debug/tracing/available_events