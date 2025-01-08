CROSS:=arm-none-eabi-
CC:=$(CROSS)gcc
OBJDUMP:=$(CROSS)objdump
OBJCOPY:=$(CROSS)objcopy

OPT:=-O2
FLAGS:=-mcpu=cortex-m4 -mthumb
CFLAGS:=$(FLAGS) $(OPT) -fno-common -Wall -Werror -Wextra
LDFLAGS:=$(FLAGS) -T./moye.lds -nostartfiles -nostdlib -lnosys -Wl,--no-warn-rwx-segments

.PHONY: all

all: fw.bin fw.elf fw.asm reset.bin reset.elf reset.asm
	-rm ../parser/fw.bin ../parser/reset.bin
	ln -sf ../shell/fw.bin ../parser/fw.bin 
	ln -sf ../shell/reset.bin ../parser/reset.bin

fw.bin: fw.elf
	$(OBJCOPY) $< -O binary $@

fw.asm: fw.elf
	$(OBJDUMP) -S $< > $@

fw.elf: fw.o
	$(CC) $(LDFLAGS) -o $@ $^

fw.o: fw.c
	$(CC) $(CFLAGS) -c -o $@ $<

reset.bin: reset.elf
	$(OBJCOPY) $< -O binary $@

reset.asm: reset.elf
	$(OBJDUMP) -S $< > $@

reset.elf: reset.o
	$(CC) $(LDFLAGS) -o $@ $^

reset.o: reset.c
	$(CC) $(CFLAGS) -c -o $@ $<


clean:
	rm -f *.elf *.bin *.asm *.hex
