
reset.elf:     file format elf32-littlearm


Disassembly of section .text:

09000000 <_reset>:
 9000000:	b672      	cpsid	i
 9000002:	4802      	ldr	r0, [pc, #8]	@ (900000c <_reset+0xc>)
 9000004:	4902      	ldr	r1, [pc, #8]	@ (9000010 <_reset+0x10>)
 9000006:	6001      	str	r1, [r0, #0]
 9000008:	f8df f008 	ldr.w	pc, [pc, #8]	@ 9000014 <_reset+0x14>
 900000c:	40020280 	.word	0x40020280
 9000010:	00800001 	.word	0x00800001
 9000014:	deadbeef 	.word	0xdeadbeef
	...
