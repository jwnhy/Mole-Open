#include <stdint.h>
/*
		"ldr r0, =0x40020080\n\t"
		"ldr r0, [r0]\n\t"
		"ldr r1, =0x4094030\n\t"
		"str r0, [r1]\n\t"
		// clean cache
		"dsb\n\t"
		"ldr r0, =0xE000E000\n\t"
		"str r1, [r0, #0xF68]\n\t"
		// write magic
		"ldr r0, =0x4094008\n\t"
		"ldr r1, =0xdeadbeef\n\t"
		"str r1, [r0]\n\t"
    */


__attribute__((naked)) void _reset(void)
{
	__asm__(
      "cpsid i\n\t"
      "ldr r0, =0x40020280\n\t"
      "ldr r1, =0x800001\n\t"
      "str r1, [r0]\n\t"
      "ldr.w pc, =0xdeadbeef\n\t"
      );
}

//typedef int (*func_t)(void) __attribute__((noreturn));
//int main(void)
//{
//	func_t real = (func_t)0x801fa5;
//	real();
//}
