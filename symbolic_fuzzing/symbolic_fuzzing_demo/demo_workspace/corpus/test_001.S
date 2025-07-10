# Test case 1: Target data pattern 0xAB
.section .text
.global _start

_start:
    li x1, 0x000000AB    # Load target data pattern
    li x2, 0x00000001    # flags[0] = 1
    li x3, 0x00000000    # flags[1] = 0
    addi x4, x0, 15      # flags = 1111 (hard to reach)
    nop
