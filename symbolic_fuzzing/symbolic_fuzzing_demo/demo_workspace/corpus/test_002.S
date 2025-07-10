# Test case 2: Complex flag combinations
.section .text
.global _start

_start:
    li x1, 0x000000AB    # Target data
    li x2, 0x00000009    # flags = 1001
    li x3, 0x0000000F    # flags = 1111
    li x4, 0x0000CD00    # Upper bits for error condition
    nop
