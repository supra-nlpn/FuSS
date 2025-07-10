# Test case 3: Edge cases
.section .text
.global _start

_start:
    li x1, 0x000000AC    # data_in != 0xAB
    li x2, 0x00000000    # flags = 0000
    li x3, 0xFFFFFFFF    # All bits set
    nop
    nop
