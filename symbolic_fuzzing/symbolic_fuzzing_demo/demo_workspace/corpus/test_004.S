# Test case 4: Error condition trigger
.section .text
.global _start

_start:
    li x1, 0x00CD00AB    # data_in with error pattern in [15:8]
    li x2, 0x0000000F    # flags = 1111 to reach S2
    nop
    nop
    nop
