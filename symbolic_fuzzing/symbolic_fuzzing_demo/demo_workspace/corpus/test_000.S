# Test case 0: Basic initialization
.section .text
.global _start

_start:
    li x1, 0x00000000    # Load immediate 0
    li x2, 0x000000AB    # Load target value 0xAB  
    li x3, 0x00000001    # Load flags pattern
    nop                  # No operation
    nop
