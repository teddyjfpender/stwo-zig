/* Entry point for the evmone-class RV64IM guest (our code).
   Same contract as ethereum/rv64/src/main.rs: set gp and sp, run, halt. */
    .section .text._start
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    /* Run C++ static constructors. */
    la s0, __init_array_start
    la s1, __init_array_end
2:  bgeu s0, s1, 3f
    ld t0, 0(s0)
    jalr t0
    addi s0, s0, 8
    j 2b
3:  call stwo_guest_main
1:  j 1b

    .section .text.stwo_guest_abort
    .globl stwo_guest_abort
stwo_guest_abort:
    /* Illegal instruction: the executor stops with an error, no output. */
    .word 0
