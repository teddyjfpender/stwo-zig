// Every word/range plane is an independent mean-centered prefix. This runs
// after the shared independent scan; the raw totals remain untouched at tail.
kernel void stwo_zig_secure_interaction_mean_v1(
    device uint *output [[buffer(0)]], constant uint &rows [[buffer(1)]],
    constant uint &batches [[buffer(2)]], uint2 position [[thread_position_in_grid]]) {
    uint logical=position.x, batch=position.y;
    if(logical>=rows || batch>=batches) return;
    RiscvQm31 total=riscv_load_qm31(output,4u*batches*rows+4u*batch);
    // rows is an admitted power of two < M31. Repeated modular halving is its
    // exact inverse; no host-selected mean or claim is uploaded.
    uint inverse=1u;
    for(uint n=rows;n>1u;n>>=1u) inverse=(inverse&1u)?(inverse+RISCV_M31_P)/2u:inverse/2u;
    RiscvQm31 shift=riscv_qm_mul_base(total,riscv_m31_mul(inverse,logical+1u));
    uint physical=framework_interaction_row(logical,rows);
    RiscvQm31 prefix=framework_interaction_load(output,rows,batch,physical);
    framework_interaction_store(output,rows,batch,physical,riscv_qm_sub(prefix,shift));
}
