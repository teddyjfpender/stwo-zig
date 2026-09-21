// The same 256-lane two-level scan as core/relation.metal, applied separately
// to each batch. Independent prefixes have raw claims and no average shift.
inline RiscvQm31 framework_interaction_inverse(RiscvQm31 value) {
    Qm31Value result = qm_inv(Qm31Value{value.a,value.b,value.c,value.d});
    return {result.a,result.b,result.c,result.d};
}
inline uint framework_interaction_row(uint index, uint rows) {
    uint circle = (index & 1u) == 0u ? index/2u : rows-1u-index/2u;
    return riscv_bit_reverse(circle, ctz(rows));
}
inline RiscvQm31 framework_interaction_load(device const uint *output, uint rows, uint batch, uint row) {
    return riscv_load_secure_column(output, 4u*batch, rows, row);
}
inline void framework_interaction_store(device uint *output, uint rows, uint batch, uint row, RiscvQm31 v) {
    output[riscv_column_offset(4u*batch,rows,row)] = v.a;
    output[riscv_column_offset(4u*batch+1u,rows,row)] = v.b;
    output[riscv_column_offset(4u*batch+2u,rows,row)] = v.c;
    output[riscv_column_offset(4u*batch+3u,rows,row)] = v.d;
}
kernel void stwo_zig_framework_interaction_block_scan_v1(
    device uint *output [[buffer(0)]], device RiscvQm31 *block_sums [[buffer(1)]],
    constant uint &rows [[buffer(2)]], constant uint &blocks [[buffer(3)]],
    uint lane [[thread_index_in_threadgroup]], uint group [[threadgroup_position_in_grid]]) {
    uint batch=group/blocks, local=group%blocks, index=local*256u+lane;
    threadgroup RiscvQm31 values[256];
    values[lane] = index<rows ? framework_interaction_load(output,rows,batch,framework_interaction_row(index,rows)) : RiscvQm31{0u,0u,0u,0u};
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint offset=1u; offset<256u; offset<<=1u) {
        RiscvQm31 value=values[lane];
        if (lane>=offset) value=riscv_qm_add(value,values[lane-offset]);
        threadgroup_barrier(mem_flags::mem_threadgroup);
        values[lane]=value;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    if (index<rows) framework_interaction_store(output,rows,batch,framework_interaction_row(index,rows),values[lane]);
    if (lane+1u==min(256u,rows-local*256u)) block_sums[group]=values[lane];
}
kernel void stwo_zig_framework_interaction_scan_blocks_v1(
    device uint *output [[buffer(0)]], device RiscvQm31 *block_sums [[buffer(1)]],
    constant uint &rows [[buffer(2)]], constant uint &blocks [[buffer(3)]],
    constant uint &batches [[buffer(4)]], uint batch [[thread_position_in_grid]]) {
    if (batch>=batches) return;
    RiscvQm31 sum={0u,0u,0u,0u};
    for (uint block=0u; block<blocks; ++block) {
        uint index=batch*blocks+block;
        sum=riscv_qm_add(sum,block_sums[index]); block_sums[index]=sum;
    }
    ulong claim=ulong(batches)*4u*rows+batch*4u;
    output[claim]=sum.a; output[claim+1u]=sum.b; output[claim+2u]=sum.c; output[claim+3u]=sum.d;
}
kernel void stwo_zig_framework_interaction_finalize_v1(
    device uint *output [[buffer(0)]], device const RiscvQm31 *block_sums [[buffer(1)]],
    constant uint &rows [[buffer(2)]], constant uint &blocks [[buffer(3)]],
    constant uint &batches [[buffer(4)]], uint2 id [[thread_position_in_grid]]) {
    uint index=id.x,batch=id.y;
    if (index>=rows || batch>=batches) return;
    uint block=index/256u;
    if (block==0u) return;
    uint row=framework_interaction_row(index,rows);
    framework_interaction_store(output,rows,batch,row,riscv_qm_add(framework_interaction_load(output,rows,batch,row),block_sums[batch*blocks+block-1u]));
}

// Framework layout scans only the final cumulative plane and removes its mean.
kernel void stwo_zig_framework_interaction_cumulative_block_scan_v1(
    device uint *output [[buffer(0)]], device RiscvQm31 *block_sums [[buffer(1)]],
    constant uint &rows [[buffer(2)]], constant uint &blocks [[buffer(3)]],
    constant uint &batches [[buffer(4)]],
    uint lane [[thread_index_in_threadgroup]], uint group [[threadgroup_position_in_grid]]) {
    uint batch=batches-1u, local=group, index=local*256u+lane;
    threadgroup RiscvQm31 values[256];
    values[lane] = index<rows ? framework_interaction_load(output,rows,batch,framework_interaction_row(index,rows)) : RiscvQm31{0u,0u,0u,0u};
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint offset=1u; offset<256u; offset<<=1u) {
        RiscvQm31 value=values[lane];
        if (lane>=offset) value=riscv_qm_add(value,values[lane-offset]);
        threadgroup_barrier(mem_flags::mem_threadgroup);
        values[lane]=value;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    if (index<rows) framework_interaction_store(output,rows,batch,framework_interaction_row(index,rows),values[lane]);
    if (lane+1u==min(256u,rows-local*256u)) block_sums[group]=values[lane];
}
kernel void stwo_zig_framework_interaction_cumulative_scan_blocks_v1(
    device uint *output [[buffer(0)]], device RiscvQm31 *block_sums [[buffer(1)]],
    constant uint &rows [[buffer(2)]], constant uint &blocks [[buffer(3)]],
    constant uint &batches [[buffer(4)]], uint batch [[thread_position_in_grid]]) {
    if (batch!=0u) return;
    RiscvQm31 sum={0u,0u,0u,0u};
    for (uint block=0u; block<blocks; ++block) {
        uint index=block;
        sum=riscv_qm_add(sum,block_sums[index]); block_sums[index]=sum;
    }
    ulong claim=ulong(batches)*4u*rows;
    output[claim]=sum.a; output[claim+1u]=sum.b; output[claim+2u]=sum.c; output[claim+3u]=sum.d;
}
kernel void stwo_zig_framework_interaction_cumulative_finalize_v1(
    device uint *output [[buffer(0)]], device const RiscvQm31 *block_sums [[buffer(1)]],
    constant uint &rows [[buffer(2)]], constant uint &blocks [[buffer(3)]],
    constant uint &batches [[buffer(4)]], uint2 id [[thread_position_in_grid]]) {
    uint index=id.x;
    if(index>=rows || id.y!=0u) return;
    uint row=framework_interaction_row(index,rows),block=index/256u,batch=batches-1u;
    RiscvQm31 prefix=framework_interaction_load(output,rows,batch,row);
    if(block!=0u) prefix=riscv_qm_add(prefix,block_sums[block-1u]);
    ulong claim_offset=ulong(batches)*4u*rows;
    RiscvQm31 claim={output[claim_offset],output[claim_offset+1u],output[claim_offset+2u],output[claim_offset+3u]};
    // In M31, inverse(2^k)=2^(31-k). The runtime admits power-of-two rows.
    uint factor=riscv_m31_mul(index+1u,1u<<(31u-ctz(rows)));
    framework_interaction_store(output,rows,batch,row,riscv_qm_sub(prefix,riscv_qm_mul_base(claim,factor)));
}
