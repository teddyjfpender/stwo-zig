// Appended to secure_polynomial_v1.cuh by the authenticated AOT exporter.
// All buffers are caller-owned resident allocations. No device malloc/JIT.
__device__ __forceinline__ RiscvQm31 stwo_secure_load(const uint *p,uint rows,uint batch,uint row) {
    ulong base=4ull*batch*rows+row;
    return {p[base],p[base+rows],p[base+2ull*rows],p[base+3ull*rows]};
}
extern "C" __global__ void stwo_cuda_secure_scan_block_v1(uint *values,uint *block_sums,uint rows,uint batches,uint mapped) {
    uint local=threadIdx.x,logical=blockIdx.x*256u+local,batch=blockIdx.y;
    if(batch>=batches) return; // launch y is exact; no divergent block exit.
    __shared__ RiscvQm31 prefix[256];
    uint physical=mapped?framework_interaction_row(logical<rows?logical:0u,rows):logical;
    prefix[local]=logical<rows?stwo_secure_load(values,rows,batch,physical):RiscvQm31{0u,0u,0u,0u};
    __syncthreads();
    for(uint distance=1u;distance<256u;distance<<=1u) {
        RiscvQm31 prior=local>=distance?prefix[local-distance]:RiscvQm31{0u,0u,0u,0u};
        __syncthreads();
        prefix[local]=riscv_qm_add(prefix[local],prior);
        __syncthreads();
    }
    if(logical<rows) framework_interaction_store(values,rows,batch,physical,prefix[local]);
    if(local==255u) framework_interaction_store(block_sums,(rows+255u)/256u,batch,blockIdx.x,prefix[local]);
}
extern "C" __global__ void stwo_cuda_secure_scan_carry_v1(uint *values,const uint *block_prefixes,uint rows,uint batches,uint mapped) {
    uint logical=blockIdx.x*256u+threadIdx.x,batch=blockIdx.y;
    if(logical>=rows || batch>=batches || blockIdx.x==0u) return;
    uint physical=mapped?framework_interaction_row(logical,rows):logical;
    RiscvQm31 carry=stwo_secure_load(block_prefixes,(rows+255u)/256u,batch,blockIdx.x-1u);
    framework_interaction_store(values,rows,batch,physical,riscv_qm_add(stwo_secure_load(values,rows,batch,physical),carry));
}
extern "C" __global__ void stwo_cuda_secure_mean_v1(uint *values,uint *totals,uint rows,uint batches) {
    uint logical=blockIdx.x*256u+threadIdx.x,batch=blockIdx.y;
    if(logical>=rows || batch>=batches) return;
    // Tail is unchanged during centering (its centered value is exactly zero).
    // Save totals in a separate dispatch before mutating any row.
    RiscvQm31 total=riscv_load_qm31(totals,4u*batch);
    uint inverse=1u;
    for(uint n=rows;n>1u;n>>=1u) inverse=(inverse&1u)?(inverse+RISCV_M31_P)/2u:inverse/2u;
    uint physical=framework_interaction_row(logical,rows);
    RiscvQm31 shift=riscv_qm_mul_base(total,riscv_m31_mul(inverse,logical+1u));
    framework_interaction_store(values,rows,batch,physical,riscv_qm_sub(stwo_secure_load(values,rows,batch,physical),shift));
}
extern "C" __global__ void stwo_cuda_secure_totals_v1(const uint *values,uint *totals,uint rows,uint batches) {
    uint batch=blockIdx.x*256u+threadIdx.x;
    if(batch>=batches) return;
    RiscvQm31 total=stwo_secure_load(values,rows,batch,framework_interaction_row(rows-1u,rows));
    totals[4u*batch]=total.a;totals[4u*batch+1u]=total.b;totals[4u*batch+2u]=total.c;totals[4u*batch+3u]=total.d;
}
__device__ __forceinline__ ulong stwo_word_u64(uint lo,uint hi) { return ulong(lo)|(ulong(hi)<<32u); }
__device__ __forceinline__ void stwo_word_store(uint *out,uint rows,uint col,uint row,uint value) { out[ulong(col)*rows+row]=value; }
extern "C" __global__ void stwo_cuda_word_memory_witness_v4(
    const uint *records, const uint *claim,
    uint *output, uint *status,
    uint rows) {
    uint logical=blockIdx.x*blockDim.x+threadIdx.x;
    if(logical>=rows) return;
    uint physical=framework_interaction_row(logical,rows);
    for(uint col=0u;col<39u;++col) stwo_word_store(output,rows,col,physical,0u);
    if(logical==rows-1u) stwo_word_store(output,rows,3u,physical,1u);
    if(logical>=claim[4]) return;
    const uint *current=records+6ul*logical;
    ulong ordinal=stwo_word_u64(claim[0],claim[1])+logical;
    stwo_word_store(output,rows,0u,physical,1u);
    stwo_word_store(output,rows,1u,physical,logical==0u);
    stwo_word_store(output,rows,2u,physical,logical+1u==claim[4]);
    for(uint limb=0u;limb<4u;++limb) {
        stwo_word_store(output,rows,4u+limb,physical,uint((ordinal>>(16u*limb))&65535ul));
        if(ordinal!=0ul) stwo_word_store(output,rows,8u+limb,physical,uint(((ordinal-1ul)>>(16u*limb))&65535ul));
    }
    if(current[0]>1u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
    if(logical==0u) for(uint i=0u;i<6u;++i) if(current[i]!=claim[13u+i]) atomic_fetch_or_explicit(status,2u,memory_order_relaxed);
    if(logical+1u==claim[4]) for(uint i=0u;i<6u;++i) if(current[i]!=claim[19u+i]) atomic_fetch_or_explicit(status,2u,memory_order_relaxed);
    uint main=12u;
    stwo_word_store(output,rows,main+2u,physical,current[1]&65535u);
    stwo_word_store(output,rows,main+3u,physical,current[1]>>16u);
    stwo_word_store(output,rows,main+4u,physical,current[0]);
    ulong clock=stwo_word_u64(current[2],current[3]);
    for(uint i=0u;i<4u;++i) stwo_word_store(output,rows,main+5u+i,physical,uint((clock>>(16u*i))&65535ul));
    stwo_word_store(output,rows,main+9u,physical,current[4]&65535u);
    stwo_word_store(output,rows,main+10u,physical,current[4]>>16u);
    stwo_word_store(output,rows,main+25u,physical,current[5]&65535u);
    stwo_word_store(output,rows,main+26u,physical,current[5]>>16u);
    bool has_prior=logical!=0u || claim[6]!=0u;
    if(!has_prior) return;
    const uint *prior=logical==0u?claim+7u:records+6ul*(logical-1u);
    if(prior[0]>1u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
    bool same=prior[0]==current[0] && prior[1]==current[1];
    ulong left=same?stwo_word_u64(prior[2],prior[3]):(ulong(prior[0])<<32u)|prior[1];
    ulong right=same?clock:(ulong(current[0])<<32u)|current[1];
    if(right<=left || (same && prior[5]!=current[4])) { atomic_fetch_or_explicit(status,2u,memory_order_relaxed); return; }
    stwo_word_store(output,rows,main,physical,1u);
    stwo_word_store(output,rows,main+1u,physical,uint(same));
    ulong gap=right-left-1ul;
    uint incoming=1u,count=same?4u:3u,gap_col=same?17u:11u,carry_col=same?21u:14u;
    for(uint i=0u;i<count;++i) {
        uint difference=uint((gap>>(16u*i))&65535ul);
        incoming=(uint((left>>(16u*i))&65535ul)+difference+incoming)>>16u;
        stwo_word_store(output,rows,main+gap_col+i,physical,difference);
        stwo_word_store(output,rows,main+carry_col+i,physical,incoming);
    }
}
extern "C" __global__ void stwo_cuda_range16_witness_v4(
    const uint *multiplicities, uint *output,
    uint *status) {
    uint logical=blockIdx.x*blockDim.x+threadIdx.x;
    if(logical>=65536u) return;
    uint physical=framework_interaction_row(logical,65536u);
    uint count=multiplicities[logical];
    if(count>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
    output[physical]=logical;
    output[65536u+physical]=count;
}
