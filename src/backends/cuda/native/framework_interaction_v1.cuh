// Shared exact logical-row prefix/mean schedule. Requires unchanged framework
// field helpers. Source and every helper kind are pinned by executable IDs.
__device__ __forceinline__ uint framework_row(uint index,uint rows) {
    uint n=(index&1u)==0u?index/2u:rows-1u-index/2u;
    return __brev(n)>>(32u-uint(__ffs(rows)-1));
}
__device__ __forceinline__ RiscvQm31 framework_load(const uint *out,uint rows,uint batch,uint row) {
    return {out[(4u*batch)*ulong(rows)+row],out[(4u*batch+1u)*ulong(rows)+row],out[(4u*batch+2u)*ulong(rows)+row],out[(4u*batch+3u)*ulong(rows)+row]};
}
__device__ __forceinline__ void framework_store(uint *out,uint rows,uint batch,uint row,RiscvQm31 q) {
    out[(4u*batch)*ulong(rows)+row]=q.a;out[(4u*batch+1u)*ulong(rows)+row]=q.b;out[(4u*batch+2u)*ulong(rows)+row]=q.c;out[(4u*batch+3u)*ulong(rows)+row]=q.d;
}
__device__ __forceinline__ RiscvQm31 framework_inverse(RiscvQm31 q) { return riscv_from_q(stwo::cuda::oods::inverse(riscv_to_q(q))); }
