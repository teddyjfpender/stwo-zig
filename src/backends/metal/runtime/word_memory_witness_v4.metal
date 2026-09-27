// Fixed12/main27 directly from resident sorted Transition records. Inputs are
// six full u32 words: space,address,clockLo,clockHi,before,after. Claim metadata
// is independently admitted by the host, never inferred from this witness.
constant uint STWO_WORD_WITNESS_PARAMETER_WORDS=25u;
kernel void stwo_zig_range16_inverse_table_v1(device const uint *z_words [[buffer(0)]], device uint *output [[buffer(1)]], uint value [[thread_position_in_grid]]) {
    if(value>=65536u) return;
    RiscvQm31 denominator=riscv_qm_sub(RiscvQm31{value,0u,0u,0u},riscv_load_qm31(z_words,0u));
    bool pole=(denominator.a|denominator.b|denominator.c|denominator.d)==0u;
    RiscvQm31 inverse=pole?RiscvQm31{0u,0u,0u,0u}:framework_interaction_inverse(denominator);
    output[4u*value]=inverse.a;output[4u*value+1u]=inverse.b;output[4u*value+2u]=inverse.c;output[4u*value+3u]=inverse.d;
    output[262144u+value]=uint(pole);
}
inline ulong stwo_word_u64(uint lo,uint hi) { return ulong(lo)|(ulong(hi)<<32u); }
inline void stwo_word_store(device uint *out,uint rows,uint col,uint row,uint value) { out[ulong(col)*rows+row]=value; }
// Both layouts share one event witness emitter. Only the column/row routing
// differs; the full u64 integer and adjacency construction stays identical.
inline void stwo_word_emit_event(device const uint *records,device const uint *claim,
    device uint *output,device atomic_uint *status,uint rows,uint logical,
    uint physical,uint fixed,uint main,bool domain_last) {
    for(uint col=0u;col<12u;++col) stwo_word_store(output,rows,fixed+col,physical,0u);
    for(uint col=0u;col<27u;++col) stwo_word_store(output,rows,main+col,physical,0u);
    if(domain_last) stwo_word_store(output,rows,fixed+3u,physical,1u);
    if(logical>=claim[4]) return;
    const device uint *current=records+6ul*logical;
    ulong ordinal=stwo_word_u64(claim[0],claim[1])+logical;
    stwo_word_store(output,rows,fixed+0u,physical,1u);
    stwo_word_store(output,rows,fixed+1u,physical,logical==0u);
    stwo_word_store(output,rows,fixed+2u,physical,logical+1u==claim[4]);
    for(uint limb=0u;limb<4u;++limb) {
        stwo_word_store(output,rows,fixed+4u+limb,physical,uint((ordinal>>(16u*limb))&65535ul));
        if(ordinal!=0ul) stwo_word_store(output,rows,fixed+8u+limb,physical,uint(((ordinal-1ul)>>(16u*limb))&65535ul));
    }
    if(current[0]>1u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
    if(logical==0u) for(uint i=0u;i<6u;++i) if(current[i]!=claim[13u+i]) atomic_fetch_or_explicit(status,2u,memory_order_relaxed);
    if(logical+1u==claim[4]) for(uint i=0u;i<6u;++i) if(current[i]!=claim[19u+i]) atomic_fetch_or_explicit(status,2u,memory_order_relaxed);
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
    const device uint *prior=logical==0u?claim+7u:records+6ul*(logical-1u);
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
kernel void stwo_zig_word_memory_witness_v4(
    device const uint *records [[buffer(0)]], device const uint *claim [[buffer(1)]],
    device uint *output [[buffer(2)]], device atomic_uint *status [[buffer(3)]],
    constant uint &rows [[buffer(4)]], uint logical [[thread_position_in_grid]]) {
    if(logical>=rows) return;
    stwo_word_emit_event(records,claim,output,status,rows,logical,
        framework_interaction_row(logical,rows),0u,12u,logical+1u==rows);
}
kernel void stwo_zig_range16_witness_v4(
    device const uint *multiplicities [[buffer(0)]], device uint *output [[buffer(1)]],
    device atomic_uint *status [[buffer(2)]], uint logical [[thread_position_in_grid]]) {
    if(logical>=65536u) return;
    uint physical=framework_interaction_row(logical,65536u);
    uint count=multiplicities[logical];
    if(count>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
    output[physical]=logical;
    output[65536u+physical]=count;
}
