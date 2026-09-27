#define STWO_ZIG_AMALGAMATED
#ifndef STWO_ZIG_BASE_METAL
#define STWO_ZIG_BASE_METAL

#include <metal_stdlib>
using namespace metal;

#endif
#ifndef STWO_ZIG_M31_METAL
#define STWO_ZIG_M31_METAL

#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#endif

inline uint m31_reduce(ulong value) {
    ulong reduced = (value & 0x7ffffffful) + (value >> 31u);
    reduced = (reduced & 0x7ffffffful) + (reduced >> 31u);
    uint result = (uint)reduced;
    return result >= 0x7fffffffu ? result - 0x7fffffffu : result;
}

// Canonical operands sum to less than 2p, so addition needs no 64-bit fold.
inline uint m31_add(uint lhs, uint rhs) {
    uint sum = lhs + rhs;
    return sum >= 0x7fffffffu ? sum - 0x7fffffffu : sum;
}
inline uint m31_sub(uint lhs, uint rhs) { return lhs >= rhs ? lhs - rhs : lhs + 0x7fffffffu - rhs; }
// A product of canonical operands is below p^2. One Mersenne fold is then
// below 2p, and one conditional subtraction produces the canonical residue.
inline uint m31_mul(uint lhs, uint rhs) {
    ulong product = (ulong)lhs * rhs;
    ulong folded = (product & 0x7ffffffful) + (product >> 31u);
    uint result = (uint)folded;
    return result >= 0x7fffffffu ? result - 0x7fffffffu : result;
}
// In F_p with p = 2^31 - 1, multiplication by 2^shift rotates the 31-bit
// canonical representative. This is the normalization factor for every
// power-of-two circle IFFT.
inline uint m31_mul_pow2(uint value, uint shift) {
    shift %= 31u;
    if (shift == 0u) return value;
    return ((value << shift) & 0x7fffffffu) | (value >> (31u - shift));
}
inline uint m31_neg(uint value) { return value == 0u ? 0u : 0x7fffffffu - value; }

inline uint m31_inv(uint value) {
    uint base = value;
    uint result = 1u;
    uint exponent = 0x7ffffffdu;
    while (exponent != 0u) {
        if ((exponent & 1u) != 0u) result = m31_mul(result, base);
        base = m31_mul(base, base);
        exponent >>= 1u;
    }
    return result;
}

#endif
#ifndef STWO_ZIG_EXTENSION_FIELDS_METAL
#define STWO_ZIG_EXTENSION_FIELDS_METAL

#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#include "stwo_zig/m31.metal"
#endif

struct Cm31Value { uint a, b; };
struct Qm31Value { uint a, b, c, d; };

inline Cm31Value cm_add(Cm31Value lhs, Cm31Value rhs) {
    return { m31_add(lhs.a, rhs.a), m31_add(lhs.b, rhs.b) };
}

inline Cm31Value cm_sub(Cm31Value lhs, Cm31Value rhs) {
    return { m31_sub(lhs.a, rhs.a), m31_sub(lhs.b, rhs.b) };
}

inline Cm31Value cm_mul(Cm31Value lhs, Cm31Value rhs) {
    uint ac = m31_mul(lhs.a, rhs.a);
    uint bd = m31_mul(lhs.b, rhs.b);
    uint cross = m31_mul(m31_add(lhs.a, lhs.b), m31_add(rhs.a, rhs.b));
    return { m31_sub(ac, bd), m31_sub(m31_sub(cross, ac), bd) };
}

inline Cm31Value cm_inv(Cm31Value value) {
    uint denominator = m31_add(m31_mul(value.a, value.a), m31_mul(value.b, value.b));
    uint inverse = m31_inv(denominator);
    return { m31_mul(value.a, inverse), m31_mul(m31_neg(value.b), inverse) };
}

inline Cm31Value cm_mul_m31(Cm31Value value, uint scalar) {
    return { m31_mul(value.a, scalar), m31_mul(value.b, scalar) };
}

inline Qm31Value qm_add(Qm31Value lhs, Qm31Value rhs) {
    return { m31_add(lhs.a, rhs.a), m31_add(lhs.b, rhs.b),
             m31_add(lhs.c, rhs.c), m31_add(lhs.d, rhs.d) };
}

inline Qm31Value qm_sub(Qm31Value lhs, Qm31Value rhs) {
    return { m31_sub(lhs.a, rhs.a), m31_sub(lhs.b, rhs.b),
             m31_sub(lhs.c, rhs.c), m31_sub(lhs.d, rhs.d) };
}

inline Qm31Value qm_mul_cm(Qm31Value value, Cm31Value scalar) {
    Cm31Value c0 = cm_mul({ value.a, value.b }, scalar);
    Cm31Value c1 = cm_mul({ value.c, value.d }, scalar);
    return { c0.a, c0.b, c1.a, c1.b };
}

inline Qm31Value qm_mul_m31(Qm31Value value, uint scalar) {
    return { m31_mul(value.a, scalar), m31_mul(value.b, scalar),
             m31_mul(value.c, scalar), m31_mul(value.d, scalar) };
}

inline Cm31Value cm_mul_r(Cm31Value value) {
    return { m31_sub(m31_add(value.a, value.a), value.b),
             m31_add(value.a, m31_add(value.b, value.b)) };
}

inline Qm31Value qm_mul(Qm31Value lhs, Qm31Value rhs) {
    Cm31Value lhs0 = { lhs.a, lhs.b };
    Cm31Value lhs1 = { lhs.c, lhs.d };
    Cm31Value rhs0 = { rhs.a, rhs.b };
    Cm31Value rhs1 = { rhs.c, rhs.d };
    Cm31Value ac = cm_mul(lhs0, rhs0);
    Cm31Value bd = cm_mul(lhs1, rhs1);
    Cm31Value cross = cm_sub(cm_sub(cm_mul(cm_add(lhs0, lhs1), cm_add(rhs0, rhs1)), ac), bd);
    Cm31Value c0 = cm_add(ac, cm_mul_r(bd));
    return { c0.a, c0.b, cross.a, cross.b };
}

inline Qm31Value qm_inv(Qm31Value value) {
    Cm31Value c0 = { value.a, value.b };
    Cm31Value c1 = { value.c, value.d };
    Cm31Value denominator = cm_sub(cm_mul(c0, c0), cm_mul_r(cm_mul(c1, c1)));
    Cm31Value inverse = cm_inv(denominator);
    Cm31Value out0 = cm_mul(c0, inverse);
    Cm31Value out1 = cm_mul({ m31_neg(c1.a), m31_neg(c1.b) }, inverse);
    return { out0.a, out0.b, out1.a, out1.b };
}

#endif
#include <metal_stdlib>
using namespace metal;
constant uint RISCV_M31_P = 0x7fffffffu;
struct RiscvQm31 { uint a; uint b; uint c; uint d; };
inline uint riscv_m31_add(uint a, uint b) { uint s = a + b; return s >= RISCV_M31_P ? s - RISCV_M31_P : s; }
inline uint riscv_m31_sub(uint a, uint b) { return a >= b ? a - b : a + RISCV_M31_P - b; }
inline uint riscv_m31_mul(uint a, uint b) { ulong p = ulong(a) * b; uint f = uint((p & RISCV_M31_P) + (p >> 31)); return f >= RISCV_M31_P ? f - RISCV_M31_P : f; }
inline uint riscv_m31_neg(uint a) { return a == 0u ? 0u : RISCV_M31_P - a; }
inline ulong riscv_column_offset(uint column, uint rows, uint row) { return ulong(column) * ulong(rows) + ulong(row); }
inline RiscvQm31 riscv_qm_add(RiscvQm31 l, RiscvQm31 r) { return { riscv_m31_add(l.a,r.a), riscv_m31_add(l.b,r.b), riscv_m31_add(l.c,r.c), riscv_m31_add(l.d,r.d) }; }
inline RiscvQm31 riscv_qm_sub(RiscvQm31 l, RiscvQm31 r) { return { riscv_m31_sub(l.a,r.a), riscv_m31_sub(l.b,r.b), riscv_m31_sub(l.c,r.c), riscv_m31_sub(l.d,r.d) }; }
inline RiscvQm31 riscv_qm_mul_base(RiscvQm31 v, uint s) { return { riscv_m31_mul(v.a,s), riscv_m31_mul(v.b,s), riscv_m31_mul(v.c,s), riscv_m31_mul(v.d,s) }; }
inline RiscvQm31 riscv_qm_mul(RiscvQm31 l, RiscvQm31 r) {
    uint x0=riscv_m31_sub(riscv_m31_mul(l.a,r.a),riscv_m31_mul(l.b,r.b)), x1=riscv_m31_add(riscv_m31_mul(l.a,r.b),riscv_m31_mul(l.b,r.a));
    uint y0=riscv_m31_sub(riscv_m31_mul(l.c,r.c),riscv_m31_mul(l.d,r.d)), y1=riscv_m31_add(riscv_m31_mul(l.c,r.d),riscv_m31_mul(l.d,r.c));
    uint c0=riscv_m31_sub(riscv_m31_mul(l.a,r.c),riscv_m31_mul(l.b,r.d)), c1=riscv_m31_add(riscv_m31_mul(l.a,r.d),riscv_m31_mul(l.b,r.c));
    uint c2=riscv_m31_sub(riscv_m31_mul(l.c,r.a),riscv_m31_mul(l.d,r.b)), c3=riscv_m31_add(riscv_m31_mul(l.c,r.b),riscv_m31_mul(l.d,r.a));
    return { riscv_m31_add(x0,riscv_m31_sub(riscv_m31_add(y0,y0),y1)), riscv_m31_add(x1,riscv_m31_add(y0,riscv_m31_add(y1,y1))), riscv_m31_add(c0,c2), riscv_m31_add(c1,c3) };
}
inline RiscvQm31 riscv_load_qm31(device const uint *values, uint offset) { return { values[offset], values[offset+1u], values[offset+2u], values[offset+3u] }; }
inline RiscvQm31 riscv_load_secure_column(device const uint *columns, uint first, uint rows, uint row) { return { columns[riscv_column_offset(first+0u,rows,row)], columns[riscv_column_offset(first+1u,rows,row)], columns[riscv_column_offset(first+2u,rows,row)], columns[riscv_column_offset(first+3u,rows,row)] }; }
inline uint riscv_bit_reverse(uint value, uint bits) { return bits == 0u ? value : reverse_bits(value) >> (32u-bits); }
inline uint riscv_previous_circle_row(uint row, uint rows, uint denominator_count) {
    uint log_rows = ctz(rows), natural = riscv_bit_reverse(row, log_rows), half_rows = rows >> 1u, step = denominator_count >> 1u;
    natural = natural < half_rows ? (natural + half_rows - step) % half_rows : ((natural - half_rows + step) % half_rows) + half_rows;
    return riscv_bit_reverse(natural, log_rows);
}
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
kernel void stwo_zig_word_memory_witness_v4(
    device const uint *records [[buffer(0)]], device const uint *claim [[buffer(1)]],
    device uint *output [[buffer(2)]], device atomic_uint *status [[buffer(3)]],
    constant uint &rows [[buffer(4)]], uint logical [[thread_position_in_grid]]) {
    if(logical>=rows) return;
    uint physical=framework_interaction_row(logical,rows);
    for(uint col=0u;col<39u;++col) stwo_word_store(output,rows,col,physical,0u);
    if(logical==rows-1u) stwo_word_store(output,rows,3u,physical,1u);
    if(logical>=claim[4]) return;
    const device uint *current=records+6ul*logical;
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
kernel void stwo_zig_framework_poly_v1_4d84db166cab43ef74e2a7b694d2654aa379a63c142f598f2e8a3a17756bdefb(device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]], device const uint *tree2 [[buffer(2)]],
 device const ulong *column_offsets [[buffer(3)]], device const uint *profile_parameters [[buffer(4)]], device const uint *reserved [[buffer(5)]],
 device const uint *powers [[buffer(6)]], device uint *output [[buffer(7)]], constant uint &row_count [[buffer(8)]],
 constant uint *denominator_inverses [[buffer(9)]], constant uint &denominator_count [[buffer(10)]], uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 uint previous_row = riscv_previous_circle_row(row,row_count,denominator_count);
 RiscvQm31 v0 = { tree0[column_offsets[0u]+row],0u,0u,0u };
 RiscvQm31 v1 = { tree0[column_offsets[1u]+row],0u,0u,0u };
 RiscvQm31 v2 = { tree0[column_offsets[2u]+row],0u,0u,0u };
 RiscvQm31 v3 = { tree0[column_offsets[3u]+row],0u,0u,0u };
 RiscvQm31 v4 = { tree0[column_offsets[4u]+row],0u,0u,0u };
 RiscvQm31 v5 = { tree0[column_offsets[5u]+row],0u,0u,0u };
 RiscvQm31 v6 = { tree0[column_offsets[6u]+row],0u,0u,0u };
 RiscvQm31 v7 = { tree0[column_offsets[7u]+row],0u,0u,0u };
 RiscvQm31 v8 = { tree0[column_offsets[8u]+row],0u,0u,0u };
 RiscvQm31 v9 = { tree0[column_offsets[9u]+row],0u,0u,0u };
 RiscvQm31 v10 = { tree0[column_offsets[10u]+row],0u,0u,0u };
 RiscvQm31 v11 = { tree0[column_offsets[11u]+row],0u,0u,0u };
 RiscvQm31 v12 = { tree1[column_offsets[12u]+row],0u,0u,0u };
 RiscvQm31 v13 = { tree1[column_offsets[13u]+row],0u,0u,0u };
 RiscvQm31 v14 = { tree1[column_offsets[14u]+row],0u,0u,0u };
 RiscvQm31 v15 = { tree1[column_offsets[15u]+row],0u,0u,0u };
 RiscvQm31 v16 = { tree1[column_offsets[16u]+row],0u,0u,0u };
 RiscvQm31 v17 = { tree1[column_offsets[17u]+row],0u,0u,0u };
 RiscvQm31 v18 = { tree1[column_offsets[18u]+row],0u,0u,0u };
 RiscvQm31 v19 = { tree1[column_offsets[19u]+row],0u,0u,0u };
 RiscvQm31 v20 = { tree1[column_offsets[20u]+row],0u,0u,0u };
 RiscvQm31 v21 = { tree1[column_offsets[21u]+row],0u,0u,0u };
 RiscvQm31 v22 = { tree1[column_offsets[22u]+row],0u,0u,0u };
 RiscvQm31 v23 = { tree1[column_offsets[23u]+row],0u,0u,0u };
 RiscvQm31 v24 = { tree1[column_offsets[24u]+row],0u,0u,0u };
 RiscvQm31 v25 = { tree1[column_offsets[25u]+row],0u,0u,0u };
 RiscvQm31 v26 = { tree1[column_offsets[26u]+row],0u,0u,0u };
 RiscvQm31 v27 = { tree1[column_offsets[27u]+row],0u,0u,0u };
 RiscvQm31 v28 = { tree1[column_offsets[28u]+row],0u,0u,0u };
 RiscvQm31 v29 = { tree1[column_offsets[29u]+row],0u,0u,0u };
 RiscvQm31 v30 = { tree1[column_offsets[30u]+row],0u,0u,0u };
 RiscvQm31 v31 = { tree1[column_offsets[31u]+row],0u,0u,0u };
 RiscvQm31 v32 = { tree1[column_offsets[32u]+row],0u,0u,0u };
 RiscvQm31 v33 = { tree1[column_offsets[33u]+row],0u,0u,0u };
 RiscvQm31 v34 = { tree1[column_offsets[34u]+row],0u,0u,0u };
 RiscvQm31 v35 = { tree1[column_offsets[35u]+row],0u,0u,0u };
 RiscvQm31 v36 = { tree1[column_offsets[36u]+row],0u,0u,0u };
 RiscvQm31 v37 = { tree1[column_offsets[37u]+row],0u,0u,0u };
 RiscvQm31 v38 = { tree1[column_offsets[38u]+row],0u,0u,0u };
 RiscvQm31 v39 = { tree1[column_offsets[39u]+previous_row],0u,0u,0u };
 RiscvQm31 v40 = { tree1[column_offsets[40u]+previous_row],0u,0u,0u };
 RiscvQm31 v41 = { tree1[column_offsets[41u]+previous_row],0u,0u,0u };
 RiscvQm31 v42 = { tree1[column_offsets[42u]+previous_row],0u,0u,0u };
 RiscvQm31 v43 = { tree1[column_offsets[43u]+previous_row],0u,0u,0u };
 RiscvQm31 v44 = { tree1[column_offsets[44u]+previous_row],0u,0u,0u };
 RiscvQm31 v45 = { tree1[column_offsets[45u]+previous_row],0u,0u,0u };
 RiscvQm31 v46 = { tree1[column_offsets[46u]+previous_row],0u,0u,0u };
 RiscvQm31 v47 = { tree1[column_offsets[47u]+previous_row],0u,0u,0u };
 RiscvQm31 v48 = { tree2[column_offsets[48u]+row],0u,0u,0u };
 RiscvQm31 v49 = { tree2[column_offsets[49u]+row],0u,0u,0u };
 RiscvQm31 v50 = { tree2[column_offsets[50u]+row],0u,0u,0u };
 RiscvQm31 v51 = { tree2[column_offsets[51u]+row],0u,0u,0u };
 RiscvQm31 v52 = { tree2[column_offsets[52u]+row],0u,0u,0u };
 RiscvQm31 v53 = { tree2[column_offsets[53u]+row],0u,0u,0u };
 RiscvQm31 v54 = { tree2[column_offsets[54u]+row],0u,0u,0u };
 RiscvQm31 v55 = { tree2[column_offsets[55u]+row],0u,0u,0u };
 RiscvQm31 v56 = { tree2[column_offsets[56u]+row],0u,0u,0u };
 RiscvQm31 v57 = { tree2[column_offsets[57u]+row],0u,0u,0u };
 RiscvQm31 v58 = { tree2[column_offsets[58u]+row],0u,0u,0u };
 RiscvQm31 v59 = { tree2[column_offsets[59u]+row],0u,0u,0u };
 RiscvQm31 v60 = { tree2[column_offsets[60u]+row],0u,0u,0u };
 RiscvQm31 v61 = { tree2[column_offsets[61u]+row],0u,0u,0u };
 RiscvQm31 v62 = { tree2[column_offsets[62u]+row],0u,0u,0u };
 RiscvQm31 v63 = { tree2[column_offsets[63u]+row],0u,0u,0u };
 RiscvQm31 v64 = { tree2[column_offsets[64u]+row],0u,0u,0u };
 RiscvQm31 v65 = { tree2[column_offsets[65u]+row],0u,0u,0u };
 RiscvQm31 v66 = { tree2[column_offsets[66u]+row],0u,0u,0u };
 RiscvQm31 v67 = { tree2[column_offsets[67u]+row],0u,0u,0u };
 RiscvQm31 v68 = { tree2[column_offsets[68u]+row],0u,0u,0u };
 RiscvQm31 v69 = { tree2[column_offsets[69u]+row],0u,0u,0u };
 RiscvQm31 v70 = { tree2[column_offsets[70u]+row],0u,0u,0u };
 RiscvQm31 v71 = { tree2[column_offsets[71u]+row],0u,0u,0u };
 RiscvQm31 v72 = { tree2[column_offsets[72u]+row],0u,0u,0u };
 RiscvQm31 v73 = { tree2[column_offsets[73u]+row],0u,0u,0u };
 RiscvQm31 v74 = { tree2[column_offsets[74u]+row],0u,0u,0u };
 RiscvQm31 v75 = { tree2[column_offsets[75u]+row],0u,0u,0u };
 RiscvQm31 v76 = { tree2[column_offsets[76u]+row],0u,0u,0u };
 RiscvQm31 v77 = { tree2[column_offsets[77u]+row],0u,0u,0u };
 RiscvQm31 v78 = { tree2[column_offsets[78u]+row],0u,0u,0u };
 RiscvQm31 v79 = { tree2[column_offsets[79u]+row],0u,0u,0u };
 RiscvQm31 v80 = { tree2[column_offsets[80u]+row],0u,0u,0u };
 RiscvQm31 v81 = { tree2[column_offsets[81u]+row],0u,0u,0u };
 RiscvQm31 v82 = { tree2[column_offsets[82u]+row],0u,0u,0u };
 RiscvQm31 v83 = { tree2[column_offsets[83u]+row],0u,0u,0u };
 RiscvQm31 v84 = { tree2[column_offsets[84u]+row],0u,0u,0u };
 RiscvQm31 v85 = { tree2[column_offsets[85u]+row],0u,0u,0u };
 RiscvQm31 v86 = { tree2[column_offsets[86u]+row],0u,0u,0u };
 RiscvQm31 v87 = { tree2[column_offsets[87u]+row],0u,0u,0u };
 RiscvQm31 v88 = { tree2[column_offsets[88u]+row],0u,0u,0u };
 RiscvQm31 v89 = { tree2[column_offsets[89u]+row],0u,0u,0u };
 RiscvQm31 v90 = { tree2[column_offsets[90u]+row],0u,0u,0u };
 RiscvQm31 v91 = { tree2[column_offsets[91u]+row],0u,0u,0u };
 RiscvQm31 v92 = { tree2[column_offsets[92u]+row],0u,0u,0u };
 RiscvQm31 v93 = { tree2[column_offsets[93u]+row],0u,0u,0u };
 RiscvQm31 v94 = { tree2[column_offsets[94u]+row],0u,0u,0u };
 RiscvQm31 v95 = { tree2[column_offsets[95u]+row],0u,0u,0u };
 RiscvQm31 v96 = { tree2[column_offsets[96u]+row],0u,0u,0u };
 RiscvQm31 v97 = { tree2[column_offsets[97u]+row],0u,0u,0u };
 RiscvQm31 v98 = { tree2[column_offsets[98u]+row],0u,0u,0u };
 RiscvQm31 v99 = { tree2[column_offsets[99u]+row],0u,0u,0u };
 RiscvQm31 v100 = { tree2[column_offsets[100u]+row],0u,0u,0u };
 RiscvQm31 v101 = { tree2[column_offsets[101u]+row],0u,0u,0u };
 RiscvQm31 v102 = { tree2[column_offsets[102u]+row],0u,0u,0u };
 RiscvQm31 v103 = { tree2[column_offsets[103u]+row],0u,0u,0u };
 RiscvQm31 v104 = { tree2[column_offsets[104u]+row],0u,0u,0u };
 RiscvQm31 v105 = { tree2[column_offsets[105u]+row],0u,0u,0u };
 RiscvQm31 v106 = { tree2[column_offsets[106u]+row],0u,0u,0u };
 RiscvQm31 v107 = { tree2[column_offsets[107u]+row],0u,0u,0u };
 RiscvQm31 v108 = { tree2[column_offsets[108u]+row],0u,0u,0u };
 RiscvQm31 v109 = { tree2[column_offsets[109u]+row],0u,0u,0u };
 RiscvQm31 v110 = { tree2[column_offsets[110u]+row],0u,0u,0u };
 RiscvQm31 v111 = { tree2[column_offsets[111u]+row],0u,0u,0u };
 RiscvQm31 v112 = { tree2[column_offsets[112u]+row],0u,0u,0u };
 RiscvQm31 v113 = { tree2[column_offsets[113u]+row],0u,0u,0u };
 RiscvQm31 v114 = { tree2[column_offsets[114u]+row],0u,0u,0u };
 RiscvQm31 v115 = { tree2[column_offsets[115u]+row],0u,0u,0u };
 RiscvQm31 v116 = { tree2[column_offsets[116u]+previous_row],0u,0u,0u };
 RiscvQm31 v117 = { tree2[column_offsets[117u]+previous_row],0u,0u,0u };
 RiscvQm31 v118 = { tree2[column_offsets[118u]+previous_row],0u,0u,0u };
 RiscvQm31 v119 = { tree2[column_offsets[119u]+previous_row],0u,0u,0u };
 RiscvQm31 v120 = { tree2[column_offsets[120u]+previous_row],0u,0u,0u };
 RiscvQm31 v121 = { tree2[column_offsets[121u]+previous_row],0u,0u,0u };
 RiscvQm31 v122 = { tree2[column_offsets[122u]+previous_row],0u,0u,0u };
 RiscvQm31 v123 = { tree2[column_offsets[123u]+previous_row],0u,0u,0u };
 RiscvQm31 v124 = { tree2[column_offsets[124u]+previous_row],0u,0u,0u };
 RiscvQm31 v125 = { tree2[column_offsets[125u]+previous_row],0u,0u,0u };
 RiscvQm31 v126 = { tree2[column_offsets[126u]+previous_row],0u,0u,0u };
 RiscvQm31 v127 = { tree2[column_offsets[127u]+previous_row],0u,0u,0u };
 RiscvQm31 v128 = { tree2[column_offsets[128u]+previous_row],0u,0u,0u };
 RiscvQm31 v129 = { tree2[column_offsets[129u]+previous_row],0u,0u,0u };
 RiscvQm31 v130 = { tree2[column_offsets[130u]+previous_row],0u,0u,0u };
 RiscvQm31 v131 = { tree2[column_offsets[131u]+previous_row],0u,0u,0u };
 RiscvQm31 v132 = { tree2[column_offsets[132u]+previous_row],0u,0u,0u };
 RiscvQm31 v133 = { tree2[column_offsets[133u]+previous_row],0u,0u,0u };
 RiscvQm31 v134 = { tree2[column_offsets[134u]+previous_row],0u,0u,0u };
 RiscvQm31 v135 = { tree2[column_offsets[135u]+previous_row],0u,0u,0u };
 RiscvQm31 v136 = { tree2[column_offsets[136u]+previous_row],0u,0u,0u };
 RiscvQm31 v137 = { tree2[column_offsets[137u]+previous_row],0u,0u,0u };
 RiscvQm31 v138 = { tree2[column_offsets[138u]+previous_row],0u,0u,0u };
 RiscvQm31 v139 = { tree2[column_offsets[139u]+previous_row],0u,0u,0u };
 RiscvQm31 v140 = { tree2[column_offsets[140u]+previous_row],0u,0u,0u };
 RiscvQm31 v141 = { tree2[column_offsets[141u]+previous_row],0u,0u,0u };
 RiscvQm31 v142 = { tree2[column_offsets[142u]+previous_row],0u,0u,0u };
 RiscvQm31 v143 = { tree2[column_offsets[143u]+previous_row],0u,0u,0u };
 RiscvQm31 v144 = { tree2[column_offsets[144u]+previous_row],0u,0u,0u };
 RiscvQm31 v145 = { tree2[column_offsets[145u]+previous_row],0u,0u,0u };
 RiscvQm31 v146 = { tree2[column_offsets[146u]+previous_row],0u,0u,0u };
 RiscvQm31 v147 = { tree2[column_offsets[147u]+previous_row],0u,0u,0u };
 RiscvQm31 v148 = { tree2[column_offsets[148u]+previous_row],0u,0u,0u };
 RiscvQm31 v149 = { tree2[column_offsets[149u]+previous_row],0u,0u,0u };
 RiscvQm31 v150 = { tree2[column_offsets[150u]+previous_row],0u,0u,0u };
 RiscvQm31 v151 = { tree2[column_offsets[151u]+previous_row],0u,0u,0u };
 RiscvQm31 v152 = { tree2[column_offsets[152u]+previous_row],0u,0u,0u };
 RiscvQm31 v153 = { tree2[column_offsets[153u]+previous_row],0u,0u,0u };
 RiscvQm31 v154 = { tree2[column_offsets[154u]+previous_row],0u,0u,0u };
 RiscvQm31 v155 = { tree2[column_offsets[155u]+previous_row],0u,0u,0u };
 RiscvQm31 v156 = { tree2[column_offsets[156u]+previous_row],0u,0u,0u };
 RiscvQm31 v157 = { tree2[column_offsets[157u]+previous_row],0u,0u,0u };
 RiscvQm31 v158 = { tree2[column_offsets[158u]+previous_row],0u,0u,0u };
 RiscvQm31 v159 = { tree2[column_offsets[159u]+previous_row],0u,0u,0u };
 RiscvQm31 v160 = { tree2[column_offsets[160u]+previous_row],0u,0u,0u };
 RiscvQm31 v161 = { tree2[column_offsets[161u]+previous_row],0u,0u,0u };
 RiscvQm31 v162 = { tree2[column_offsets[162u]+previous_row],0u,0u,0u };
 RiscvQm31 v163 = { tree2[column_offsets[163u]+previous_row],0u,0u,0u };
 RiscvQm31 v164 = { tree2[column_offsets[164u]+previous_row],0u,0u,0u };
 RiscvQm31 v165 = { tree2[column_offsets[165u]+previous_row],0u,0u,0u };
 RiscvQm31 v166 = { tree2[column_offsets[166u]+previous_row],0u,0u,0u };
 RiscvQm31 v167 = { tree2[column_offsets[167u]+previous_row],0u,0u,0u };
 RiscvQm31 v168 = { tree2[column_offsets[168u]+previous_row],0u,0u,0u };
 RiscvQm31 v169 = { tree2[column_offsets[169u]+previous_row],0u,0u,0u };
 RiscvQm31 v170 = { tree2[column_offsets[170u]+previous_row],0u,0u,0u };
 RiscvQm31 v171 = { tree2[column_offsets[171u]+previous_row],0u,0u,0u };
 RiscvQm31 v172 = { tree2[column_offsets[172u]+previous_row],0u,0u,0u };
 RiscvQm31 v173 = { tree2[column_offsets[173u]+previous_row],0u,0u,0u };
 RiscvQm31 v174 = { tree2[column_offsets[174u]+previous_row],0u,0u,0u };
 RiscvQm31 v175 = { tree2[column_offsets[175u]+previous_row],0u,0u,0u };
 RiscvQm31 v176 = { tree2[column_offsets[176u]+previous_row],0u,0u,0u };
 RiscvQm31 v177 = { tree2[column_offsets[177u]+previous_row],0u,0u,0u };
 RiscvQm31 v178 = { tree2[column_offsets[178u]+previous_row],0u,0u,0u };
 RiscvQm31 v179 = { tree2[column_offsets[179u]+previous_row],0u,0u,0u };
 RiscvQm31 v180 = { tree2[column_offsets[180u]+previous_row],0u,0u,0u };
 RiscvQm31 v181 = { tree2[column_offsets[181u]+previous_row],0u,0u,0u };
 RiscvQm31 v182 = { tree2[column_offsets[182u]+previous_row],0u,0u,0u };
 RiscvQm31 v183 = { tree2[column_offsets[183u]+previous_row],0u,0u,0u };
 RiscvQm31 v184 = riscv_qm_sub(v0,v1);
 RiscvQm31 v185 = riscv_qm_sub(v12,v184);
 RiscvQm31 v186 = { 1u,0u,0u,0u };
 RiscvQm31 v187 = riscv_qm_sub(v13,v186);
 RiscvQm31 v188 = riscv_qm_mul(v13,v187);
 RiscvQm31 v189 = riscv_qm_mul(v12,v188);
 RiscvQm31 v190 = { 1u,0u,0u,0u };
 RiscvQm31 v191 = riscv_qm_sub(v16,v190);
 RiscvQm31 v192 = riscv_qm_mul(v16,v191);
 RiscvQm31 v193 = riscv_qm_mul(v0,v192);
 RiscvQm31 v194 = { 1u,0u,0u,0u };
 RiscvQm31 v195 = riscv_qm_sub(v26,v194);
 RiscvQm31 v196 = riscv_qm_mul(v26,v195);
 RiscvQm31 v197 = riscv_qm_mul(v12,v196);
 RiscvQm31 v198 = { 1u,0u,0u,0u };
 RiscvQm31 v199 = riscv_qm_sub(v27,v198);
 RiscvQm31 v200 = riscv_qm_mul(v27,v199);
 RiscvQm31 v201 = riscv_qm_mul(v12,v200);
 RiscvQm31 v202 = { 1u,0u,0u,0u };
 RiscvQm31 v203 = riscv_qm_sub(v28,v202);
 RiscvQm31 v204 = riscv_qm_mul(v28,v203);
 RiscvQm31 v205 = riscv_qm_mul(v12,v204);
 RiscvQm31 v206 = { 1u,0u,0u,0u };
 RiscvQm31 v207 = riscv_qm_sub(v33,v206);
 RiscvQm31 v208 = riscv_qm_mul(v33,v207);
 RiscvQm31 v209 = riscv_qm_mul(v12,v208);
 RiscvQm31 v210 = { 1u,0u,0u,0u };
 RiscvQm31 v211 = riscv_qm_sub(v34,v210);
 RiscvQm31 v212 = riscv_qm_mul(v34,v211);
 RiscvQm31 v213 = riscv_qm_mul(v12,v212);
 RiscvQm31 v214 = { 1u,0u,0u,0u };
 RiscvQm31 v215 = riscv_qm_sub(v35,v214);
 RiscvQm31 v216 = riscv_qm_mul(v35,v215);
 RiscvQm31 v217 = riscv_qm_mul(v12,v216);
 RiscvQm31 v218 = { 1u,0u,0u,0u };
 RiscvQm31 v219 = riscv_qm_sub(v36,v218);
 RiscvQm31 v220 = riscv_qm_mul(v36,v219);
 RiscvQm31 v221 = riscv_qm_mul(v12,v220);
 RiscvQm31 v222 = riscv_load_qm31(profile_parameters,0u);
 RiscvQm31 v223 = riscv_qm_sub(v222,v41);
 RiscvQm31 v224 = riscv_qm_mul(v1,v223);
 RiscvQm31 v225 = riscv_qm_add(v41,v224);
 RiscvQm31 v226 = riscv_load_qm31(profile_parameters,4u);
 RiscvQm31 v227 = riscv_qm_sub(v226,v39);
 RiscvQm31 v228 = riscv_qm_mul(v1,v227);
 RiscvQm31 v229 = riscv_qm_add(v39,v228);
 RiscvQm31 v230 = riscv_load_qm31(profile_parameters,8u);
 RiscvQm31 v231 = riscv_qm_sub(v230,v40);
 RiscvQm31 v232 = riscv_qm_mul(v1,v231);
 RiscvQm31 v233 = riscv_qm_add(v40,v232);
 RiscvQm31 v234 = riscv_load_qm31(profile_parameters,12u);
 RiscvQm31 v235 = riscv_qm_sub(v234,v42);
 RiscvQm31 v236 = riscv_qm_mul(v1,v235);
 RiscvQm31 v237 = riscv_qm_add(v42,v236);
 RiscvQm31 v238 = riscv_load_qm31(profile_parameters,16u);
 RiscvQm31 v239 = riscv_qm_sub(v238,v43);
 RiscvQm31 v240 = riscv_qm_mul(v1,v239);
 RiscvQm31 v241 = riscv_qm_add(v43,v240);
 RiscvQm31 v242 = riscv_load_qm31(profile_parameters,20u);
 RiscvQm31 v243 = riscv_qm_sub(v242,v44);
 RiscvQm31 v244 = riscv_qm_mul(v1,v243);
 RiscvQm31 v245 = riscv_qm_add(v44,v244);
 RiscvQm31 v246 = riscv_load_qm31(profile_parameters,24u);
 RiscvQm31 v247 = riscv_qm_sub(v246,v45);
 RiscvQm31 v248 = riscv_qm_mul(v1,v247);
 RiscvQm31 v249 = riscv_qm_add(v45,v248);
 RiscvQm31 v250 = riscv_load_qm31(profile_parameters,28u);
 RiscvQm31 v251 = riscv_qm_sub(v250,v46);
 RiscvQm31 v252 = riscv_qm_mul(v1,v251);
 RiscvQm31 v253 = riscv_qm_add(v46,v252);
 RiscvQm31 v254 = riscv_load_qm31(profile_parameters,32u);
 RiscvQm31 v255 = riscv_qm_sub(v254,v47);
 RiscvQm31 v256 = riscv_qm_mul(v1,v255);
 RiscvQm31 v257 = riscv_qm_add(v47,v256);
 RiscvQm31 v258 = riscv_qm_mul(v12,v13);
 RiscvQm31 v259 = riscv_qm_sub(v229,v14);
 RiscvQm31 v260 = riscv_qm_mul(v258,v259);
 RiscvQm31 v261 = riscv_qm_mul(v12,v13);
 RiscvQm31 v262 = riscv_qm_sub(v233,v15);
 RiscvQm31 v263 = riscv_qm_mul(v261,v262);
 RiscvQm31 v264 = riscv_qm_mul(v12,v13);
 RiscvQm31 v265 = riscv_qm_sub(v225,v16);
 RiscvQm31 v266 = riscv_qm_mul(v264,v265);
 RiscvQm31 v267 = riscv_qm_mul(v12,v13);
 RiscvQm31 v268 = riscv_qm_sub(v253,v21);
 RiscvQm31 v269 = riscv_qm_mul(v267,v268);
 RiscvQm31 v270 = riscv_qm_mul(v12,v13);
 RiscvQm31 v271 = riscv_qm_sub(v257,v22);
 RiscvQm31 v272 = riscv_qm_mul(v270,v271);
 RiscvQm31 v273 = { 1u,0u,0u,0u };
 RiscvQm31 v274 = riscv_qm_sub(v273,v13);
 RiscvQm31 v275 = riscv_qm_mul(v12,v274);
 RiscvQm31 v276 = riscv_qm_add(v229,v23);
 RiscvQm31 v277 = { 1u,0u,0u,0u };
 RiscvQm31 v278 = riscv_qm_add(v276,v277);
 RiscvQm31 v279 = riscv_qm_sub(v278,v14);
 RiscvQm31 v280 = riscv_load_qm31(profile_parameters,36u);
 RiscvQm31 v281 = riscv_qm_mul(v280,v26);
 RiscvQm31 v282 = riscv_qm_sub(v279,v281);
 RiscvQm31 v283 = riscv_qm_mul(v275,v282);
 RiscvQm31 v284 = riscv_qm_add(v233,v24);
 RiscvQm31 v285 = riscv_qm_add(v284,v26);
 RiscvQm31 v286 = riscv_qm_sub(v285,v15);
 RiscvQm31 v287 = riscv_load_qm31(profile_parameters,40u);
 RiscvQm31 v288 = riscv_qm_mul(v287,v27);
 RiscvQm31 v289 = riscv_qm_sub(v286,v288);
 RiscvQm31 v290 = riscv_qm_mul(v275,v289);
 RiscvQm31 v291 = riscv_qm_add(v225,v25);
 RiscvQm31 v292 = riscv_qm_add(v291,v27);
 RiscvQm31 v293 = riscv_qm_sub(v292,v16);
 RiscvQm31 v294 = riscv_load_qm31(profile_parameters,44u);
 RiscvQm31 v295 = riscv_qm_mul(v294,v28);
 RiscvQm31 v296 = riscv_qm_sub(v293,v295);
 RiscvQm31 v297 = riscv_qm_mul(v275,v296);
 RiscvQm31 v298 = riscv_qm_mul(v275,v28);
 RiscvQm31 v299 = riscv_qm_mul(v12,v13);
 RiscvQm31 v300 = riscv_qm_add(v237,v29);
 RiscvQm31 v301 = { 1u,0u,0u,0u };
 RiscvQm31 v302 = riscv_qm_add(v300,v301);
 RiscvQm31 v303 = riscv_qm_sub(v302,v17);
 RiscvQm31 v304 = riscv_load_qm31(profile_parameters,48u);
 RiscvQm31 v305 = riscv_qm_mul(v304,v33);
 RiscvQm31 v306 = riscv_qm_sub(v303,v305);
 RiscvQm31 v307 = riscv_qm_mul(v299,v306);
 RiscvQm31 v308 = riscv_qm_add(v241,v30);
 RiscvQm31 v309 = riscv_qm_add(v308,v33);
 RiscvQm31 v310 = riscv_qm_sub(v309,v18);
 RiscvQm31 v311 = riscv_load_qm31(profile_parameters,52u);
 RiscvQm31 v312 = riscv_qm_mul(v311,v34);
 RiscvQm31 v313 = riscv_qm_sub(v310,v312);
 RiscvQm31 v314 = riscv_qm_mul(v299,v313);
 RiscvQm31 v315 = riscv_qm_add(v245,v31);
 RiscvQm31 v316 = riscv_qm_add(v315,v34);
 RiscvQm31 v317 = riscv_qm_sub(v316,v19);
 RiscvQm31 v318 = riscv_load_qm31(profile_parameters,56u);
 RiscvQm31 v319 = riscv_qm_mul(v318,v35);
 RiscvQm31 v320 = riscv_qm_sub(v317,v319);
 RiscvQm31 v321 = riscv_qm_mul(v299,v320);
 RiscvQm31 v322 = riscv_qm_add(v249,v32);
 RiscvQm31 v323 = riscv_qm_add(v322,v35);
 RiscvQm31 v324 = riscv_qm_sub(v323,v20);
 RiscvQm31 v325 = riscv_load_qm31(profile_parameters,60u);
 RiscvQm31 v326 = riscv_qm_mul(v325,v36);
 RiscvQm31 v327 = riscv_qm_sub(v324,v326);
 RiscvQm31 v328 = riscv_qm_mul(v299,v327);
 RiscvQm31 v329 = riscv_qm_mul(v299,v36);
 RiscvQm31 v330 = riscv_load_qm31(profile_parameters,64u);
 RiscvQm31 v331 = riscv_qm_sub(v16,v330);
 RiscvQm31 v332 = riscv_qm_mul(v1,v331);
 RiscvQm31 v333 = riscv_load_qm31(profile_parameters,68u);
 RiscvQm31 v334 = riscv_qm_sub(v14,v333);
 RiscvQm31 v335 = riscv_qm_mul(v1,v334);
 RiscvQm31 v336 = riscv_load_qm31(profile_parameters,72u);
 RiscvQm31 v337 = riscv_qm_sub(v15,v336);
 RiscvQm31 v338 = riscv_qm_mul(v1,v337);
 RiscvQm31 v339 = riscv_load_qm31(profile_parameters,76u);
 RiscvQm31 v340 = riscv_qm_sub(v17,v339);
 RiscvQm31 v341 = riscv_qm_mul(v1,v340);
 RiscvQm31 v342 = riscv_load_qm31(profile_parameters,80u);
 RiscvQm31 v343 = riscv_qm_sub(v18,v342);
 RiscvQm31 v344 = riscv_qm_mul(v1,v343);
 RiscvQm31 v345 = riscv_load_qm31(profile_parameters,84u);
 RiscvQm31 v346 = riscv_qm_sub(v19,v345);
 RiscvQm31 v347 = riscv_qm_mul(v1,v346);
 RiscvQm31 v348 = riscv_load_qm31(profile_parameters,88u);
 RiscvQm31 v349 = riscv_qm_sub(v20,v348);
 RiscvQm31 v350 = riscv_qm_mul(v1,v349);
 RiscvQm31 v351 = riscv_load_qm31(profile_parameters,92u);
 RiscvQm31 v352 = riscv_qm_sub(v21,v351);
 RiscvQm31 v353 = riscv_qm_mul(v1,v352);
 RiscvQm31 v354 = riscv_load_qm31(profile_parameters,96u);
 RiscvQm31 v355 = riscv_qm_sub(v22,v354);
 RiscvQm31 v356 = riscv_qm_mul(v1,v355);
 RiscvQm31 v357 = riscv_load_qm31(profile_parameters,100u);
 RiscvQm31 v358 = riscv_qm_sub(v37,v357);
 RiscvQm31 v359 = riscv_qm_mul(v1,v358);
 RiscvQm31 v360 = riscv_load_qm31(profile_parameters,104u);
 RiscvQm31 v361 = riscv_qm_sub(v38,v360);
 RiscvQm31 v362 = riscv_qm_mul(v1,v361);
 RiscvQm31 v363 = riscv_load_qm31(profile_parameters,108u);
 RiscvQm31 v364 = riscv_qm_sub(v16,v363);
 RiscvQm31 v365 = riscv_qm_mul(v2,v364);
 RiscvQm31 v366 = riscv_load_qm31(profile_parameters,112u);
 RiscvQm31 v367 = riscv_qm_sub(v14,v366);
 RiscvQm31 v368 = riscv_qm_mul(v2,v367);
 RiscvQm31 v369 = riscv_load_qm31(profile_parameters,116u);
 RiscvQm31 v370 = riscv_qm_sub(v15,v369);
 RiscvQm31 v371 = riscv_qm_mul(v2,v370);
 RiscvQm31 v372 = riscv_load_qm31(profile_parameters,120u);
 RiscvQm31 v373 = riscv_qm_sub(v17,v372);
 RiscvQm31 v374 = riscv_qm_mul(v2,v373);
 RiscvQm31 v375 = riscv_load_qm31(profile_parameters,124u);
 RiscvQm31 v376 = riscv_qm_sub(v18,v375);
 RiscvQm31 v377 = riscv_qm_mul(v2,v376);
 RiscvQm31 v378 = riscv_load_qm31(profile_parameters,128u);
 RiscvQm31 v379 = riscv_qm_sub(v19,v378);
 RiscvQm31 v380 = riscv_qm_mul(v2,v379);
 RiscvQm31 v381 = riscv_load_qm31(profile_parameters,132u);
 RiscvQm31 v382 = riscv_qm_sub(v20,v381);
 RiscvQm31 v383 = riscv_qm_mul(v2,v382);
 RiscvQm31 v384 = riscv_load_qm31(profile_parameters,136u);
 RiscvQm31 v385 = riscv_qm_sub(v21,v384);
 RiscvQm31 v386 = riscv_qm_mul(v2,v385);
 RiscvQm31 v387 = riscv_load_qm31(profile_parameters,140u);
 RiscvQm31 v388 = riscv_qm_sub(v22,v387);
 RiscvQm31 v389 = riscv_qm_mul(v2,v388);
 RiscvQm31 v390 = riscv_load_qm31(profile_parameters,144u);
 RiscvQm31 v391 = riscv_qm_sub(v37,v390);
 RiscvQm31 v392 = riscv_qm_mul(v2,v391);
 RiscvQm31 v393 = riscv_load_qm31(profile_parameters,148u);
 RiscvQm31 v394 = riscv_qm_sub(v38,v393);
 RiscvQm31 v395 = riscv_qm_mul(v2,v394);
 RiscvQm31 v396 = { 1u,0u,0u,0u };
 RiscvQm31 v397 = riscv_qm_sub(v396,v13);
 RiscvQm31 v398 = riscv_qm_mul(v12,v397);
 RiscvQm31 v399 = { 1u,0u,0u,0u };
 RiscvQm31 v400 = riscv_qm_sub(v399,v13);
 RiscvQm31 v401 = riscv_qm_mul(v12,v400);
 RiscvQm31 v402 = { 1u,0u,0u,0u };
 RiscvQm31 v403 = riscv_qm_sub(v402,v13);
 RiscvQm31 v404 = riscv_qm_mul(v12,v403);
 RiscvQm31 v405 = riscv_qm_mul(v12,v13);
 RiscvQm31 v406 = riscv_qm_mul(v12,v13);
 RiscvQm31 v407 = riscv_qm_mul(v12,v13);
 RiscvQm31 v408 = riscv_qm_mul(v12,v13);
 RiscvQm31 v409 = riscv_load_qm31(profile_parameters,152u);
 RiscvQm31 v410 = riscv_qm_sub(v409,v41);
 RiscvQm31 v411 = riscv_qm_mul(v1,v410);
 RiscvQm31 v412 = riscv_qm_add(v41,v411);
 RiscvQm31 v413 = riscv_load_qm31(profile_parameters,156u);
 RiscvQm31 v414 = riscv_qm_sub(v413,v39);
 RiscvQm31 v415 = riscv_qm_mul(v1,v414);
 RiscvQm31 v416 = riscv_qm_add(v39,v415);
 RiscvQm31 v417 = riscv_load_qm31(profile_parameters,160u);
 RiscvQm31 v418 = riscv_qm_sub(v417,v40);
 RiscvQm31 v419 = riscv_qm_mul(v1,v418);
 RiscvQm31 v420 = riscv_qm_add(v40,v419);
 RiscvQm31 v421 = riscv_load_qm31(profile_parameters,164u);
 RiscvQm31 v422 = riscv_qm_sub(v421,v42);
 RiscvQm31 v423 = riscv_qm_mul(v1,v422);
 RiscvQm31 v424 = riscv_qm_add(v42,v423);
 RiscvQm31 v425 = riscv_load_qm31(profile_parameters,168u);
 RiscvQm31 v426 = riscv_qm_sub(v425,v43);
 RiscvQm31 v427 = riscv_qm_mul(v1,v426);
 RiscvQm31 v428 = riscv_qm_add(v43,v427);
 RiscvQm31 v429 = riscv_load_qm31(profile_parameters,172u);
 RiscvQm31 v430 = riscv_qm_sub(v429,v44);
 RiscvQm31 v431 = riscv_qm_mul(v1,v430);
 RiscvQm31 v432 = riscv_qm_add(v44,v431);
 RiscvQm31 v433 = riscv_load_qm31(profile_parameters,176u);
 RiscvQm31 v434 = riscv_qm_sub(v433,v45);
 RiscvQm31 v435 = riscv_qm_mul(v1,v434);
 RiscvQm31 v436 = riscv_qm_add(v45,v435);
 RiscvQm31 v437 = riscv_load_qm31(profile_parameters,180u);
 RiscvQm31 v438 = riscv_qm_sub(v437,v46);
 RiscvQm31 v439 = riscv_qm_mul(v1,v438);
 RiscvQm31 v440 = riscv_qm_add(v46,v439);
 RiscvQm31 v441 = riscv_load_qm31(profile_parameters,184u);
 RiscvQm31 v442 = riscv_qm_sub(v441,v47);
 RiscvQm31 v443 = riscv_qm_mul(v1,v442);
 RiscvQm31 v444 = riscv_qm_add(v47,v443);
 RiscvQm31 v445 = riscv_load_qm31(profile_parameters,188u);
 RiscvQm31 v446 = riscv_qm_mul(v445,v16);
 RiscvQm31 v447 = { 0u,0u,0u,0u };
 RiscvQm31 v448 = riscv_qm_add(v447,v446);
 RiscvQm31 v449 = riscv_load_qm31(profile_parameters,192u);
 RiscvQm31 v450 = riscv_qm_mul(v449,v14);
 RiscvQm31 v451 = riscv_qm_add(v448,v450);
 RiscvQm31 v452 = riscv_load_qm31(profile_parameters,196u);
 RiscvQm31 v453 = riscv_qm_mul(v452,v15);
 RiscvQm31 v454 = riscv_qm_add(v451,v453);
 RiscvQm31 v455 = riscv_load_qm31(profile_parameters,200u);
 RiscvQm31 v456 = riscv_qm_mul(v455,v17);
 RiscvQm31 v457 = riscv_qm_add(v454,v456);
 RiscvQm31 v458 = riscv_load_qm31(profile_parameters,204u);
 RiscvQm31 v459 = riscv_qm_mul(v458,v18);
 RiscvQm31 v460 = riscv_qm_add(v457,v459);
 RiscvQm31 v461 = riscv_load_qm31(profile_parameters,208u);
 RiscvQm31 v462 = riscv_qm_mul(v461,v19);
 RiscvQm31 v463 = riscv_qm_add(v460,v462);
 RiscvQm31 v464 = riscv_load_qm31(profile_parameters,212u);
 RiscvQm31 v465 = riscv_qm_mul(v464,v20);
 RiscvQm31 v466 = riscv_qm_add(v463,v465);
 RiscvQm31 v467 = riscv_load_qm31(profile_parameters,216u);
 RiscvQm31 v468 = riscv_qm_mul(v467,v21);
 RiscvQm31 v469 = riscv_qm_add(v466,v468);
 RiscvQm31 v470 = riscv_load_qm31(profile_parameters,220u);
 RiscvQm31 v471 = riscv_qm_mul(v470,v22);
 RiscvQm31 v472 = riscv_qm_add(v469,v471);
 RiscvQm31 v473 = riscv_load_qm31(profile_parameters,224u);
 RiscvQm31 v474 = riscv_qm_mul(v473,v37);
 RiscvQm31 v475 = riscv_qm_add(v472,v474);
 RiscvQm31 v476 = riscv_load_qm31(profile_parameters,228u);
 RiscvQm31 v477 = riscv_qm_mul(v476,v38);
 RiscvQm31 v478 = riscv_qm_add(v475,v477);
 RiscvQm31 v479 = riscv_load_qm31(profile_parameters,232u);
 RiscvQm31 v480 = riscv_qm_sub(v478,v479);
 RiscvQm31 v481 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v482 = riscv_load_qm31(profile_parameters,236u);
 RiscvQm31 v483 = riscv_qm_mul(v482,v4);
 RiscvQm31 v484 = { 0u,0u,0u,0u };
 RiscvQm31 v485 = riscv_qm_add(v484,v483);
 RiscvQm31 v486 = riscv_load_qm31(profile_parameters,240u);
 RiscvQm31 v487 = riscv_qm_mul(v486,v5);
 RiscvQm31 v488 = riscv_qm_add(v485,v487);
 RiscvQm31 v489 = riscv_load_qm31(profile_parameters,244u);
 RiscvQm31 v490 = riscv_qm_mul(v489,v6);
 RiscvQm31 v491 = riscv_qm_add(v488,v490);
 RiscvQm31 v492 = riscv_load_qm31(profile_parameters,248u);
 RiscvQm31 v493 = riscv_qm_mul(v492,v7);
 RiscvQm31 v494 = riscv_qm_add(v491,v493);
 RiscvQm31 v495 = riscv_load_qm31(profile_parameters,252u);
 RiscvQm31 v496 = riscv_qm_mul(v495,v16);
 RiscvQm31 v497 = riscv_qm_add(v494,v496);
 RiscvQm31 v498 = riscv_load_qm31(profile_parameters,256u);
 RiscvQm31 v499 = riscv_qm_mul(v498,v14);
 RiscvQm31 v500 = riscv_qm_add(v497,v499);
 RiscvQm31 v501 = riscv_load_qm31(profile_parameters,260u);
 RiscvQm31 v502 = riscv_qm_mul(v501,v15);
 RiscvQm31 v503 = riscv_qm_add(v500,v502);
 RiscvQm31 v504 = riscv_load_qm31(profile_parameters,264u);
 RiscvQm31 v505 = riscv_qm_mul(v504,v17);
 RiscvQm31 v506 = riscv_qm_add(v503,v505);
 RiscvQm31 v507 = riscv_load_qm31(profile_parameters,268u);
 RiscvQm31 v508 = riscv_qm_mul(v507,v18);
 RiscvQm31 v509 = riscv_qm_add(v506,v508);
 RiscvQm31 v510 = riscv_load_qm31(profile_parameters,272u);
 RiscvQm31 v511 = riscv_qm_mul(v510,v19);
 RiscvQm31 v512 = riscv_qm_add(v509,v511);
 RiscvQm31 v513 = riscv_load_qm31(profile_parameters,276u);
 RiscvQm31 v514 = riscv_qm_mul(v513,v20);
 RiscvQm31 v515 = riscv_qm_add(v512,v514);
 RiscvQm31 v516 = riscv_load_qm31(profile_parameters,280u);
 RiscvQm31 v517 = riscv_qm_mul(v516,v37);
 RiscvQm31 v518 = riscv_qm_add(v515,v517);
 RiscvQm31 v519 = riscv_load_qm31(profile_parameters,284u);
 RiscvQm31 v520 = riscv_qm_mul(v519,v38);
 RiscvQm31 v521 = riscv_qm_add(v518,v520);
 RiscvQm31 v522 = riscv_load_qm31(profile_parameters,288u);
 RiscvQm31 v523 = riscv_qm_sub(v521,v522);
 RiscvQm31 v524 = riscv_qm_sub(v0,v2);
 RiscvQm31 v525 = riscv_load_qm31(profile_parameters,292u);
 RiscvQm31 v526 = riscv_qm_mul(v525,v8);
 RiscvQm31 v527 = { 0u,0u,0u,0u };
 RiscvQm31 v528 = riscv_qm_add(v527,v526);
 RiscvQm31 v529 = riscv_load_qm31(profile_parameters,296u);
 RiscvQm31 v530 = riscv_qm_mul(v529,v9);
 RiscvQm31 v531 = riscv_qm_add(v528,v530);
 RiscvQm31 v532 = riscv_load_qm31(profile_parameters,300u);
 RiscvQm31 v533 = riscv_qm_mul(v532,v10);
 RiscvQm31 v534 = riscv_qm_add(v531,v533);
 RiscvQm31 v535 = riscv_load_qm31(profile_parameters,304u);
 RiscvQm31 v536 = riscv_qm_mul(v535,v11);
 RiscvQm31 v537 = riscv_qm_add(v534,v536);
 RiscvQm31 v538 = riscv_load_qm31(profile_parameters,308u);
 RiscvQm31 v539 = riscv_qm_mul(v538,v412);
 RiscvQm31 v540 = riscv_qm_add(v537,v539);
 RiscvQm31 v541 = riscv_load_qm31(profile_parameters,312u);
 RiscvQm31 v542 = riscv_qm_mul(v541,v416);
 RiscvQm31 v543 = riscv_qm_add(v540,v542);
 RiscvQm31 v544 = riscv_load_qm31(profile_parameters,316u);
 RiscvQm31 v545 = riscv_qm_mul(v544,v420);
 RiscvQm31 v546 = riscv_qm_add(v543,v545);
 RiscvQm31 v547 = riscv_load_qm31(profile_parameters,320u);
 RiscvQm31 v548 = riscv_qm_mul(v547,v424);
 RiscvQm31 v549 = riscv_qm_add(v546,v548);
 RiscvQm31 v550 = riscv_load_qm31(profile_parameters,324u);
 RiscvQm31 v551 = riscv_qm_mul(v550,v428);
 RiscvQm31 v552 = riscv_qm_add(v549,v551);
 RiscvQm31 v553 = riscv_load_qm31(profile_parameters,328u);
 RiscvQm31 v554 = riscv_qm_mul(v553,v432);
 RiscvQm31 v555 = riscv_qm_add(v552,v554);
 RiscvQm31 v556 = riscv_load_qm31(profile_parameters,332u);
 RiscvQm31 v557 = riscv_qm_mul(v556,v436);
 RiscvQm31 v558 = riscv_qm_add(v555,v557);
 RiscvQm31 v559 = riscv_load_qm31(profile_parameters,336u);
 RiscvQm31 v560 = riscv_qm_mul(v559,v440);
 RiscvQm31 v561 = riscv_qm_add(v558,v560);
 RiscvQm31 v562 = riscv_load_qm31(profile_parameters,340u);
 RiscvQm31 v563 = riscv_qm_mul(v562,v444);
 RiscvQm31 v564 = riscv_qm_add(v561,v563);
 RiscvQm31 v565 = riscv_load_qm31(profile_parameters,344u);
 RiscvQm31 v566 = riscv_qm_sub(v564,v565);
 RiscvQm31 v567 = riscv_qm_sub(v0,v1);
 RiscvQm31 v568 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v567);
 RiscvQm31 v569 = riscv_load_qm31(profile_parameters,348u);
 RiscvQm31 v570 = riscv_qm_mul(v569,v16);
 RiscvQm31 v571 = { 0u,0u,0u,0u };
 RiscvQm31 v572 = riscv_qm_add(v571,v570);
 RiscvQm31 v573 = riscv_load_qm31(profile_parameters,352u);
 RiscvQm31 v574 = riscv_qm_mul(v573,v14);
 RiscvQm31 v575 = riscv_qm_add(v572,v574);
 RiscvQm31 v576 = riscv_load_qm31(profile_parameters,356u);
 RiscvQm31 v577 = riscv_qm_mul(v576,v15);
 RiscvQm31 v578 = riscv_qm_add(v575,v577);
 RiscvQm31 v579 = riscv_load_qm31(profile_parameters,360u);
 RiscvQm31 v580 = riscv_qm_mul(v579,v21);
 RiscvQm31 v581 = riscv_qm_add(v578,v580);
 RiscvQm31 v582 = riscv_load_qm31(profile_parameters,364u);
 RiscvQm31 v583 = riscv_qm_mul(v582,v22);
 RiscvQm31 v584 = riscv_qm_add(v581,v583);
 RiscvQm31 v585 = riscv_load_qm31(profile_parameters,368u);
 RiscvQm31 v586 = riscv_qm_sub(v584,v585);
 RiscvQm31 v587 = { 1u,0u,0u,0u };
 RiscvQm31 v588 = riscv_qm_sub(v587,v13);
 RiscvQm31 v589 = riscv_qm_mul(v12,v588);
 RiscvQm31 v590 = riscv_qm_add(v1,v589);
 RiscvQm31 v591 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v590);
 RiscvQm31 v592 = { 1u,0u,0u,0u };
 RiscvQm31 v593 = riscv_qm_sub(v592,v13);
 RiscvQm31 v594 = riscv_qm_mul(v12,v593);
 RiscvQm31 v595 = { 1u,0u,0u,0u };
 RiscvQm31 v596 = riscv_qm_sub(v595,v1);
 RiscvQm31 v597 = riscv_qm_mul(v594,v596);
 RiscvQm31 v598 = riscv_load_qm31(profile_parameters,372u);
 RiscvQm31 v599 = riscv_qm_mul(v598,v41);
 RiscvQm31 v600 = { 0u,0u,0u,0u };
 RiscvQm31 v601 = riscv_qm_add(v600,v599);
 RiscvQm31 v602 = riscv_load_qm31(profile_parameters,376u);
 RiscvQm31 v603 = riscv_qm_mul(v602,v39);
 RiscvQm31 v604 = riscv_qm_add(v601,v603);
 RiscvQm31 v605 = riscv_load_qm31(profile_parameters,380u);
 RiscvQm31 v606 = riscv_qm_mul(v605,v40);
 RiscvQm31 v607 = riscv_qm_add(v604,v606);
 RiscvQm31 v608 = riscv_load_qm31(profile_parameters,384u);
 RiscvQm31 v609 = riscv_qm_mul(v608,v42);
 RiscvQm31 v610 = riscv_qm_add(v607,v609);
 RiscvQm31 v611 = riscv_load_qm31(profile_parameters,388u);
 RiscvQm31 v612 = riscv_qm_mul(v611,v43);
 RiscvQm31 v613 = riscv_qm_add(v610,v612);
 RiscvQm31 v614 = riscv_load_qm31(profile_parameters,392u);
 RiscvQm31 v615 = riscv_qm_mul(v614,v44);
 RiscvQm31 v616 = riscv_qm_add(v613,v615);
 RiscvQm31 v617 = riscv_load_qm31(profile_parameters,396u);
 RiscvQm31 v618 = riscv_qm_mul(v617,v45);
 RiscvQm31 v619 = riscv_qm_add(v616,v618);
 RiscvQm31 v620 = riscv_load_qm31(profile_parameters,400u);
 RiscvQm31 v621 = riscv_qm_mul(v620,v46);
 RiscvQm31 v622 = riscv_qm_add(v619,v621);
 RiscvQm31 v623 = riscv_load_qm31(profile_parameters,404u);
 RiscvQm31 v624 = riscv_qm_mul(v623,v47);
 RiscvQm31 v625 = riscv_qm_add(v622,v624);
 RiscvQm31 v626 = riscv_load_qm31(profile_parameters,408u);
 RiscvQm31 v627 = riscv_qm_sub(v625,v626);
 RiscvQm31 v628 = riscv_qm_mul(v597,v41);
 RiscvQm31 v629 = riscv_load_qm31(profile_parameters,412u);
 RiscvQm31 v630 = riscv_qm_mul(v1,v629);
 RiscvQm31 v631 = riscv_load_qm31(profile_parameters,416u);
 RiscvQm31 v632 = riscv_qm_mul(v2,v631);
 RiscvQm31 v633 = riscv_qm_add(v630,v632);
 RiscvQm31 v634 = riscv_load_qm31(profile_parameters,420u);
 RiscvQm31 v635 = riscv_qm_mul(v1,v634);
 RiscvQm31 v636 = riscv_qm_add(v628,v635);
 RiscvQm31 v637 = riscv_load_qm31(profile_parameters,424u);
 RiscvQm31 v638 = riscv_qm_mul(v2,v637);
 RiscvQm31 v639 = riscv_qm_add(v636,v638);
 RiscvQm31 v640 = { 1u,0u,0u,0u };
 RiscvQm31 v641 = riscv_qm_sub(v640,v41);
 RiscvQm31 v642 = riscv_qm_mul(v597,v641);
 RiscvQm31 v643 = riscv_load_qm31(profile_parameters,428u);
 RiscvQm31 v644 = riscv_qm_mul(v1,v643);
 RiscvQm31 v645 = riscv_load_qm31(profile_parameters,432u);
 RiscvQm31 v646 = riscv_qm_mul(v2,v645);
 RiscvQm31 v647 = riscv_qm_add(v644,v646);
 RiscvQm31 v648 = riscv_load_qm31(profile_parameters,436u);
 RiscvQm31 v649 = riscv_qm_mul(v1,v648);
 RiscvQm31 v650 = riscv_qm_add(v642,v649);
 RiscvQm31 v651 = riscv_load_qm31(profile_parameters,440u);
 RiscvQm31 v652 = riscv_qm_mul(v2,v651);
 RiscvQm31 v653 = riscv_qm_add(v650,v652);
 RiscvQm31 v654 = riscv_load_qm31(profile_parameters,444u);
 RiscvQm31 v655 = riscv_qm_mul(v654,v14);
 RiscvQm31 v656 = { 0u,0u,0u,0u };
 RiscvQm31 v657 = riscv_qm_add(v656,v655);
 RiscvQm31 v658 = riscv_load_qm31(profile_parameters,448u);
 RiscvQm31 v659 = riscv_qm_sub(v657,v658);
 RiscvQm31 v660 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v661 = { 0u,0u,0u,0u };
 RiscvQm31 v662 = riscv_qm_add(v661,v0);
 RiscvQm31 v663 = riscv_load_qm31(profile_parameters,452u);
 RiscvQm31 v664 = riscv_qm_mul(v663,v15);
 RiscvQm31 v665 = { 0u,0u,0u,0u };
 RiscvQm31 v666 = riscv_qm_add(v665,v664);
 RiscvQm31 v667 = riscv_load_qm31(profile_parameters,456u);
 RiscvQm31 v668 = riscv_qm_sub(v666,v667);
 RiscvQm31 v669 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v670 = riscv_qm_add(v662,v0);
 RiscvQm31 v671 = riscv_load_qm31(profile_parameters,460u);
 RiscvQm31 v672 = riscv_qm_mul(v671,v17);
 RiscvQm31 v673 = { 0u,0u,0u,0u };
 RiscvQm31 v674 = riscv_qm_add(v673,v672);
 RiscvQm31 v675 = riscv_load_qm31(profile_parameters,464u);
 RiscvQm31 v676 = riscv_qm_sub(v674,v675);
 RiscvQm31 v677 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v678 = riscv_qm_add(v670,v0);
 RiscvQm31 v679 = riscv_load_qm31(profile_parameters,468u);
 RiscvQm31 v680 = riscv_qm_mul(v679,v18);
 RiscvQm31 v681 = { 0u,0u,0u,0u };
 RiscvQm31 v682 = riscv_qm_add(v681,v680);
 RiscvQm31 v683 = riscv_load_qm31(profile_parameters,472u);
 RiscvQm31 v684 = riscv_qm_sub(v682,v683);
 RiscvQm31 v685 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v686 = riscv_qm_add(v678,v0);
 RiscvQm31 v687 = riscv_load_qm31(profile_parameters,476u);
 RiscvQm31 v688 = riscv_qm_mul(v687,v19);
 RiscvQm31 v689 = { 0u,0u,0u,0u };
 RiscvQm31 v690 = riscv_qm_add(v689,v688);
 RiscvQm31 v691 = riscv_load_qm31(profile_parameters,480u);
 RiscvQm31 v692 = riscv_qm_sub(v690,v691);
 RiscvQm31 v693 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v694 = riscv_qm_add(v686,v0);
 RiscvQm31 v695 = riscv_load_qm31(profile_parameters,484u);
 RiscvQm31 v696 = riscv_qm_mul(v695,v20);
 RiscvQm31 v697 = { 0u,0u,0u,0u };
 RiscvQm31 v698 = riscv_qm_add(v697,v696);
 RiscvQm31 v699 = riscv_load_qm31(profile_parameters,488u);
 RiscvQm31 v700 = riscv_qm_sub(v698,v699);
 RiscvQm31 v701 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v702 = riscv_qm_add(v694,v0);
 RiscvQm31 v703 = riscv_load_qm31(profile_parameters,492u);
 RiscvQm31 v704 = riscv_qm_mul(v703,v21);
 RiscvQm31 v705 = { 0u,0u,0u,0u };
 RiscvQm31 v706 = riscv_qm_add(v705,v704);
 RiscvQm31 v707 = riscv_load_qm31(profile_parameters,496u);
 RiscvQm31 v708 = riscv_qm_sub(v706,v707);
 RiscvQm31 v709 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v710 = riscv_qm_add(v702,v0);
 RiscvQm31 v711 = riscv_load_qm31(profile_parameters,500u);
 RiscvQm31 v712 = riscv_qm_mul(v711,v22);
 RiscvQm31 v713 = { 0u,0u,0u,0u };
 RiscvQm31 v714 = riscv_qm_add(v713,v712);
 RiscvQm31 v715 = riscv_load_qm31(profile_parameters,504u);
 RiscvQm31 v716 = riscv_qm_sub(v714,v715);
 RiscvQm31 v717 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v718 = riscv_qm_add(v710,v0);
 RiscvQm31 v719 = riscv_load_qm31(profile_parameters,508u);
 RiscvQm31 v720 = riscv_qm_mul(v719,v37);
 RiscvQm31 v721 = { 0u,0u,0u,0u };
 RiscvQm31 v722 = riscv_qm_add(v721,v720);
 RiscvQm31 v723 = riscv_load_qm31(profile_parameters,512u);
 RiscvQm31 v724 = riscv_qm_sub(v722,v723);
 RiscvQm31 v725 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v726 = riscv_qm_add(v718,v0);
 RiscvQm31 v727 = riscv_load_qm31(profile_parameters,516u);
 RiscvQm31 v728 = riscv_qm_mul(v727,v38);
 RiscvQm31 v729 = { 0u,0u,0u,0u };
 RiscvQm31 v730 = riscv_qm_add(v729,v728);
 RiscvQm31 v731 = riscv_load_qm31(profile_parameters,520u);
 RiscvQm31 v732 = riscv_qm_sub(v730,v731);
 RiscvQm31 v733 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v734 = riscv_qm_add(v726,v0);
 RiscvQm31 v735 = riscv_load_qm31(profile_parameters,524u);
 RiscvQm31 v736 = riscv_qm_mul(v735,v23);
 RiscvQm31 v737 = { 0u,0u,0u,0u };
 RiscvQm31 v738 = riscv_qm_add(v737,v736);
 RiscvQm31 v739 = riscv_load_qm31(profile_parameters,528u);
 RiscvQm31 v740 = riscv_qm_sub(v738,v739);
 RiscvQm31 v741 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v398);
 RiscvQm31 v742 = riscv_qm_add(v734,v398);
 RiscvQm31 v743 = riscv_load_qm31(profile_parameters,532u);
 RiscvQm31 v744 = riscv_qm_mul(v743,v24);
 RiscvQm31 v745 = { 0u,0u,0u,0u };
 RiscvQm31 v746 = riscv_qm_add(v745,v744);
 RiscvQm31 v747 = riscv_load_qm31(profile_parameters,536u);
 RiscvQm31 v748 = riscv_qm_sub(v746,v747);
 RiscvQm31 v749 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v401);
 RiscvQm31 v750 = riscv_qm_add(v742,v401);
 RiscvQm31 v751 = riscv_load_qm31(profile_parameters,540u);
 RiscvQm31 v752 = riscv_qm_mul(v751,v25);
 RiscvQm31 v753 = { 0u,0u,0u,0u };
 RiscvQm31 v754 = riscv_qm_add(v753,v752);
 RiscvQm31 v755 = riscv_load_qm31(profile_parameters,544u);
 RiscvQm31 v756 = riscv_qm_sub(v754,v755);
 RiscvQm31 v757 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v404);
 RiscvQm31 v758 = riscv_qm_add(v750,v404);
 RiscvQm31 v759 = riscv_load_qm31(profile_parameters,548u);
 RiscvQm31 v760 = riscv_qm_mul(v759,v29);
 RiscvQm31 v761 = { 0u,0u,0u,0u };
 RiscvQm31 v762 = riscv_qm_add(v761,v760);
 RiscvQm31 v763 = riscv_load_qm31(profile_parameters,552u);
 RiscvQm31 v764 = riscv_qm_sub(v762,v763);
 RiscvQm31 v765 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v405);
 RiscvQm31 v766 = riscv_qm_add(v758,v405);
 RiscvQm31 v767 = riscv_load_qm31(profile_parameters,556u);
 RiscvQm31 v768 = riscv_qm_mul(v767,v30);
 RiscvQm31 v769 = { 0u,0u,0u,0u };
 RiscvQm31 v770 = riscv_qm_add(v769,v768);
 RiscvQm31 v771 = riscv_load_qm31(profile_parameters,560u);
 RiscvQm31 v772 = riscv_qm_sub(v770,v771);
 RiscvQm31 v773 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v406);
 RiscvQm31 v774 = riscv_qm_add(v766,v406);
 RiscvQm31 v775 = riscv_load_qm31(profile_parameters,564u);
 RiscvQm31 v776 = riscv_qm_mul(v775,v31);
 RiscvQm31 v777 = { 0u,0u,0u,0u };
 RiscvQm31 v778 = riscv_qm_add(v777,v776);
 RiscvQm31 v779 = riscv_load_qm31(profile_parameters,568u);
 RiscvQm31 v780 = riscv_qm_sub(v778,v779);
 RiscvQm31 v781 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v407);
 RiscvQm31 v782 = riscv_qm_add(v774,v407);
 RiscvQm31 v783 = riscv_load_qm31(profile_parameters,572u);
 RiscvQm31 v784 = riscv_qm_mul(v783,v32);
 RiscvQm31 v785 = { 0u,0u,0u,0u };
 RiscvQm31 v786 = riscv_qm_add(v785,v784);
 RiscvQm31 v787 = riscv_load_qm31(profile_parameters,576u);
 RiscvQm31 v788 = riscv_qm_sub(v786,v787);
 RiscvQm31 v789 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v408);
 RiscvQm31 v790 = riscv_qm_add(v782,v408);
 RiscvQm31 v791 = { 0u,1u,0u,0u };
 RiscvQm31 v792 = riscv_qm_mul(v49,v791);
 RiscvQm31 v793 = riscv_qm_add(v48,v792);
 RiscvQm31 v794 = { 0u,0u,1u,0u };
 RiscvQm31 v795 = riscv_qm_mul(v50,v794);
 RiscvQm31 v796 = riscv_qm_add(v793,v795);
 RiscvQm31 v797 = { 0u,0u,0u,1u };
 RiscvQm31 v798 = riscv_qm_mul(v51,v797);
 RiscvQm31 v799 = riscv_qm_add(v796,v798);
 RiscvQm31 v800 = { 0u,1u,0u,0u };
 RiscvQm31 v801 = riscv_qm_mul(v117,v800);
 RiscvQm31 v802 = riscv_qm_add(v116,v801);
 RiscvQm31 v803 = { 0u,0u,1u,0u };
 RiscvQm31 v804 = riscv_qm_mul(v118,v803);
 RiscvQm31 v805 = riscv_qm_add(v802,v804);
 RiscvQm31 v806 = { 0u,0u,0u,1u };
 RiscvQm31 v807 = riscv_qm_mul(v119,v806);
 RiscvQm31 v808 = riscv_qm_add(v805,v807);
 RiscvQm31 v809 = riscv_qm_sub(v799,v808);
 RiscvQm31 v810 = riscv_load_qm31(profile_parameters,580u);
 RiscvQm31 v811 = riscv_qm_add(v809,v810);
 RiscvQm31 v812 = riscv_qm_mul(v811,v480);
 RiscvQm31 v813 = riscv_qm_sub(v812,v481);
 RiscvQm31 v814 = { 0u,1u,0u,0u };
 RiscvQm31 v815 = riscv_qm_mul(v53,v814);
 RiscvQm31 v816 = riscv_qm_add(v52,v815);
 RiscvQm31 v817 = { 0u,0u,1u,0u };
 RiscvQm31 v818 = riscv_qm_mul(v54,v817);
 RiscvQm31 v819 = riscv_qm_add(v816,v818);
 RiscvQm31 v820 = { 0u,0u,0u,1u };
 RiscvQm31 v821 = riscv_qm_mul(v55,v820);
 RiscvQm31 v822 = riscv_qm_add(v819,v821);
 RiscvQm31 v823 = { 0u,1u,0u,0u };
 RiscvQm31 v824 = riscv_qm_mul(v121,v823);
 RiscvQm31 v825 = riscv_qm_add(v120,v824);
 RiscvQm31 v826 = { 0u,0u,1u,0u };
 RiscvQm31 v827 = riscv_qm_mul(v122,v826);
 RiscvQm31 v828 = riscv_qm_add(v825,v827);
 RiscvQm31 v829 = { 0u,0u,0u,1u };
 RiscvQm31 v830 = riscv_qm_mul(v123,v829);
 RiscvQm31 v831 = riscv_qm_add(v828,v830);
 RiscvQm31 v832 = riscv_qm_sub(v822,v831);
 RiscvQm31 v833 = riscv_load_qm31(profile_parameters,584u);
 RiscvQm31 v834 = riscv_qm_add(v832,v833);
 RiscvQm31 v835 = riscv_qm_mul(v834,v523);
 RiscvQm31 v836 = riscv_qm_mul(v835,v566);
 RiscvQm31 v837 = riscv_qm_mul(v524,v566);
 RiscvQm31 v838 = riscv_qm_sub(v836,v837);
 RiscvQm31 v839 = riscv_qm_mul(v568,v523);
 RiscvQm31 v840 = riscv_qm_sub(v838,v839);
 RiscvQm31 v841 = { 0u,1u,0u,0u };
 RiscvQm31 v842 = riscv_qm_mul(v57,v841);
 RiscvQm31 v843 = riscv_qm_add(v56,v842);
 RiscvQm31 v844 = { 0u,0u,1u,0u };
 RiscvQm31 v845 = riscv_qm_mul(v58,v844);
 RiscvQm31 v846 = riscv_qm_add(v843,v845);
 RiscvQm31 v847 = { 0u,0u,0u,1u };
 RiscvQm31 v848 = riscv_qm_mul(v59,v847);
 RiscvQm31 v849 = riscv_qm_add(v846,v848);
 RiscvQm31 v850 = { 0u,1u,0u,0u };
 RiscvQm31 v851 = riscv_qm_mul(v125,v850);
 RiscvQm31 v852 = riscv_qm_add(v124,v851);
 RiscvQm31 v853 = { 0u,0u,1u,0u };
 RiscvQm31 v854 = riscv_qm_mul(v126,v853);
 RiscvQm31 v855 = riscv_qm_add(v852,v854);
 RiscvQm31 v856 = { 0u,0u,0u,1u };
 RiscvQm31 v857 = riscv_qm_mul(v127,v856);
 RiscvQm31 v858 = riscv_qm_add(v855,v857);
 RiscvQm31 v859 = riscv_qm_sub(v849,v858);
 RiscvQm31 v860 = riscv_load_qm31(profile_parameters,588u);
 RiscvQm31 v861 = riscv_qm_add(v859,v860);
 RiscvQm31 v862 = riscv_qm_mul(v861,v586);
 RiscvQm31 v863 = riscv_qm_sub(v862,v591);
 RiscvQm31 v864 = { 0u,1u,0u,0u };
 RiscvQm31 v865 = riscv_qm_mul(v61,v864);
 RiscvQm31 v866 = riscv_qm_add(v60,v865);
 RiscvQm31 v867 = { 0u,0u,1u,0u };
 RiscvQm31 v868 = riscv_qm_mul(v62,v867);
 RiscvQm31 v869 = riscv_qm_add(v866,v868);
 RiscvQm31 v870 = { 0u,0u,0u,1u };
 RiscvQm31 v871 = riscv_qm_mul(v63,v870);
 RiscvQm31 v872 = riscv_qm_add(v869,v871);
 RiscvQm31 v873 = { 0u,1u,0u,0u };
 RiscvQm31 v874 = riscv_qm_mul(v129,v873);
 RiscvQm31 v875 = riscv_qm_add(v128,v874);
 RiscvQm31 v876 = { 0u,0u,1u,0u };
 RiscvQm31 v877 = riscv_qm_mul(v130,v876);
 RiscvQm31 v878 = riscv_qm_add(v875,v877);
 RiscvQm31 v879 = { 0u,0u,0u,1u };
 RiscvQm31 v880 = riscv_qm_mul(v131,v879);
 RiscvQm31 v881 = riscv_qm_add(v878,v880);
 RiscvQm31 v882 = riscv_qm_sub(v872,v881);
 RiscvQm31 v883 = riscv_load_qm31(profile_parameters,592u);
 RiscvQm31 v884 = riscv_qm_add(v882,v883);
 RiscvQm31 v885 = riscv_qm_mul(v884,v627);
 RiscvQm31 v886 = { 1u,0u,0u,0u };
 RiscvQm31 v887 = riscv_qm_mul(v885,v886);
 RiscvQm31 v888 = { 1u,0u,0u,0u };
 RiscvQm31 v889 = riscv_qm_mul(v628,v888);
 RiscvQm31 v890 = riscv_qm_sub(v887,v889);
 RiscvQm31 v891 = riscv_qm_mul(v633,v627);
 RiscvQm31 v892 = riscv_qm_sub(v890,v891);
 RiscvQm31 v893 = { 0u,1u,0u,0u };
 RiscvQm31 v894 = riscv_qm_mul(v65,v893);
 RiscvQm31 v895 = riscv_qm_add(v64,v894);
 RiscvQm31 v896 = { 0u,0u,1u,0u };
 RiscvQm31 v897 = riscv_qm_mul(v66,v896);
 RiscvQm31 v898 = riscv_qm_add(v895,v897);
 RiscvQm31 v899 = { 0u,0u,0u,1u };
 RiscvQm31 v900 = riscv_qm_mul(v67,v899);
 RiscvQm31 v901 = riscv_qm_add(v898,v900);
 RiscvQm31 v902 = { 0u,1u,0u,0u };
 RiscvQm31 v903 = riscv_qm_mul(v133,v902);
 RiscvQm31 v904 = riscv_qm_add(v132,v903);
 RiscvQm31 v905 = { 0u,0u,1u,0u };
 RiscvQm31 v906 = riscv_qm_mul(v134,v905);
 RiscvQm31 v907 = riscv_qm_add(v904,v906);
 RiscvQm31 v908 = { 0u,0u,0u,1u };
 RiscvQm31 v909 = riscv_qm_mul(v135,v908);
 RiscvQm31 v910 = riscv_qm_add(v907,v909);
 RiscvQm31 v911 = riscv_qm_sub(v901,v910);
 RiscvQm31 v912 = riscv_load_qm31(profile_parameters,596u);
 RiscvQm31 v913 = riscv_qm_add(v911,v912);
 RiscvQm31 v914 = riscv_qm_sub(v913,v639);
 RiscvQm31 v915 = { 0u,1u,0u,0u };
 RiscvQm31 v916 = riscv_qm_mul(v69,v915);
 RiscvQm31 v917 = riscv_qm_add(v68,v916);
 RiscvQm31 v918 = { 0u,0u,1u,0u };
 RiscvQm31 v919 = riscv_qm_mul(v70,v918);
 RiscvQm31 v920 = riscv_qm_add(v917,v919);
 RiscvQm31 v921 = { 0u,0u,0u,1u };
 RiscvQm31 v922 = riscv_qm_mul(v71,v921);
 RiscvQm31 v923 = riscv_qm_add(v920,v922);
 RiscvQm31 v924 = { 0u,1u,0u,0u };
 RiscvQm31 v925 = riscv_qm_mul(v137,v924);
 RiscvQm31 v926 = riscv_qm_add(v136,v925);
 RiscvQm31 v927 = { 0u,0u,1u,0u };
 RiscvQm31 v928 = riscv_qm_mul(v138,v927);
 RiscvQm31 v929 = riscv_qm_add(v926,v928);
 RiscvQm31 v930 = { 0u,0u,0u,1u };
 RiscvQm31 v931 = riscv_qm_mul(v139,v930);
 RiscvQm31 v932 = riscv_qm_add(v929,v931);
 RiscvQm31 v933 = riscv_qm_sub(v923,v932);
 RiscvQm31 v934 = riscv_load_qm31(profile_parameters,600u);
 RiscvQm31 v935 = riscv_qm_add(v933,v934);
 RiscvQm31 v936 = riscv_qm_sub(v935,v790);
 RiscvQm31 v937 = { 0u,1u,0u,0u };
 RiscvQm31 v938 = riscv_qm_mul(v73,v937);
 RiscvQm31 v939 = riscv_qm_add(v72,v938);
 RiscvQm31 v940 = { 0u,0u,1u,0u };
 RiscvQm31 v941 = riscv_qm_mul(v74,v940);
 RiscvQm31 v942 = riscv_qm_add(v939,v941);
 RiscvQm31 v943 = { 0u,0u,0u,1u };
 RiscvQm31 v944 = riscv_qm_mul(v75,v943);
 RiscvQm31 v945 = riscv_qm_add(v942,v944);
 RiscvQm31 v946 = { 0u,1u,0u,0u };
 RiscvQm31 v947 = riscv_qm_mul(v141,v946);
 RiscvQm31 v948 = riscv_qm_add(v140,v947);
 RiscvQm31 v949 = { 0u,0u,1u,0u };
 RiscvQm31 v950 = riscv_qm_mul(v142,v949);
 RiscvQm31 v951 = riscv_qm_add(v948,v950);
 RiscvQm31 v952 = { 0u,0u,0u,1u };
 RiscvQm31 v953 = riscv_qm_mul(v143,v952);
 RiscvQm31 v954 = riscv_qm_add(v951,v953);
 RiscvQm31 v955 = riscv_qm_sub(v945,v954);
 RiscvQm31 v956 = riscv_load_qm31(profile_parameters,604u);
 RiscvQm31 v957 = riscv_qm_add(v955,v956);
 RiscvQm31 v958 = riscv_qm_mul(v957,v627);
 RiscvQm31 v959 = { 1u,0u,0u,0u };
 RiscvQm31 v960 = riscv_qm_mul(v958,v959);
 RiscvQm31 v961 = { 1u,0u,0u,0u };
 RiscvQm31 v962 = riscv_qm_mul(v642,v961);
 RiscvQm31 v963 = riscv_qm_sub(v960,v962);
 RiscvQm31 v964 = riscv_qm_mul(v647,v627);
 RiscvQm31 v965 = riscv_qm_sub(v963,v964);
 RiscvQm31 v966 = { 0u,1u,0u,0u };
 RiscvQm31 v967 = riscv_qm_mul(v77,v966);
 RiscvQm31 v968 = riscv_qm_add(v76,v967);
 RiscvQm31 v969 = { 0u,0u,1u,0u };
 RiscvQm31 v970 = riscv_qm_mul(v78,v969);
 RiscvQm31 v971 = riscv_qm_add(v968,v970);
 RiscvQm31 v972 = { 0u,0u,0u,1u };
 RiscvQm31 v973 = riscv_qm_mul(v79,v972);
 RiscvQm31 v974 = riscv_qm_add(v971,v973);
 RiscvQm31 v975 = { 0u,1u,0u,0u };
 RiscvQm31 v976 = riscv_qm_mul(v145,v975);
 RiscvQm31 v977 = riscv_qm_add(v144,v976);
 RiscvQm31 v978 = { 0u,0u,1u,0u };
 RiscvQm31 v979 = riscv_qm_mul(v146,v978);
 RiscvQm31 v980 = riscv_qm_add(v977,v979);
 RiscvQm31 v981 = { 0u,0u,0u,1u };
 RiscvQm31 v982 = riscv_qm_mul(v147,v981);
 RiscvQm31 v983 = riscv_qm_add(v980,v982);
 RiscvQm31 v984 = riscv_qm_sub(v974,v983);
 RiscvQm31 v985 = riscv_load_qm31(profile_parameters,608u);
 RiscvQm31 v986 = riscv_qm_add(v984,v985);
 RiscvQm31 v987 = riscv_qm_sub(v986,v653);
 RiscvQm31 v988 = { 0u,1u,0u,0u };
 RiscvQm31 v989 = riscv_qm_mul(v81,v988);
 RiscvQm31 v990 = riscv_qm_add(v80,v989);
 RiscvQm31 v991 = { 0u,0u,1u,0u };
 RiscvQm31 v992 = riscv_qm_mul(v82,v991);
 RiscvQm31 v993 = riscv_qm_add(v990,v992);
 RiscvQm31 v994 = { 0u,0u,0u,1u };
 RiscvQm31 v995 = riscv_qm_mul(v83,v994);
 RiscvQm31 v996 = riscv_qm_add(v993,v995);
 RiscvQm31 v997 = { 0u,1u,0u,0u };
 RiscvQm31 v998 = riscv_qm_mul(v149,v997);
 RiscvQm31 v999 = riscv_qm_add(v148,v998);
 RiscvQm31 v1000 = { 0u,0u,1u,0u };
 RiscvQm31 v1001 = riscv_qm_mul(v150,v1000);
 RiscvQm31 v1002 = riscv_qm_add(v999,v1001);
 RiscvQm31 v1003 = { 0u,0u,0u,1u };
 RiscvQm31 v1004 = riscv_qm_mul(v151,v1003);
 RiscvQm31 v1005 = riscv_qm_add(v1002,v1004);
 RiscvQm31 v1006 = riscv_qm_sub(v996,v1005);
 RiscvQm31 v1007 = riscv_load_qm31(profile_parameters,612u);
 RiscvQm31 v1008 = riscv_qm_add(v1006,v1007);
 RiscvQm31 v1009 = riscv_qm_mul(v1008,v659);
 RiscvQm31 v1010 = riscv_qm_mul(v1009,v668);
 RiscvQm31 v1011 = riscv_qm_mul(v660,v668);
 RiscvQm31 v1012 = riscv_qm_sub(v1010,v1011);
 RiscvQm31 v1013 = riscv_qm_mul(v669,v659);
 RiscvQm31 v1014 = riscv_qm_sub(v1012,v1013);
 RiscvQm31 v1015 = { 0u,1u,0u,0u };
 RiscvQm31 v1016 = riscv_qm_mul(v85,v1015);
 RiscvQm31 v1017 = riscv_qm_add(v84,v1016);
 RiscvQm31 v1018 = { 0u,0u,1u,0u };
 RiscvQm31 v1019 = riscv_qm_mul(v86,v1018);
 RiscvQm31 v1020 = riscv_qm_add(v1017,v1019);
 RiscvQm31 v1021 = { 0u,0u,0u,1u };
 RiscvQm31 v1022 = riscv_qm_mul(v87,v1021);
 RiscvQm31 v1023 = riscv_qm_add(v1020,v1022);
 RiscvQm31 v1024 = { 0u,1u,0u,0u };
 RiscvQm31 v1025 = riscv_qm_mul(v153,v1024);
 RiscvQm31 v1026 = riscv_qm_add(v152,v1025);
 RiscvQm31 v1027 = { 0u,0u,1u,0u };
 RiscvQm31 v1028 = riscv_qm_mul(v154,v1027);
 RiscvQm31 v1029 = riscv_qm_add(v1026,v1028);
 RiscvQm31 v1030 = { 0u,0u,0u,1u };
 RiscvQm31 v1031 = riscv_qm_mul(v155,v1030);
 RiscvQm31 v1032 = riscv_qm_add(v1029,v1031);
 RiscvQm31 v1033 = riscv_qm_sub(v1023,v1032);
 RiscvQm31 v1034 = riscv_load_qm31(profile_parameters,616u);
 RiscvQm31 v1035 = riscv_qm_add(v1033,v1034);
 RiscvQm31 v1036 = riscv_qm_mul(v1035,v676);
 RiscvQm31 v1037 = riscv_qm_mul(v1036,v684);
 RiscvQm31 v1038 = riscv_qm_mul(v677,v684);
 RiscvQm31 v1039 = riscv_qm_sub(v1037,v1038);
 RiscvQm31 v1040 = riscv_qm_mul(v685,v676);
 RiscvQm31 v1041 = riscv_qm_sub(v1039,v1040);
 RiscvQm31 v1042 = { 0u,1u,0u,0u };
 RiscvQm31 v1043 = riscv_qm_mul(v89,v1042);
 RiscvQm31 v1044 = riscv_qm_add(v88,v1043);
 RiscvQm31 v1045 = { 0u,0u,1u,0u };
 RiscvQm31 v1046 = riscv_qm_mul(v90,v1045);
 RiscvQm31 v1047 = riscv_qm_add(v1044,v1046);
 RiscvQm31 v1048 = { 0u,0u,0u,1u };
 RiscvQm31 v1049 = riscv_qm_mul(v91,v1048);
 RiscvQm31 v1050 = riscv_qm_add(v1047,v1049);
 RiscvQm31 v1051 = { 0u,1u,0u,0u };
 RiscvQm31 v1052 = riscv_qm_mul(v157,v1051);
 RiscvQm31 v1053 = riscv_qm_add(v156,v1052);
 RiscvQm31 v1054 = { 0u,0u,1u,0u };
 RiscvQm31 v1055 = riscv_qm_mul(v158,v1054);
 RiscvQm31 v1056 = riscv_qm_add(v1053,v1055);
 RiscvQm31 v1057 = { 0u,0u,0u,1u };
 RiscvQm31 v1058 = riscv_qm_mul(v159,v1057);
 RiscvQm31 v1059 = riscv_qm_add(v1056,v1058);
 RiscvQm31 v1060 = riscv_qm_sub(v1050,v1059);
 RiscvQm31 v1061 = riscv_load_qm31(profile_parameters,620u);
 RiscvQm31 v1062 = riscv_qm_add(v1060,v1061);
 RiscvQm31 v1063 = riscv_qm_mul(v1062,v692);
 RiscvQm31 v1064 = riscv_qm_mul(v1063,v700);
 RiscvQm31 v1065 = riscv_qm_mul(v693,v700);
 RiscvQm31 v1066 = riscv_qm_sub(v1064,v1065);
 RiscvQm31 v1067 = riscv_qm_mul(v701,v692);
 RiscvQm31 v1068 = riscv_qm_sub(v1066,v1067);
 RiscvQm31 v1069 = { 0u,1u,0u,0u };
 RiscvQm31 v1070 = riscv_qm_mul(v93,v1069);
 RiscvQm31 v1071 = riscv_qm_add(v92,v1070);
 RiscvQm31 v1072 = { 0u,0u,1u,0u };
 RiscvQm31 v1073 = riscv_qm_mul(v94,v1072);
 RiscvQm31 v1074 = riscv_qm_add(v1071,v1073);
 RiscvQm31 v1075 = { 0u,0u,0u,1u };
 RiscvQm31 v1076 = riscv_qm_mul(v95,v1075);
 RiscvQm31 v1077 = riscv_qm_add(v1074,v1076);
 RiscvQm31 v1078 = { 0u,1u,0u,0u };
 RiscvQm31 v1079 = riscv_qm_mul(v161,v1078);
 RiscvQm31 v1080 = riscv_qm_add(v160,v1079);
 RiscvQm31 v1081 = { 0u,0u,1u,0u };
 RiscvQm31 v1082 = riscv_qm_mul(v162,v1081);
 RiscvQm31 v1083 = riscv_qm_add(v1080,v1082);
 RiscvQm31 v1084 = { 0u,0u,0u,1u };
 RiscvQm31 v1085 = riscv_qm_mul(v163,v1084);
 RiscvQm31 v1086 = riscv_qm_add(v1083,v1085);
 RiscvQm31 v1087 = riscv_qm_sub(v1077,v1086);
 RiscvQm31 v1088 = riscv_load_qm31(profile_parameters,624u);
 RiscvQm31 v1089 = riscv_qm_add(v1087,v1088);
 RiscvQm31 v1090 = riscv_qm_mul(v1089,v708);
 RiscvQm31 v1091 = riscv_qm_mul(v1090,v716);
 RiscvQm31 v1092 = riscv_qm_mul(v709,v716);
 RiscvQm31 v1093 = riscv_qm_sub(v1091,v1092);
 RiscvQm31 v1094 = riscv_qm_mul(v717,v708);
 RiscvQm31 v1095 = riscv_qm_sub(v1093,v1094);
 RiscvQm31 v1096 = { 0u,1u,0u,0u };
 RiscvQm31 v1097 = riscv_qm_mul(v97,v1096);
 RiscvQm31 v1098 = riscv_qm_add(v96,v1097);
 RiscvQm31 v1099 = { 0u,0u,1u,0u };
 RiscvQm31 v1100 = riscv_qm_mul(v98,v1099);
 RiscvQm31 v1101 = riscv_qm_add(v1098,v1100);
 RiscvQm31 v1102 = { 0u,0u,0u,1u };
 RiscvQm31 v1103 = riscv_qm_mul(v99,v1102);
 RiscvQm31 v1104 = riscv_qm_add(v1101,v1103);
 RiscvQm31 v1105 = { 0u,1u,0u,0u };
 RiscvQm31 v1106 = riscv_qm_mul(v165,v1105);
 RiscvQm31 v1107 = riscv_qm_add(v164,v1106);
 RiscvQm31 v1108 = { 0u,0u,1u,0u };
 RiscvQm31 v1109 = riscv_qm_mul(v166,v1108);
 RiscvQm31 v1110 = riscv_qm_add(v1107,v1109);
 RiscvQm31 v1111 = { 0u,0u,0u,1u };
 RiscvQm31 v1112 = riscv_qm_mul(v167,v1111);
 RiscvQm31 v1113 = riscv_qm_add(v1110,v1112);
 RiscvQm31 v1114 = riscv_qm_sub(v1104,v1113);
 RiscvQm31 v1115 = riscv_load_qm31(profile_parameters,628u);
 RiscvQm31 v1116 = riscv_qm_add(v1114,v1115);
 RiscvQm31 v1117 = riscv_qm_mul(v1116,v724);
 RiscvQm31 v1118 = riscv_qm_mul(v1117,v732);
 RiscvQm31 v1119 = riscv_qm_mul(v725,v732);
 RiscvQm31 v1120 = riscv_qm_sub(v1118,v1119);
 RiscvQm31 v1121 = riscv_qm_mul(v733,v724);
 RiscvQm31 v1122 = riscv_qm_sub(v1120,v1121);
 RiscvQm31 v1123 = { 0u,1u,0u,0u };
 RiscvQm31 v1124 = riscv_qm_mul(v101,v1123);
 RiscvQm31 v1125 = riscv_qm_add(v100,v1124);
 RiscvQm31 v1126 = { 0u,0u,1u,0u };
 RiscvQm31 v1127 = riscv_qm_mul(v102,v1126);
 RiscvQm31 v1128 = riscv_qm_add(v1125,v1127);
 RiscvQm31 v1129 = { 0u,0u,0u,1u };
 RiscvQm31 v1130 = riscv_qm_mul(v103,v1129);
 RiscvQm31 v1131 = riscv_qm_add(v1128,v1130);
 RiscvQm31 v1132 = { 0u,1u,0u,0u };
 RiscvQm31 v1133 = riscv_qm_mul(v169,v1132);
 RiscvQm31 v1134 = riscv_qm_add(v168,v1133);
 RiscvQm31 v1135 = { 0u,0u,1u,0u };
 RiscvQm31 v1136 = riscv_qm_mul(v170,v1135);
 RiscvQm31 v1137 = riscv_qm_add(v1134,v1136);
 RiscvQm31 v1138 = { 0u,0u,0u,1u };
 RiscvQm31 v1139 = riscv_qm_mul(v171,v1138);
 RiscvQm31 v1140 = riscv_qm_add(v1137,v1139);
 RiscvQm31 v1141 = riscv_qm_sub(v1131,v1140);
 RiscvQm31 v1142 = riscv_load_qm31(profile_parameters,632u);
 RiscvQm31 v1143 = riscv_qm_add(v1141,v1142);
 RiscvQm31 v1144 = riscv_qm_mul(v1143,v740);
 RiscvQm31 v1145 = riscv_qm_mul(v1144,v748);
 RiscvQm31 v1146 = riscv_qm_mul(v741,v748);
 RiscvQm31 v1147 = riscv_qm_sub(v1145,v1146);
 RiscvQm31 v1148 = riscv_qm_mul(v749,v740);
 RiscvQm31 v1149 = riscv_qm_sub(v1147,v1148);
 RiscvQm31 v1150 = { 0u,1u,0u,0u };
 RiscvQm31 v1151 = riscv_qm_mul(v105,v1150);
 RiscvQm31 v1152 = riscv_qm_add(v104,v1151);
 RiscvQm31 v1153 = { 0u,0u,1u,0u };
 RiscvQm31 v1154 = riscv_qm_mul(v106,v1153);
 RiscvQm31 v1155 = riscv_qm_add(v1152,v1154);
 RiscvQm31 v1156 = { 0u,0u,0u,1u };
 RiscvQm31 v1157 = riscv_qm_mul(v107,v1156);
 RiscvQm31 v1158 = riscv_qm_add(v1155,v1157);
 RiscvQm31 v1159 = { 0u,1u,0u,0u };
 RiscvQm31 v1160 = riscv_qm_mul(v173,v1159);
 RiscvQm31 v1161 = riscv_qm_add(v172,v1160);
 RiscvQm31 v1162 = { 0u,0u,1u,0u };
 RiscvQm31 v1163 = riscv_qm_mul(v174,v1162);
 RiscvQm31 v1164 = riscv_qm_add(v1161,v1163);
 RiscvQm31 v1165 = { 0u,0u,0u,1u };
 RiscvQm31 v1166 = riscv_qm_mul(v175,v1165);
 RiscvQm31 v1167 = riscv_qm_add(v1164,v1166);
 RiscvQm31 v1168 = riscv_qm_sub(v1158,v1167);
 RiscvQm31 v1169 = riscv_load_qm31(profile_parameters,636u);
 RiscvQm31 v1170 = riscv_qm_add(v1168,v1169);
 RiscvQm31 v1171 = riscv_qm_mul(v1170,v756);
 RiscvQm31 v1172 = riscv_qm_mul(v1171,v764);
 RiscvQm31 v1173 = riscv_qm_mul(v757,v764);
 RiscvQm31 v1174 = riscv_qm_sub(v1172,v1173);
 RiscvQm31 v1175 = riscv_qm_mul(v765,v756);
 RiscvQm31 v1176 = riscv_qm_sub(v1174,v1175);
 RiscvQm31 v1177 = { 0u,1u,0u,0u };
 RiscvQm31 v1178 = riscv_qm_mul(v109,v1177);
 RiscvQm31 v1179 = riscv_qm_add(v108,v1178);
 RiscvQm31 v1180 = { 0u,0u,1u,0u };
 RiscvQm31 v1181 = riscv_qm_mul(v110,v1180);
 RiscvQm31 v1182 = riscv_qm_add(v1179,v1181);
 RiscvQm31 v1183 = { 0u,0u,0u,1u };
 RiscvQm31 v1184 = riscv_qm_mul(v111,v1183);
 RiscvQm31 v1185 = riscv_qm_add(v1182,v1184);
 RiscvQm31 v1186 = { 0u,1u,0u,0u };
 RiscvQm31 v1187 = riscv_qm_mul(v177,v1186);
 RiscvQm31 v1188 = riscv_qm_add(v176,v1187);
 RiscvQm31 v1189 = { 0u,0u,1u,0u };
 RiscvQm31 v1190 = riscv_qm_mul(v178,v1189);
 RiscvQm31 v1191 = riscv_qm_add(v1188,v1190);
 RiscvQm31 v1192 = { 0u,0u,0u,1u };
 RiscvQm31 v1193 = riscv_qm_mul(v179,v1192);
 RiscvQm31 v1194 = riscv_qm_add(v1191,v1193);
 RiscvQm31 v1195 = riscv_qm_sub(v1185,v1194);
 RiscvQm31 v1196 = riscv_load_qm31(profile_parameters,640u);
 RiscvQm31 v1197 = riscv_qm_add(v1195,v1196);
 RiscvQm31 v1198 = riscv_qm_mul(v1197,v772);
 RiscvQm31 v1199 = riscv_qm_mul(v1198,v780);
 RiscvQm31 v1200 = riscv_qm_mul(v773,v780);
 RiscvQm31 v1201 = riscv_qm_sub(v1199,v1200);
 RiscvQm31 v1202 = riscv_qm_mul(v781,v772);
 RiscvQm31 v1203 = riscv_qm_sub(v1201,v1202);
 RiscvQm31 v1204 = { 0u,1u,0u,0u };
 RiscvQm31 v1205 = riscv_qm_mul(v113,v1204);
 RiscvQm31 v1206 = riscv_qm_add(v112,v1205);
 RiscvQm31 v1207 = { 0u,0u,1u,0u };
 RiscvQm31 v1208 = riscv_qm_mul(v114,v1207);
 RiscvQm31 v1209 = riscv_qm_add(v1206,v1208);
 RiscvQm31 v1210 = { 0u,0u,0u,1u };
 RiscvQm31 v1211 = riscv_qm_mul(v115,v1210);
 RiscvQm31 v1212 = riscv_qm_add(v1209,v1211);
 RiscvQm31 v1213 = { 0u,1u,0u,0u };
 RiscvQm31 v1214 = riscv_qm_mul(v181,v1213);
 RiscvQm31 v1215 = riscv_qm_add(v180,v1214);
 RiscvQm31 v1216 = { 0u,0u,1u,0u };
 RiscvQm31 v1217 = riscv_qm_mul(v182,v1216);
 RiscvQm31 v1218 = riscv_qm_add(v1215,v1217);
 RiscvQm31 v1219 = { 0u,0u,0u,1u };
 RiscvQm31 v1220 = riscv_qm_mul(v183,v1219);
 RiscvQm31 v1221 = riscv_qm_add(v1218,v1220);
 RiscvQm31 v1222 = riscv_qm_sub(v1212,v1221);
 RiscvQm31 v1223 = riscv_load_qm31(profile_parameters,644u);
 RiscvQm31 v1224 = riscv_qm_add(v1222,v1223);
 RiscvQm31 v1225 = riscv_qm_mul(v1224,v788);
 RiscvQm31 v1226 = { 1u,0u,0u,0u };
 RiscvQm31 v1227 = riscv_qm_mul(v1225,v1226);
 RiscvQm31 v1228 = { 1u,0u,0u,0u };
 RiscvQm31 v1229 = riscv_qm_mul(v789,v1228);
 RiscvQm31 v1230 = riscv_qm_sub(v1227,v1229);
 RiscvQm31 v1231 = { 0u,0u,0u,0u };
 RiscvQm31 v1232 = riscv_qm_mul(v1231,v788);
 RiscvQm31 v1233 = riscv_qm_sub(v1230,v1232);
 RiscvQm31 folded={0u,0u,0u,0u};
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,248u),v185));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,244u),v189));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,240u),v193));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,236u),v197));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,232u),v201));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,228u),v205));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,224u),v209));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,220u),v213));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,216u),v217));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,212u),v221));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,208u),v260));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,204u),v263));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,200u),v266));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,196u),v269));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,192u),v272));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,188u),v283));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,184u),v290));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,180u),v297));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,176u),v298));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,172u),v307));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,168u),v314));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,164u),v321));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,160u),v328));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,156u),v329));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,152u),v332));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,148u),v335));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,144u),v338));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,140u),v341));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,136u),v344));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,132u),v347));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,128u),v350));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,124u),v353));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,120u),v356));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,116u),v359));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,112u),v362));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,108u),v365));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,104u),v368));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,100u),v371));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,96u),v374));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,92u),v377));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,88u),v380));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,84u),v383));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,80u),v386));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,76u),v389));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,72u),v392));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,68u),v395));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,64u),v813));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,60u),v840));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,56u),v863));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,52u),v892));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,48u),v914));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,44u),v936));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,40u),v965));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,36u),v987));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,32u),v1014));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,28u),v1041));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,24u),v1068));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,20u),v1095));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,16u),v1122));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,12u),v1149));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,8u),v1176));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,4u),v1203));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,0u),v1233));
 RiscvQm31 result=riscv_qm_mul_base(folded,denominator_inverses[row/(row_count/denominator_count)]);
 output[ulong(row)]=riscv_m31_add(output[ulong(row)],result.a);
 output[ulong(row_count)+row]=riscv_m31_add(output[ulong(row_count)+row],result.b);
 output[2ul*row_count+row]=riscv_m31_add(output[2ul*row_count+row],result.c);
 output[3ul*row_count+row]=riscv_m31_add(output[3ul*row_count+row],result.d);
}
kernel void stwo_zig_secure_interaction_v1_50a4766b4d66545037f7f8ca019e928e8d2d9c01a14f24f13913df09f9345630(device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *reserved [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]], device const uint *range_inverses [[buffer(8)]], uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 uint bits = ctz(row_count), circle = riscv_bit_reverse(row, bits);
 uint logical = circle < row_count/2u ? 2u*circle : 2u*(row_count-1u-circle)+1u;
 uint previous_logical = (logical+row_count-1u)%row_count;
 uint previous_row = framework_interaction_row(previous_logical,row_count);
 if(tree0[column_offsets[0u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v0 = { tree0[column_offsets[0u]+row],0u,0u,0u };
 if(tree0[column_offsets[1u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v1 = { tree0[column_offsets[1u]+row],0u,0u,0u };
 if(tree0[column_offsets[2u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v2 = { tree0[column_offsets[2u]+row],0u,0u,0u };
 if(tree0[column_offsets[3u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v3 = { tree0[column_offsets[3u]+row],0u,0u,0u };
 if(tree0[column_offsets[4u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v4 = { tree0[column_offsets[4u]+row],0u,0u,0u };
 if(tree0[column_offsets[5u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v5 = { tree0[column_offsets[5u]+row],0u,0u,0u };
 if(tree0[column_offsets[6u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v6 = { tree0[column_offsets[6u]+row],0u,0u,0u };
 if(tree0[column_offsets[7u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v7 = { tree0[column_offsets[7u]+row],0u,0u,0u };
 if(tree0[column_offsets[8u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v8 = { tree0[column_offsets[8u]+row],0u,0u,0u };
 if(tree0[column_offsets[9u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v9 = { tree0[column_offsets[9u]+row],0u,0u,0u };
 if(tree0[column_offsets[10u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v10 = { tree0[column_offsets[10u]+row],0u,0u,0u };
 if(tree0[column_offsets[11u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v11 = { tree0[column_offsets[11u]+row],0u,0u,0u };
 if(tree1[column_offsets[12u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v12 = { tree1[column_offsets[12u]+row],0u,0u,0u };
 if(tree1[column_offsets[13u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v13 = { tree1[column_offsets[13u]+row],0u,0u,0u };
 if(tree1[column_offsets[14u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v14 = { tree1[column_offsets[14u]+row],0u,0u,0u };
 if(tree1[column_offsets[15u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v15 = { tree1[column_offsets[15u]+row],0u,0u,0u };
 if(tree1[column_offsets[16u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v16 = { tree1[column_offsets[16u]+row],0u,0u,0u };
 if(tree1[column_offsets[17u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v17 = { tree1[column_offsets[17u]+row],0u,0u,0u };
 if(tree1[column_offsets[18u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v18 = { tree1[column_offsets[18u]+row],0u,0u,0u };
 if(tree1[column_offsets[19u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v19 = { tree1[column_offsets[19u]+row],0u,0u,0u };
 if(tree1[column_offsets[20u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v20 = { tree1[column_offsets[20u]+row],0u,0u,0u };
 if(tree1[column_offsets[21u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v21 = { tree1[column_offsets[21u]+row],0u,0u,0u };
 if(tree1[column_offsets[22u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v22 = { tree1[column_offsets[22u]+row],0u,0u,0u };
 if(tree1[column_offsets[23u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v23 = { tree1[column_offsets[23u]+row],0u,0u,0u };
 if(tree1[column_offsets[24u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v24 = { tree1[column_offsets[24u]+row],0u,0u,0u };
 if(tree1[column_offsets[25u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v25 = { tree1[column_offsets[25u]+row],0u,0u,0u };
 if(tree1[column_offsets[26u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v26 = { tree1[column_offsets[26u]+row],0u,0u,0u };
 if(tree1[column_offsets[27u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v27 = { tree1[column_offsets[27u]+row],0u,0u,0u };
 if(tree1[column_offsets[28u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v28 = { tree1[column_offsets[28u]+row],0u,0u,0u };
 if(tree1[column_offsets[29u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v29 = { tree1[column_offsets[29u]+row],0u,0u,0u };
 if(tree1[column_offsets[30u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v30 = { tree1[column_offsets[30u]+row],0u,0u,0u };
 if(tree1[column_offsets[31u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v31 = { tree1[column_offsets[31u]+row],0u,0u,0u };
 if(tree1[column_offsets[32u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v32 = { tree1[column_offsets[32u]+row],0u,0u,0u };
 if(tree1[column_offsets[33u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v33 = { tree1[column_offsets[33u]+row],0u,0u,0u };
 if(tree1[column_offsets[34u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v34 = { tree1[column_offsets[34u]+row],0u,0u,0u };
 if(tree1[column_offsets[35u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v35 = { tree1[column_offsets[35u]+row],0u,0u,0u };
 if(tree1[column_offsets[36u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v36 = { tree1[column_offsets[36u]+row],0u,0u,0u };
 if(tree1[column_offsets[37u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v37 = { tree1[column_offsets[37u]+row],0u,0u,0u };
 if(tree1[column_offsets[38u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v38 = { tree1[column_offsets[38u]+row],0u,0u,0u };
 if(tree1[column_offsets[39u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v39 = { tree1[column_offsets[39u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[40u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v40 = { tree1[column_offsets[40u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[41u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v41 = { tree1[column_offsets[41u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[42u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v42 = { tree1[column_offsets[42u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[43u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v43 = { tree1[column_offsets[43u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[44u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v44 = { tree1[column_offsets[44u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[45u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v45 = { tree1[column_offsets[45u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[46u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v46 = { tree1[column_offsets[46u]+previous_row],0u,0u,0u };
 if(tree1[column_offsets[47u]+previous_row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v47 = { tree1[column_offsets[47u]+previous_row],0u,0u,0u };
 RiscvQm31 v48 = { 1u,0u,0u,0u };
 RiscvQm31 v49 = riscv_qm_sub(v48,v13);
 RiscvQm31 v50 = riscv_qm_mul(v12,v49);
 RiscvQm31 v51 = { 1u,0u,0u,0u };
 RiscvQm31 v52 = riscv_qm_sub(v51,v13);
 RiscvQm31 v53 = riscv_qm_mul(v12,v52);
 RiscvQm31 v54 = { 1u,0u,0u,0u };
 RiscvQm31 v55 = riscv_qm_sub(v54,v13);
 RiscvQm31 v56 = riscv_qm_mul(v12,v55);
 RiscvQm31 v57 = riscv_qm_mul(v12,v13);
 RiscvQm31 v58 = riscv_qm_mul(v12,v13);
 RiscvQm31 v59 = riscv_qm_mul(v12,v13);
 RiscvQm31 v60 = riscv_qm_mul(v12,v13);
 RiscvQm31 v61 = riscv_load_qm31(profile_parameters,0u);
 RiscvQm31 v62 = riscv_qm_sub(v61,v41);
 RiscvQm31 v63 = riscv_qm_mul(v1,v62);
 RiscvQm31 v64 = riscv_qm_add(v41,v63);
 RiscvQm31 v65 = riscv_load_qm31(profile_parameters,4u);
 RiscvQm31 v66 = riscv_qm_sub(v65,v39);
 RiscvQm31 v67 = riscv_qm_mul(v1,v66);
 RiscvQm31 v68 = riscv_qm_add(v39,v67);
 RiscvQm31 v69 = riscv_load_qm31(profile_parameters,8u);
 RiscvQm31 v70 = riscv_qm_sub(v69,v40);
 RiscvQm31 v71 = riscv_qm_mul(v1,v70);
 RiscvQm31 v72 = riscv_qm_add(v40,v71);
 RiscvQm31 v73 = riscv_load_qm31(profile_parameters,12u);
 RiscvQm31 v74 = riscv_qm_sub(v73,v42);
 RiscvQm31 v75 = riscv_qm_mul(v1,v74);
 RiscvQm31 v76 = riscv_qm_add(v42,v75);
 RiscvQm31 v77 = riscv_load_qm31(profile_parameters,16u);
 RiscvQm31 v78 = riscv_qm_sub(v77,v43);
 RiscvQm31 v79 = riscv_qm_mul(v1,v78);
 RiscvQm31 v80 = riscv_qm_add(v43,v79);
 RiscvQm31 v81 = riscv_load_qm31(profile_parameters,20u);
 RiscvQm31 v82 = riscv_qm_sub(v81,v44);
 RiscvQm31 v83 = riscv_qm_mul(v1,v82);
 RiscvQm31 v84 = riscv_qm_add(v44,v83);
 RiscvQm31 v85 = riscv_load_qm31(profile_parameters,24u);
 RiscvQm31 v86 = riscv_qm_sub(v85,v45);
 RiscvQm31 v87 = riscv_qm_mul(v1,v86);
 RiscvQm31 v88 = riscv_qm_add(v45,v87);
 RiscvQm31 v89 = riscv_load_qm31(profile_parameters,28u);
 RiscvQm31 v90 = riscv_qm_sub(v89,v46);
 RiscvQm31 v91 = riscv_qm_mul(v1,v90);
 RiscvQm31 v92 = riscv_qm_add(v46,v91);
 RiscvQm31 v93 = riscv_load_qm31(profile_parameters,32u);
 RiscvQm31 v94 = riscv_qm_sub(v93,v47);
 RiscvQm31 v95 = riscv_qm_mul(v1,v94);
 RiscvQm31 v96 = riscv_qm_add(v47,v95);
 RiscvQm31 v97 = riscv_load_qm31(profile_parameters,36u);
 RiscvQm31 v98 = riscv_qm_mul(v97,v16);
 RiscvQm31 v99 = { 0u,0u,0u,0u };
 RiscvQm31 v100 = riscv_qm_add(v99,v98);
 RiscvQm31 v101 = riscv_load_qm31(profile_parameters,40u);
 RiscvQm31 v102 = riscv_qm_mul(v101,v14);
 RiscvQm31 v103 = riscv_qm_add(v100,v102);
 RiscvQm31 v104 = riscv_load_qm31(profile_parameters,44u);
 RiscvQm31 v105 = riscv_qm_mul(v104,v15);
 RiscvQm31 v106 = riscv_qm_add(v103,v105);
 RiscvQm31 v107 = riscv_load_qm31(profile_parameters,48u);
 RiscvQm31 v108 = riscv_qm_mul(v107,v17);
 RiscvQm31 v109 = riscv_qm_add(v106,v108);
 RiscvQm31 v110 = riscv_load_qm31(profile_parameters,52u);
 RiscvQm31 v111 = riscv_qm_mul(v110,v18);
 RiscvQm31 v112 = riscv_qm_add(v109,v111);
 RiscvQm31 v113 = riscv_load_qm31(profile_parameters,56u);
 RiscvQm31 v114 = riscv_qm_mul(v113,v19);
 RiscvQm31 v115 = riscv_qm_add(v112,v114);
 RiscvQm31 v116 = riscv_load_qm31(profile_parameters,60u);
 RiscvQm31 v117 = riscv_qm_mul(v116,v20);
 RiscvQm31 v118 = riscv_qm_add(v115,v117);
 RiscvQm31 v119 = riscv_load_qm31(profile_parameters,64u);
 RiscvQm31 v120 = riscv_qm_mul(v119,v21);
 RiscvQm31 v121 = riscv_qm_add(v118,v120);
 RiscvQm31 v122 = riscv_load_qm31(profile_parameters,68u);
 RiscvQm31 v123 = riscv_qm_mul(v122,v22);
 RiscvQm31 v124 = riscv_qm_add(v121,v123);
 RiscvQm31 v125 = riscv_load_qm31(profile_parameters,72u);
 RiscvQm31 v126 = riscv_qm_mul(v125,v37);
 RiscvQm31 v127 = riscv_qm_add(v124,v126);
 RiscvQm31 v128 = riscv_load_qm31(profile_parameters,76u);
 RiscvQm31 v129 = riscv_qm_mul(v128,v38);
 RiscvQm31 v130 = riscv_qm_add(v127,v129);
 RiscvQm31 v131 = riscv_load_qm31(profile_parameters,80u);
 RiscvQm31 v132 = riscv_qm_sub(v130,v131);
 RiscvQm31 v133 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v134 = riscv_load_qm31(profile_parameters,84u);
 RiscvQm31 v135 = riscv_qm_mul(v134,v4);
 RiscvQm31 v136 = { 0u,0u,0u,0u };
 RiscvQm31 v137 = riscv_qm_add(v136,v135);
 RiscvQm31 v138 = riscv_load_qm31(profile_parameters,88u);
 RiscvQm31 v139 = riscv_qm_mul(v138,v5);
 RiscvQm31 v140 = riscv_qm_add(v137,v139);
 RiscvQm31 v141 = riscv_load_qm31(profile_parameters,92u);
 RiscvQm31 v142 = riscv_qm_mul(v141,v6);
 RiscvQm31 v143 = riscv_qm_add(v140,v142);
 RiscvQm31 v144 = riscv_load_qm31(profile_parameters,96u);
 RiscvQm31 v145 = riscv_qm_mul(v144,v7);
 RiscvQm31 v146 = riscv_qm_add(v143,v145);
 RiscvQm31 v147 = riscv_load_qm31(profile_parameters,100u);
 RiscvQm31 v148 = riscv_qm_mul(v147,v16);
 RiscvQm31 v149 = riscv_qm_add(v146,v148);
 RiscvQm31 v150 = riscv_load_qm31(profile_parameters,104u);
 RiscvQm31 v151 = riscv_qm_mul(v150,v14);
 RiscvQm31 v152 = riscv_qm_add(v149,v151);
 RiscvQm31 v153 = riscv_load_qm31(profile_parameters,108u);
 RiscvQm31 v154 = riscv_qm_mul(v153,v15);
 RiscvQm31 v155 = riscv_qm_add(v152,v154);
 RiscvQm31 v156 = riscv_load_qm31(profile_parameters,112u);
 RiscvQm31 v157 = riscv_qm_mul(v156,v17);
 RiscvQm31 v158 = riscv_qm_add(v155,v157);
 RiscvQm31 v159 = riscv_load_qm31(profile_parameters,116u);
 RiscvQm31 v160 = riscv_qm_mul(v159,v18);
 RiscvQm31 v161 = riscv_qm_add(v158,v160);
 RiscvQm31 v162 = riscv_load_qm31(profile_parameters,120u);
 RiscvQm31 v163 = riscv_qm_mul(v162,v19);
 RiscvQm31 v164 = riscv_qm_add(v161,v163);
 RiscvQm31 v165 = riscv_load_qm31(profile_parameters,124u);
 RiscvQm31 v166 = riscv_qm_mul(v165,v20);
 RiscvQm31 v167 = riscv_qm_add(v164,v166);
 RiscvQm31 v168 = riscv_load_qm31(profile_parameters,128u);
 RiscvQm31 v169 = riscv_qm_mul(v168,v37);
 RiscvQm31 v170 = riscv_qm_add(v167,v169);
 RiscvQm31 v171 = riscv_load_qm31(profile_parameters,132u);
 RiscvQm31 v172 = riscv_qm_mul(v171,v38);
 RiscvQm31 v173 = riscv_qm_add(v170,v172);
 RiscvQm31 v174 = riscv_load_qm31(profile_parameters,136u);
 RiscvQm31 v175 = riscv_qm_sub(v173,v174);
 RiscvQm31 v176 = riscv_qm_sub(v0,v2);
 RiscvQm31 v177 = riscv_load_qm31(profile_parameters,140u);
 RiscvQm31 v178 = riscv_qm_mul(v177,v8);
 RiscvQm31 v179 = { 0u,0u,0u,0u };
 RiscvQm31 v180 = riscv_qm_add(v179,v178);
 RiscvQm31 v181 = riscv_load_qm31(profile_parameters,144u);
 RiscvQm31 v182 = riscv_qm_mul(v181,v9);
 RiscvQm31 v183 = riscv_qm_add(v180,v182);
 RiscvQm31 v184 = riscv_load_qm31(profile_parameters,148u);
 RiscvQm31 v185 = riscv_qm_mul(v184,v10);
 RiscvQm31 v186 = riscv_qm_add(v183,v185);
 RiscvQm31 v187 = riscv_load_qm31(profile_parameters,152u);
 RiscvQm31 v188 = riscv_qm_mul(v187,v11);
 RiscvQm31 v189 = riscv_qm_add(v186,v188);
 RiscvQm31 v190 = riscv_load_qm31(profile_parameters,156u);
 RiscvQm31 v191 = riscv_qm_mul(v190,v64);
 RiscvQm31 v192 = riscv_qm_add(v189,v191);
 RiscvQm31 v193 = riscv_load_qm31(profile_parameters,160u);
 RiscvQm31 v194 = riscv_qm_mul(v193,v68);
 RiscvQm31 v195 = riscv_qm_add(v192,v194);
 RiscvQm31 v196 = riscv_load_qm31(profile_parameters,164u);
 RiscvQm31 v197 = riscv_qm_mul(v196,v72);
 RiscvQm31 v198 = riscv_qm_add(v195,v197);
 RiscvQm31 v199 = riscv_load_qm31(profile_parameters,168u);
 RiscvQm31 v200 = riscv_qm_mul(v199,v76);
 RiscvQm31 v201 = riscv_qm_add(v198,v200);
 RiscvQm31 v202 = riscv_load_qm31(profile_parameters,172u);
 RiscvQm31 v203 = riscv_qm_mul(v202,v80);
 RiscvQm31 v204 = riscv_qm_add(v201,v203);
 RiscvQm31 v205 = riscv_load_qm31(profile_parameters,176u);
 RiscvQm31 v206 = riscv_qm_mul(v205,v84);
 RiscvQm31 v207 = riscv_qm_add(v204,v206);
 RiscvQm31 v208 = riscv_load_qm31(profile_parameters,180u);
 RiscvQm31 v209 = riscv_qm_mul(v208,v88);
 RiscvQm31 v210 = riscv_qm_add(v207,v209);
 RiscvQm31 v211 = riscv_load_qm31(profile_parameters,184u);
 RiscvQm31 v212 = riscv_qm_mul(v211,v92);
 RiscvQm31 v213 = riscv_qm_add(v210,v212);
 RiscvQm31 v214 = riscv_load_qm31(profile_parameters,188u);
 RiscvQm31 v215 = riscv_qm_mul(v214,v96);
 RiscvQm31 v216 = riscv_qm_add(v213,v215);
 RiscvQm31 v217 = riscv_load_qm31(profile_parameters,192u);
 RiscvQm31 v218 = riscv_qm_sub(v216,v217);
 RiscvQm31 v219 = riscv_qm_sub(v0,v1);
 RiscvQm31 v220 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v219);
 RiscvQm31 v221 = riscv_load_qm31(profile_parameters,196u);
 RiscvQm31 v222 = riscv_qm_mul(v221,v16);
 RiscvQm31 v223 = { 0u,0u,0u,0u };
 RiscvQm31 v224 = riscv_qm_add(v223,v222);
 RiscvQm31 v225 = riscv_load_qm31(profile_parameters,200u);
 RiscvQm31 v226 = riscv_qm_mul(v225,v14);
 RiscvQm31 v227 = riscv_qm_add(v224,v226);
 RiscvQm31 v228 = riscv_load_qm31(profile_parameters,204u);
 RiscvQm31 v229 = riscv_qm_mul(v228,v15);
 RiscvQm31 v230 = riscv_qm_add(v227,v229);
 RiscvQm31 v231 = riscv_load_qm31(profile_parameters,208u);
 RiscvQm31 v232 = riscv_qm_mul(v231,v21);
 RiscvQm31 v233 = riscv_qm_add(v230,v232);
 RiscvQm31 v234 = riscv_load_qm31(profile_parameters,212u);
 RiscvQm31 v235 = riscv_qm_mul(v234,v22);
 RiscvQm31 v236 = riscv_qm_add(v233,v235);
 RiscvQm31 v237 = riscv_load_qm31(profile_parameters,216u);
 RiscvQm31 v238 = riscv_qm_sub(v236,v237);
 RiscvQm31 v239 = { 1u,0u,0u,0u };
 RiscvQm31 v240 = riscv_qm_sub(v239,v13);
 RiscvQm31 v241 = riscv_qm_mul(v12,v240);
 RiscvQm31 v242 = riscv_qm_add(v1,v241);
 RiscvQm31 v243 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v242);
 RiscvQm31 v244 = { 1u,0u,0u,0u };
 RiscvQm31 v245 = riscv_qm_sub(v244,v13);
 RiscvQm31 v246 = riscv_qm_mul(v12,v245);
 RiscvQm31 v247 = { 1u,0u,0u,0u };
 RiscvQm31 v248 = riscv_qm_sub(v247,v1);
 RiscvQm31 v249 = riscv_qm_mul(v246,v248);
 RiscvQm31 v250 = riscv_load_qm31(profile_parameters,220u);
 RiscvQm31 v251 = riscv_qm_mul(v250,v41);
 RiscvQm31 v252 = { 0u,0u,0u,0u };
 RiscvQm31 v253 = riscv_qm_add(v252,v251);
 RiscvQm31 v254 = riscv_load_qm31(profile_parameters,224u);
 RiscvQm31 v255 = riscv_qm_mul(v254,v39);
 RiscvQm31 v256 = riscv_qm_add(v253,v255);
 RiscvQm31 v257 = riscv_load_qm31(profile_parameters,228u);
 RiscvQm31 v258 = riscv_qm_mul(v257,v40);
 RiscvQm31 v259 = riscv_qm_add(v256,v258);
 RiscvQm31 v260 = riscv_load_qm31(profile_parameters,232u);
 RiscvQm31 v261 = riscv_qm_mul(v260,v42);
 RiscvQm31 v262 = riscv_qm_add(v259,v261);
 RiscvQm31 v263 = riscv_load_qm31(profile_parameters,236u);
 RiscvQm31 v264 = riscv_qm_mul(v263,v43);
 RiscvQm31 v265 = riscv_qm_add(v262,v264);
 RiscvQm31 v266 = riscv_load_qm31(profile_parameters,240u);
 RiscvQm31 v267 = riscv_qm_mul(v266,v44);
 RiscvQm31 v268 = riscv_qm_add(v265,v267);
 RiscvQm31 v269 = riscv_load_qm31(profile_parameters,244u);
 RiscvQm31 v270 = riscv_qm_mul(v269,v45);
 RiscvQm31 v271 = riscv_qm_add(v268,v270);
 RiscvQm31 v272 = riscv_load_qm31(profile_parameters,248u);
 RiscvQm31 v273 = riscv_qm_mul(v272,v46);
 RiscvQm31 v274 = riscv_qm_add(v271,v273);
 RiscvQm31 v275 = riscv_load_qm31(profile_parameters,252u);
 RiscvQm31 v276 = riscv_qm_mul(v275,v47);
 RiscvQm31 v277 = riscv_qm_add(v274,v276);
 RiscvQm31 v278 = riscv_load_qm31(profile_parameters,256u);
 RiscvQm31 v279 = riscv_qm_sub(v277,v278);
 RiscvQm31 v280 = riscv_qm_mul(v249,v41);
 RiscvQm31 v281 = riscv_load_qm31(profile_parameters,260u);
 RiscvQm31 v282 = riscv_qm_mul(v1,v281);
 RiscvQm31 v283 = riscv_load_qm31(profile_parameters,264u);
 RiscvQm31 v284 = riscv_qm_mul(v2,v283);
 RiscvQm31 v285 = riscv_qm_add(v282,v284);
 RiscvQm31 v286 = riscv_load_qm31(profile_parameters,268u);
 RiscvQm31 v287 = riscv_qm_mul(v1,v286);
 RiscvQm31 v288 = riscv_qm_add(v280,v287);
 RiscvQm31 v289 = riscv_load_qm31(profile_parameters,272u);
 RiscvQm31 v290 = riscv_qm_mul(v2,v289);
 RiscvQm31 v291 = riscv_qm_add(v288,v290);
 RiscvQm31 v292 = { 1u,0u,0u,0u };
 RiscvQm31 v293 = riscv_qm_sub(v292,v41);
 RiscvQm31 v294 = riscv_qm_mul(v249,v293);
 RiscvQm31 v295 = riscv_load_qm31(profile_parameters,276u);
 RiscvQm31 v296 = riscv_qm_mul(v1,v295);
 RiscvQm31 v297 = riscv_load_qm31(profile_parameters,280u);
 RiscvQm31 v298 = riscv_qm_mul(v2,v297);
 RiscvQm31 v299 = riscv_qm_add(v296,v298);
 RiscvQm31 v300 = riscv_load_qm31(profile_parameters,284u);
 RiscvQm31 v301 = riscv_qm_mul(v1,v300);
 RiscvQm31 v302 = riscv_qm_add(v294,v301);
 RiscvQm31 v303 = riscv_load_qm31(profile_parameters,288u);
 RiscvQm31 v304 = riscv_qm_mul(v2,v303);
 RiscvQm31 v305 = riscv_qm_add(v302,v304);
 RiscvQm31 v306 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v307 = { 0u,0u,0u,0u };
 RiscvQm31 v308 = riscv_qm_add(v307,v0);
 RiscvQm31 v309 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v310 = riscv_qm_add(v308,v0);
 RiscvQm31 v311 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v312 = riscv_qm_add(v310,v0);
 RiscvQm31 v313 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v314 = riscv_qm_add(v312,v0);
 RiscvQm31 v315 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v316 = riscv_qm_add(v314,v0);
 RiscvQm31 v317 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v318 = riscv_qm_add(v316,v0);
 RiscvQm31 v319 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v320 = riscv_qm_add(v318,v0);
 RiscvQm31 v321 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v322 = riscv_qm_add(v320,v0);
 RiscvQm31 v323 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v324 = riscv_qm_add(v322,v0);
 RiscvQm31 v325 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v0);
 RiscvQm31 v326 = riscv_qm_add(v324,v0);
 RiscvQm31 v327 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v50);
 RiscvQm31 v328 = riscv_qm_add(v326,v50);
 RiscvQm31 v329 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v53);
 RiscvQm31 v330 = riscv_qm_add(v328,v53);
 RiscvQm31 v331 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v56);
 RiscvQm31 v332 = riscv_qm_add(v330,v56);
 RiscvQm31 v333 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v57);
 RiscvQm31 v334 = riscv_qm_add(v332,v57);
 RiscvQm31 v335 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v58);
 RiscvQm31 v336 = riscv_qm_add(v334,v58);
 RiscvQm31 v337 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v59);
 RiscvQm31 v338 = riscv_qm_add(v336,v59);
 RiscvQm31 v339 = riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},v60);
 RiscvQm31 v340 = riscv_qm_add(v338,v60);
 RiscvQm31 v341 = riscv_load_qm31(profile_parameters,292u);
 RiscvQm31 v342 = {0u,0u,0u,0u};
 if ((v133.a|v133.b|v133.c|v133.d)!=0u) {
   if ((v132.a|v132.b|v132.c|v132.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v342=riscv_qm_mul(v133,framework_interaction_inverse(v132));
 }
 RiscvQm31 v343 = {0u,0u,0u,0u};
 if ((v176.a|v176.b|v176.c|v176.d)!=0u) {
   if ((v175.a|v175.b|v175.c|v175.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v343=riscv_qm_mul(v176,framework_interaction_inverse(v175));
 }
 RiscvQm31 v344 = {0u,0u,0u,0u};
 if ((v220.a|v220.b|v220.c|v220.d)!=0u) {
   if ((v218.a|v218.b|v218.c|v218.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v344=riscv_qm_mul(v220,framework_interaction_inverse(v218));
 }
 RiscvQm31 v345 = riscv_qm_add(v343,v344);
 RiscvQm31 v346 = {0u,0u,0u,0u};
 if ((v243.a|v243.b|v243.c|v243.d)!=0u) {
   if ((v238.a|v238.b|v238.c|v238.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v346=riscv_qm_mul(v243,framework_interaction_inverse(v238));
 }
 RiscvQm31 v347 = {0u,0u,0u,0u};
 if ((v280.a|v280.b|v280.c|v280.d)!=0u) {
   if ((v279.a|v279.b|v279.c|v279.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v347=riscv_qm_mul(v280,framework_interaction_inverse(v279));
 }
 RiscvQm31 v348 = { 1u,0u,0u,0u };
 RiscvQm31 v349 = {0u,0u,0u,0u};
 if ((v285.a|v285.b|v285.c|v285.d)!=0u) {
   if ((v348.a|v348.b|v348.c|v348.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v349=riscv_qm_mul(v285,framework_interaction_inverse(v348));
 }
 RiscvQm31 v350 = riscv_qm_add(v347,v349);
 RiscvQm31 v351 = {0u,0u,0u,0u};
 if ((v294.a|v294.b|v294.c|v294.d)!=0u) {
   if ((v279.a|v279.b|v279.c|v279.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v351=riscv_qm_mul(v294,framework_interaction_inverse(v279));
 }
 RiscvQm31 v352 = { 1u,0u,0u,0u };
 RiscvQm31 v353 = {0u,0u,0u,0u};
 if ((v299.a|v299.b|v299.c|v299.d)!=0u) {
   if ((v352.a|v352.b|v352.c|v352.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v353=riscv_qm_mul(v299,framework_interaction_inverse(v352));
 }
 RiscvQm31 v354 = riscv_qm_add(v351,v353);
 RiscvQm31 v355={0u,0u,0u,0u};
 if((v306.a|v306.b|v306.c|v306.d)!=0u) {
   if((v14.b|v14.c|v14.d)!=0u || v14.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v14.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v355=riscv_qm_mul(v306,riscv_load_qm31(range_inverses,4u*v14.a));
 }
 RiscvQm31 v356={0u,0u,0u,0u};
 if((v309.a|v309.b|v309.c|v309.d)!=0u) {
   if((v15.b|v15.c|v15.d)!=0u || v15.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v15.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v356=riscv_qm_mul(v309,riscv_load_qm31(range_inverses,4u*v15.a));
 }
 RiscvQm31 v357 = riscv_qm_add(v355,v356);
 RiscvQm31 v358={0u,0u,0u,0u};
 if((v311.a|v311.b|v311.c|v311.d)!=0u) {
   if((v17.b|v17.c|v17.d)!=0u || v17.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v17.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v358=riscv_qm_mul(v311,riscv_load_qm31(range_inverses,4u*v17.a));
 }
 RiscvQm31 v359={0u,0u,0u,0u};
 if((v313.a|v313.b|v313.c|v313.d)!=0u) {
   if((v18.b|v18.c|v18.d)!=0u || v18.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v18.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v359=riscv_qm_mul(v313,riscv_load_qm31(range_inverses,4u*v18.a));
 }
 RiscvQm31 v360 = riscv_qm_add(v358,v359);
 RiscvQm31 v361={0u,0u,0u,0u};
 if((v315.a|v315.b|v315.c|v315.d)!=0u) {
   if((v19.b|v19.c|v19.d)!=0u || v19.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v19.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v361=riscv_qm_mul(v315,riscv_load_qm31(range_inverses,4u*v19.a));
 }
 RiscvQm31 v362={0u,0u,0u,0u};
 if((v317.a|v317.b|v317.c|v317.d)!=0u) {
   if((v20.b|v20.c|v20.d)!=0u || v20.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v20.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v362=riscv_qm_mul(v317,riscv_load_qm31(range_inverses,4u*v20.a));
 }
 RiscvQm31 v363 = riscv_qm_add(v361,v362);
 RiscvQm31 v364={0u,0u,0u,0u};
 if((v319.a|v319.b|v319.c|v319.d)!=0u) {
   if((v21.b|v21.c|v21.d)!=0u || v21.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v21.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v364=riscv_qm_mul(v319,riscv_load_qm31(range_inverses,4u*v21.a));
 }
 RiscvQm31 v365={0u,0u,0u,0u};
 if((v321.a|v321.b|v321.c|v321.d)!=0u) {
   if((v22.b|v22.c|v22.d)!=0u || v22.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v22.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v365=riscv_qm_mul(v321,riscv_load_qm31(range_inverses,4u*v22.a));
 }
 RiscvQm31 v366 = riscv_qm_add(v364,v365);
 RiscvQm31 v367={0u,0u,0u,0u};
 if((v323.a|v323.b|v323.c|v323.d)!=0u) {
   if((v37.b|v37.c|v37.d)!=0u || v37.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v37.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v367=riscv_qm_mul(v323,riscv_load_qm31(range_inverses,4u*v37.a));
 }
 RiscvQm31 v368={0u,0u,0u,0u};
 if((v325.a|v325.b|v325.c|v325.d)!=0u) {
   if((v38.b|v38.c|v38.d)!=0u || v38.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v38.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v368=riscv_qm_mul(v325,riscv_load_qm31(range_inverses,4u*v38.a));
 }
 RiscvQm31 v369 = riscv_qm_add(v367,v368);
 RiscvQm31 v370={0u,0u,0u,0u};
 if((v327.a|v327.b|v327.c|v327.d)!=0u) {
   if((v23.b|v23.c|v23.d)!=0u || v23.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v23.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v370=riscv_qm_mul(v327,riscv_load_qm31(range_inverses,4u*v23.a));
 }
 RiscvQm31 v371={0u,0u,0u,0u};
 if((v329.a|v329.b|v329.c|v329.d)!=0u) {
   if((v24.b|v24.c|v24.d)!=0u || v24.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v24.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v371=riscv_qm_mul(v329,riscv_load_qm31(range_inverses,4u*v24.a));
 }
 RiscvQm31 v372 = riscv_qm_add(v370,v371);
 RiscvQm31 v373={0u,0u,0u,0u};
 if((v331.a|v331.b|v331.c|v331.d)!=0u) {
   if((v25.b|v25.c|v25.d)!=0u || v25.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v25.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v373=riscv_qm_mul(v331,riscv_load_qm31(range_inverses,4u*v25.a));
 }
 RiscvQm31 v374={0u,0u,0u,0u};
 if((v333.a|v333.b|v333.c|v333.d)!=0u) {
   if((v29.b|v29.c|v29.d)!=0u || v29.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v29.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v374=riscv_qm_mul(v333,riscv_load_qm31(range_inverses,4u*v29.a));
 }
 RiscvQm31 v375 = riscv_qm_add(v373,v374);
 RiscvQm31 v376={0u,0u,0u,0u};
 if((v335.a|v335.b|v335.c|v335.d)!=0u) {
   if((v30.b|v30.c|v30.d)!=0u || v30.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v30.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v376=riscv_qm_mul(v335,riscv_load_qm31(range_inverses,4u*v30.a));
 }
 RiscvQm31 v377={0u,0u,0u,0u};
 if((v337.a|v337.b|v337.c|v337.d)!=0u) {
   if((v31.b|v31.c|v31.d)!=0u || v31.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v31.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v377=riscv_qm_mul(v337,riscv_load_qm31(range_inverses,4u*v31.a));
 }
 RiscvQm31 v378 = riscv_qm_add(v376,v377);
 RiscvQm31 v379={0u,0u,0u,0u};
 if((v339.a|v339.b|v339.c|v339.d)!=0u) {
   if((v32.b|v32.c|v32.d)!=0u || v32.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v32.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v379=riscv_qm_mul(v339,riscv_load_qm31(range_inverses,4u*v32.a));
 }
 framework_interaction_store(output,row_count,0u,row,v342);
 framework_interaction_store(output,row_count,1u,row,v345);
 framework_interaction_store(output,row_count,2u,row,v346);
 framework_interaction_store(output,row_count,3u,row,v350);
 framework_interaction_store(output,row_count,4u,row,v291);
 framework_interaction_store(output,row_count,5u,row,v340);
 framework_interaction_store(output,row_count,6u,row,v354);
 framework_interaction_store(output,row_count,7u,row,v305);
 framework_interaction_store(output,row_count,8u,row,v357);
 framework_interaction_store(output,row_count,9u,row,v360);
 framework_interaction_store(output,row_count,10u,row,v363);
 framework_interaction_store(output,row_count,11u,row,v366);
 framework_interaction_store(output,row_count,12u,row,v369);
 framework_interaction_store(output,row_count,13u,row,v372);
 framework_interaction_store(output,row_count,14u,row,v375);
 framework_interaction_store(output,row_count,15u,row,v378);
 framework_interaction_store(output,row_count,16u,row,v379);
}
kernel void stwo_zig_framework_poly_v1_4fca746d2126cc57acaf2644ccd53bcb7d6df20efabcddc3ecea5058bc51c2e5(device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]], device const uint *tree2 [[buffer(2)]],
 device const ulong *column_offsets [[buffer(3)]], device const uint *profile_parameters [[buffer(4)]], device const uint *reserved [[buffer(5)]],
 device const uint *powers [[buffer(6)]], device uint *output [[buffer(7)]], constant uint &row_count [[buffer(8)]],
 constant uint *denominator_inverses [[buffer(9)]], constant uint &denominator_count [[buffer(10)]], uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 uint previous_row = riscv_previous_circle_row(row,row_count,denominator_count);
 RiscvQm31 v0 = { tree0[column_offsets[0u]+row],0u,0u,0u };
 RiscvQm31 v1 = { tree1[column_offsets[1u]+row],0u,0u,0u };
 RiscvQm31 v2 = { tree2[column_offsets[2u]+row],0u,0u,0u };
 RiscvQm31 v3 = { tree2[column_offsets[3u]+row],0u,0u,0u };
 RiscvQm31 v4 = { tree2[column_offsets[4u]+row],0u,0u,0u };
 RiscvQm31 v5 = { tree2[column_offsets[5u]+row],0u,0u,0u };
 RiscvQm31 v6 = { tree2[column_offsets[6u]+row],0u,0u,0u };
 RiscvQm31 v7 = { tree2[column_offsets[7u]+row],0u,0u,0u };
 RiscvQm31 v8 = { tree2[column_offsets[8u]+row],0u,0u,0u };
 RiscvQm31 v9 = { tree2[column_offsets[9u]+row],0u,0u,0u };
 RiscvQm31 v10 = { tree2[column_offsets[10u]+previous_row],0u,0u,0u };
 RiscvQm31 v11 = { tree2[column_offsets[11u]+previous_row],0u,0u,0u };
 RiscvQm31 v12 = { tree2[column_offsets[12u]+previous_row],0u,0u,0u };
 RiscvQm31 v13 = { tree2[column_offsets[13u]+previous_row],0u,0u,0u };
 RiscvQm31 v14 = { tree2[column_offsets[14u]+previous_row],0u,0u,0u };
 RiscvQm31 v15 = { tree2[column_offsets[15u]+previous_row],0u,0u,0u };
 RiscvQm31 v16 = { tree2[column_offsets[16u]+previous_row],0u,0u,0u };
 RiscvQm31 v17 = { tree2[column_offsets[17u]+previous_row],0u,0u,0u };
 RiscvQm31 v18 = { 0u,1u,0u,0u };
 RiscvQm31 v19 = riscv_qm_mul(v3,v18);
 RiscvQm31 v20 = riscv_qm_add(v2,v19);
 RiscvQm31 v21 = { 0u,0u,1u,0u };
 RiscvQm31 v22 = riscv_qm_mul(v4,v21);
 RiscvQm31 v23 = riscv_qm_add(v20,v22);
 RiscvQm31 v24 = { 0u,0u,0u,1u };
 RiscvQm31 v25 = riscv_qm_mul(v5,v24);
 RiscvQm31 v26 = riscv_qm_add(v23,v25);
 RiscvQm31 v27 = { 0u,1u,0u,0u };
 RiscvQm31 v28 = riscv_qm_mul(v11,v27);
 RiscvQm31 v29 = riscv_qm_add(v10,v28);
 RiscvQm31 v30 = { 0u,0u,1u,0u };
 RiscvQm31 v31 = riscv_qm_mul(v12,v30);
 RiscvQm31 v32 = riscv_qm_add(v29,v31);
 RiscvQm31 v33 = { 0u,0u,0u,1u };
 RiscvQm31 v34 = riscv_qm_mul(v13,v33);
 RiscvQm31 v35 = riscv_qm_add(v32,v34);
 RiscvQm31 v36 = riscv_qm_sub(v26,v35);
 RiscvQm31 v37 = riscv_load_qm31(profile_parameters,0u);
 RiscvQm31 v38 = riscv_qm_add(v36,v37);
 RiscvQm31 v39 = { 0u,1u,0u,0u };
 RiscvQm31 v40 = riscv_qm_mul(v7,v39);
 RiscvQm31 v41 = riscv_qm_add(v6,v40);
 RiscvQm31 v42 = { 0u,0u,1u,0u };
 RiscvQm31 v43 = riscv_qm_mul(v8,v42);
 RiscvQm31 v44 = riscv_qm_add(v41,v43);
 RiscvQm31 v45 = { 0u,0u,0u,1u };
 RiscvQm31 v46 = riscv_qm_mul(v9,v45);
 RiscvQm31 v47 = riscv_qm_add(v44,v46);
 RiscvQm31 v48 = { 0u,1u,0u,0u };
 RiscvQm31 v49 = riscv_qm_mul(v15,v48);
 RiscvQm31 v50 = riscv_qm_add(v14,v49);
 RiscvQm31 v51 = { 0u,0u,1u,0u };
 RiscvQm31 v52 = riscv_qm_mul(v16,v51);
 RiscvQm31 v53 = riscv_qm_add(v50,v52);
 RiscvQm31 v54 = { 0u,0u,0u,1u };
 RiscvQm31 v55 = riscv_qm_mul(v17,v54);
 RiscvQm31 v56 = riscv_qm_add(v53,v55);
 RiscvQm31 v57 = riscv_qm_sub(v47,v56);
 RiscvQm31 v58 = riscv_load_qm31(profile_parameters,4u);
 RiscvQm31 v59 = riscv_qm_add(v57,v58);
 RiscvQm31 v60 = riscv_load_qm31(profile_parameters,8u);
 RiscvQm31 v61 = riscv_qm_mul(v60,v0);
 RiscvQm31 v62 = { 0u,0u,0u,0u };
 RiscvQm31 v63 = riscv_qm_add(v62,v61);
 RiscvQm31 v64 = riscv_load_qm31(profile_parameters,12u);
 RiscvQm31 v65 = riscv_qm_sub(v63,v64);
 RiscvQm31 v66 = riscv_qm_mul(v38,v65);
 RiscvQm31 v67 = riscv_qm_sub(v66,v1);
 RiscvQm31 v68 = riscv_qm_sub(v59,v1);
 RiscvQm31 folded={0u,0u,0u,0u};
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,4u),v67));
 folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,0u),v68));
 RiscvQm31 result=riscv_qm_mul_base(folded,denominator_inverses[row/(row_count/denominator_count)]);
 output[ulong(row)]=riscv_m31_add(output[ulong(row)],result.a);
 output[ulong(row_count)+row]=riscv_m31_add(output[ulong(row_count)+row],result.b);
 output[2ul*row_count+row]=riscv_m31_add(output[2ul*row_count+row],result.c);
 output[3ul*row_count+row]=riscv_m31_add(output[3ul*row_count+row],result.d);
}
kernel void stwo_zig_secure_interaction_v1_2f1e9a21acc516404019e9136c90497c03bbb948c7b49c09868da5603cc65c9c(device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *reserved [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]], device const uint *range_inverses [[buffer(8)]], uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 uint bits = ctz(row_count), circle = riscv_bit_reverse(row, bits);
 uint logical = circle < row_count/2u ? 2u*circle : 2u*(row_count-1u-circle)+1u;
 uint previous_logical = (logical+row_count-1u)%row_count;
 uint previous_row = framework_interaction_row(previous_logical,row_count);
 if(tree0[column_offsets[0u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v0 = { tree0[column_offsets[0u]+row],0u,0u,0u };
 if(tree1[column_offsets[1u]+row]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
 RiscvQm31 v1 = { tree1[column_offsets[1u]+row],0u,0u,0u };
 RiscvQm31 v2 = riscv_load_qm31(profile_parameters,0u);
 RiscvQm31 v3={0u,0u,0u,0u};
 if((v1.a|v1.b|v1.c|v1.d)!=0u) {
   if((v0.b|v0.c|v0.d)!=0u || v0.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
   else if(range_inverses[262144u+v0.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
   else v3=riscv_qm_mul(v1,riscv_load_qm31(range_inverses,4u*v0.a));
 }
 framework_interaction_store(output,row_count,0u,row,v3);
 framework_interaction_store(output,row_count,1u,row,v1);
}
