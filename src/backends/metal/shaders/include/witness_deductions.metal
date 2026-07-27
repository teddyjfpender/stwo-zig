#ifndef STWO_ZIG_WITNESS_DEDUCTIONS_METAL
#define STWO_ZIG_WITNESS_DEDUCTIONS_METAL

#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#include "stwo_zig/felt252.metal"
#include "stwo_zig/ec.metal"
#include "stwo_zig/witness_abi.metal"
#endif
inline Felt252Metal witness_from_w27(thread const uint *words) {
    uint limbs[28];
    for (uint i = 0u; i < 9u; ++i) {
        limbs[3u * i] = words[i] & 0x1ffu;
        limbs[3u * i + 1u] = (words[i] >> 9u) & 0x1ffu;
        limbs[3u * i + 2u] = (words[i] >> 18u) & 0x1ffu;
    }
    limbs[27] = words[9] & 0x1ffu;
    return felt_from_m31_words(limbs);
}

inline void witness_to_w27(thread const Felt252Metal &value, thread uint *words) {
    uint limbs[28]; felt_to_m31_words(value, limbs);
    for (uint i = 0u; i < 9u; ++i)
        words[i] = limbs[3u * i] | (limbs[3u * i + 1u] << 9u) | (limbs[3u * i + 2u] << 18u);
    words[9] = limbs[27];
}

inline Felt252Metal witness_value_mul(thread const Felt252Metal &a, thread const Felt252Metal &b) {
    Felt252Metal am = felt_to_montgomery(a), bm = felt_to_montgomery(b);
    return felt_from_montgomery(felt_mont_mul(am, bm));
}
inline Felt252Metal witness_value_cube(thread const Felt252Metal &value) {
    Felt252Metal square = witness_value_mul(value, value); return witness_value_mul(square, value);
}
inline Felt252Metal witness_poseidon_key(device uint *arena, constant WitnessArgs &args, uint round, uint key) {
    uint words[10]; uint safe_round = round < 35u ? round : 0u;
    for (uint i = 0u; i < 10u; ++i)
        words[i] = arena[arena[args.poseidon_keys + key * 10u + i] + safe_round];
    return witness_from_w27(words);
}

inline void witness_blake_mix(thread uint *values, uint m0, uint m1) {
    uint a=values[0], b=values[1], c=values[2], d=values[3];
    a=a+b+m0; d=d^a; d=(d>>16u)|(d<<16u); c+=d; b=b^c; b=(b>>12u)|(b<<20u);
    a=a+b+m1; d=d^a; d=(d>>8u)|(d<<24u); c+=d; b=b^c; b=(b>>7u)|(b<<25u);
    values[0]=a; values[1]=b; values[2]=c; values[3]=d;
}

[[clang::noinline]] void witness_deduce_0(device uint *, constant WitnessArgs &, thread const uint *input, thread uint *output) {
    for (uint i = 0u; i < 4u; ++i) output[i] = input[i];
    witness_blake_mix(output, input[4], input[5]);
}

constant uint witness_blake_sigma[160] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,
    11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4, 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,
    9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13, 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,
    12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11, 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,
    6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5, 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0
};
[[clang::noinline]] void witness_deduce_1(device uint *, constant WitnessArgs &, thread const uint *input, thread uint *output) {
    uint round = input[0] < 10u ? input[0] : 0u;
    for (uint i = 0u; i < 16u; ++i) output[i] = witness_blake_sigma[round * 16u + i];
}

[[clang::noinline]] void witness_deduce_3(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    uint row = input[0] & (args.pedersen_rows - 1u);
    for (uint column = 0u; column < 56u; ++column) output[column] = arena[arena[args.pedersen_offsets + column] + row];
}

inline EcPointMetal witness_ec_add(thread const EcPointMetal &left_standard, thread const EcPointMetal &right_standard) {
    EcPointMetal left = { felt_to_montgomery(left_standard.x), felt_to_montgomery(left_standard.y) };
    EcPointMetal right = { felt_to_montgomery(right_standard.x), felt_to_montgomery(right_standard.y) };
    Felt252Metal dx = felt_sub_252(right.x, left.x), dy = felt_sub_252(right.y, left.y);
    Felt252Metal inverse = felt_inverse_252(dx), slope = felt_mont_mul(dy, inverse);
    Felt252Metal x = felt_sub_252(felt_sub_252(felt_mont_mul(slope, slope), left.x), right.x);
    Felt252Metal y = felt_sub_252(felt_mont_mul(slope, felt_sub_252(left.x, x)), left.y);
    return { felt_from_montgomery(x), felt_from_montgomery(y) };
}

[[clang::noinline]] void witness_deduce_2(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    EcPointMetal accumulator = { felt_from_m31_words(input + 16), felt_from_m31_words(input + 44) };
    uint row = (input[1] * 262144u + input[2]) & (args.pedersen_rows - 1u), limbs[28];
    for (uint i = 0u; i < 28u; ++i) limbs[i] = arena[arena[args.pedersen_offsets + i] + row];
    EcPointMetal point; point.x = felt_from_m31_words(limbs);
    for (uint i = 0u; i < 28u; ++i) limbs[i] = arena[arena[args.pedersen_offsets + 28u + i] + row];
    point.y = felt_from_m31_words(limbs);
    EcPointMetal sum = witness_ec_add(accumulator, point);
    output[0]=input[0]; output[1]=input[1]+1u;
    for(uint i=0u;i<13u;++i) output[2u+i]=input[3u+i]; output[15]=0u;
    felt_to_m31_words(sum.x, output+16); felt_to_m31_words(sum.y, output+44);
}

[[clang::noinline]] void witness_deduce_felt_binary(uint kind, thread const uint *input, thread uint *output) {
    Felt252Metal a=felt_from_m31_words(input), b=felt_from_m31_words(input+28), result;
    if(kind==4u) result=felt_add_252(a,b);
    else if(kind==5u) result=felt_sub_252(a,b);
    else {
        Felt252Metal am=felt_to_montgomery(a), bm=felt_to_montgomery(b);
        if(kind==7u) bm=felt_inverse_252(bm);
        result=felt_from_montgomery(felt_mont_mul(am,bm));
    }
    felt_to_m31_words(result,output);
}
[[clang::noinline]] void witness_deduce_4(device uint *, constant WitnessArgs &, thread const uint *i, thread uint *o){witness_deduce_felt_binary(4u,i,o);}
[[clang::noinline]] void witness_deduce_5(device uint *, constant WitnessArgs &, thread const uint *i, thread uint *o){witness_deduce_felt_binary(5u,i,o);}
[[clang::noinline]] void witness_deduce_6(device uint *, constant WitnessArgs &, thread const uint *i, thread uint *o){witness_deduce_felt_binary(6u,i,o);}
[[clang::noinline]] void witness_deduce_7(device uint *, constant WitnessArgs &, thread const uint *i, thread uint *o){witness_deduce_felt_binary(7u,i,o);}

[[clang::noinline]] void witness_deduce_8(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    uint round=input[0]<35u?input[0]:0u;
    for(uint i=0u;i<30u;++i) output[i]=arena[arena[args.poseidon_keys+i]+round];
}
[[clang::noinline]] void witness_deduce_9(device uint *, constant WitnessArgs &, thread const uint *input, thread uint *output) {
    Felt252Metal value=witness_from_w27(input); value=witness_value_cube(value); witness_to_w27(value,output);
}
[[clang::noinline]] void witness_deduce_10(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    Felt252Metal x=witness_value_cube(witness_from_w27(input+2)), y=witness_value_cube(witness_from_w27(input+12)), z=witness_value_cube(witness_from_w27(input+22));
    Felt252Metal yz=felt_sub_252(y,z), xyz=felt_sub_252(x,yz), xyz_neg=felt_add_252(x,yz), xy=felt_add_252(x,y), two_xy=felt_add_252(xy,xy);
    Felt252Metal nx=felt_add_252(felt_add_252(two_xy,xyz),witness_poseidon_key(arena,args,input[1],0u));
    Felt252Metal ny=felt_add_252(xyz,witness_poseidon_key(arena,args,input[1],1u));
    Felt252Metal nz=felt_add_252(felt_sub_252(xyz_neg,z),witness_poseidon_key(arena,args,input[1],2u));
    output[0]=input[0]; output[1]=input[1]+1u; witness_to_w27(nx,output+2); witness_to_w27(ny,output+12); witness_to_w27(nz,output+22);
}
[[clang::noinline]] void witness_deduce_11(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    Felt252Metal state[4]; for(uint i=0u;i<4u;++i) state[i]=witness_from_w27(input+2u+i*10u);
    for(uint key=0u;key<3u;++key){
        Felt252Metal z23=witness_value_cube(state[3]), z03z13=felt_add_252(state[0],state[2]), z03z13z1=felt_add_252(z03z13,state[1]);
        Felt252Metal longsum=felt_add_252(felt_sub_252(felt_add_252(z03z13z1,state[3]),z23),witness_poseidon_key(arena,args,input[1],key));
        Felt252Metal half_z3=felt_add_252(felt_add_252(felt_add_252(longsum,z03z13z1),z03z13),state[0]), z3=felt_add_252(half_z3,half_z3);
        state[0]=state[2]; state[1]=state[3]; state[2]=z23; state[3]=z3;
    }
    output[0]=input[0]; output[1]=input[1]+1u; for(uint i=0u;i<4u;++i) witness_to_w27(state[i],output+2u+i*10u);
}

[[clang::noinline]] void witness_deduce_12(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    uint row = (input[1] * 512u + input[2]) & (args.pedersen_rows - 1u);
    uint limbs[28];
    EcPointMetal accumulator = {
        felt_from_m31_words(input + 30u),
        felt_from_m31_words(input + 58u)
    };
    EcPointMetal point;
    for (uint i = 0u; i < 28u; ++i)
        limbs[i] = arena[arena[args.pedersen_offsets + i] + row];
    point.x = felt_from_m31_words(limbs);
    for (uint i = 0u; i < 28u; ++i)
        limbs[i] = arena[arena[args.pedersen_offsets + 28u + i] + row];
    point.y = felt_from_m31_words(limbs);
    EcPointMetal sum = witness_ec_add(accumulator, point);
    output[0] = input[0];
    output[1] = input[1] + 1u;
    for (uint i = 0u; i < 27u; ++i) output[2u + i] = input[3u + i];
    output[29] = 0u;
    felt_to_m31_words(sum.x, output + 30u);
    felt_to_m31_words(sum.y, output + 58u);
}

[[clang::noinline]] void witness_deduce_13(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    uint row = input[0] & (args.pedersen_rows - 1u);
    for (uint column = 0u; column < 56u; ++column)
        output[column] = arena[arena[args.pedersen_offsets + column] + row];
}

inline EcPointMetal witness_ec_double(thread const EcPointMetal &point_standard) {
    EcPointMetal point = {
        felt_to_montgomery(point_standard.x),
        felt_to_montgomery(point_standard.y)
    };
    EcProjectiveMetal projective = ec_projective_double(
        ec_projective_from_affine(point)
    );
    Felt252Metal inverse = ec_felt_inverse_252(projective.z);
    EcPointMetal doubled = ec_projective_to_affine(projective, inverse);
    doubled.x = felt_from_montgomery(doubled.x);
    doubled.y = felt_from_montgomery(doubled.y);
    return doubled;
}

[[clang::noinline]] void witness_deduce_14(device uint *, constant WitnessArgs &, thread const uint *input, thread uint *output) {
    EcPointMetal point = {
        felt_from_m31_words(input + 12u),
        felt_from_m31_words(input + 40u)
    };
    EcPointMetal accumulator = {
        felt_from_m31_words(input + 68u),
        felt_from_m31_words(input + 96u)
    };
    output[0] = input[0];
    output[1] = input[1] == 0x7ffffffeu ? 0u : input[1] + 1u;
    if (input[124] == 0u) {
        for (uint i = 0u; i < 9u; ++i) output[2u + i] = input[3u + i];
        output[11] = 0u;
    } else {
        output[2] = input[2] >> 1u;
        for (uint i = 1u; i < 10u; ++i) output[2u + i] = input[2u + i];
    }
    EcPointMetal doubled = witness_ec_double(point);
    felt_to_m31_words(doubled.x, output + 12u);
    felt_to_m31_words(doubled.y, output + 40u);
    if ((input[2] & 1u) != 0u) accumulator = witness_ec_add(accumulator, point);
    felt_to_m31_words(accumulator.x, output + 68u);
    felt_to_m31_words(accumulator.y, output + 96u);
    output[124] = input[124] == 0u ? 26u : input[124] - 1u;
}

inline void witness_decode_u384(thread const uint *input, thread uint *output) {
    for (uint i = 0u; i < 12u; ++i) output[i] = 0u;
    for (uint felt = 0u; felt < 4u; ++felt) {
        for (uint limb = 0u; limb < 11u; ++limb) {
            uint bit = limb * 9u;
            uint word = bit >> 5u;
            uint shift = bit & 31u;
            uint value = input[felt * 28u + limb] & 0x1ffu;
            output[felt * 3u + word] |= value << shift;
            if (shift > 23u && word + 1u < 3u)
                output[felt * 3u + word + 1u] |= value >> (32u - shift);
        }
    }
}

inline uint witness_add_u384(
    thread const uint *left,
    thread const uint *right,
    thread uint *output
) {
    ulong carry = 0u;
    for (uint i = 0u; i < 12u; ++i) {
        ulong value = ulong(left[i]) + ulong(right[i]) + carry;
        output[i] = uint(value);
        carry = value >> 32u;
    }
    return uint(carry);
}

inline uint witness_sub_words(
    thread const uint *left,
    thread const uint *right,
    thread uint *output,
    uint words
) {
    ulong borrow = 0u;
    for (uint i = 0u; i < words; ++i) {
        ulong subtrahend = ulong(right[i]) + borrow;
        output[i] = left[i] - uint(subtrahend);
        borrow = ulong(left[i]) < subtrahend;
    }
    return uint(borrow);
}

[[clang::noinline]] void witness_deduce_15(device uint *, constant WitnessArgs &, thread const uint *input, thread uint *output) {
    uint a[12], b[12], c[12], sum[12], difference[12];
    witness_decode_u384(input, a);
    witness_decode_u384(input + 112u, b);
    witness_decode_u384(input + 224u, c);
    witness_add_u384(a, b, sum);
    witness_sub_words(sum, c, difference, 12u);
    uint combined = 0u;
    for (uint i = 0u; i < 12u; ++i) combined |= difference[i];
    output[0] = combined == 0u;
}

inline void witness_mul_u384(
    thread const uint *left,
    thread const uint *right,
    thread uint *output
) {
    for (uint i = 0u; i < 24u; ++i) output[i] = 0u;
    for (uint i = 0u; i < 12u; ++i) {
        ulong carry = 0u;
        for (uint j = 0u; j < 12u; ++j) {
            ulong value = ulong(left[i]) * ulong(right[j]) +
                ulong(output[i + j]) + carry;
            output[i + j] = uint(value);
            carry = value >> 32u;
        }
        uint cursor = i + 12u;
        while (carry != 0u && cursor < 24u) {
            ulong value = ulong(output[cursor]) + carry;
            output[cursor] = uint(value);
            carry = value >> 32u;
            ++cursor;
        }
    }
}

inline bool witness_remainder_ge(
    thread const uint *remainder,
    thread const uint *divisor
) {
    if (remainder[12] != 0u) return true;
    for (int i = 11; i >= 0; --i) {
        if (remainder[i] != divisor[i]) return remainder[i] > divisor[i];
    }
    return true;
}

inline void witness_div_u768_u384(
    thread const uint *numerator,
    thread const uint *divisor,
    thread uint *quotient
) {
    uint remainder[13];
    for (uint i = 0u; i < 13u; ++i) remainder[i] = 0u;
    for (uint i = 0u; i < 12u; ++i) quotient[i] = 0u;
    for (int bit = 767; bit >= 0; --bit) {
        uint carry = (numerator[uint(bit) >> 5u] >> (uint(bit) & 31u)) & 1u;
        for (uint i = 0u; i < 13u; ++i) {
            uint next = remainder[i] >> 31u;
            remainder[i] = (remainder[i] << 1u) | carry;
            carry = next;
        }
        if (witness_remainder_ge(remainder, divisor)) {
            ulong borrow = 0u;
            for (uint i = 0u; i < 12u; ++i) {
                ulong subtrahend = ulong(divisor[i]) + borrow;
                uint prior = remainder[i];
                remainder[i] = prior - uint(subtrahend);
                borrow = ulong(prior) < subtrahend;
            }
            remainder[12] -= uint(borrow);
            if (bit < 384) quotient[uint(bit) >> 5u] |= 1u << (uint(bit) & 31u);
        }
    }
}

[[clang::noinline]] void witness_deduce_16(device uint *, constant WitnessArgs &, thread const uint *input, thread uint *output) {
    uint p[12], a[12], b[12], c[12], product[24], extended_c[24], numerator[24], quotient[12];
    witness_decode_u384(input, p);
    witness_decode_u384(input + 112u, a);
    witness_decode_u384(input + 224u, b);
    witness_decode_u384(input + 336u, c);
    witness_mul_u384(a, b, product);
    for (uint i = 0u; i < 24u; ++i) extended_c[i] = i < 12u ? c[i] : 0u;
    witness_sub_words(product, extended_c, numerator, 24u);
    witness_div_u768_u384(numerator, p, quotient);
    for (uint word = 0u; word < 32u; ++word) {
        uint bit = word * 12u;
        uint limb = bit >> 5u;
        uint shift = bit & 31u;
        uint value = quotient[limb] >> shift;
        if (shift > 20u && limb + 1u < 12u)
            value |= quotient[limb + 1u] << (32u - shift);
        output[word] = value & 0xfffu;
    }
}

[[clang::noinline]] void witness_deduce_17(device uint *, constant WitnessArgs &, thread const uint *input, thread uint *output) {
    output[0] = input[0] ^ input[1] ^ input[2];
}

inline uint witness_read_small(
    device uint *arena,
    constant WitnessArgs &args,
    uint address
) {
    uint encoded = address < arena[args.table_strides]
        ? arena[arena[args.table_offsets] + address]
        : 0x3fffffffu;
    if (encoded >= 0x40000000u) return 0u;
    return witness_table_limb(arena, args, encoded, 0u) |
        (witness_table_limb(arena, args, encoded, 1u) << 9u) |
        (witness_table_limb(arena, args, encoded, 2u) << 18u) |
        ((witness_table_limb(arena, args, encoded, 3u) & 0x1fu) << 27u);
}

[[clang::noinline]] void witness_deduce_18(device uint *arena, constant WitnessArgs &args, thread const uint *input, thread uint *output) {
    uint round = input[1] < 10u ? input[1] : 0u;
    uint state[16], message[16];
    for (uint i = 0u; i < 16u; ++i) {
        state[i] = input[2u + i];
        message[i] = witness_read_small(
            arena,
            args,
            input[18] + witness_blake_sigma[round * 16u + i]
        );
    }
    const uint indices[32] = {
        0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15,
        0,5,10,15, 1,6,11,12, 2,7,8,13, 3,4,9,14
    };
    for (uint group = 0u; group < 8u; ++group) {
        uint at = group * 4u;
        uint mixed[4] = {
            state[indices[at]], state[indices[at + 1u]],
            state[indices[at + 2u]], state[indices[at + 3u]]
        };
        uint pair = group * 2u;
        witness_blake_mix(mixed, message[pair], message[pair + 1u]);
        for (uint i = 0u; i < 4u; ++i) state[indices[at + i]] = mixed[i];
    }
    output[0] = input[0];
    output[1] = input[1] + 1u;
    for (uint i = 0u; i < 16u; ++i) output[2u + i] = state[i];
    output[18] = input[18];
}

#endif
