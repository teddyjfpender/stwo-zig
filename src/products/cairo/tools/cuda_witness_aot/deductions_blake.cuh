// Whole Blake round reads the canonical execution-memory table ABI directly.
static __device__ __forceinline__ unsigned stwo_wit_read_small(
    const unsigned* const* tables, const unsigned* strides, unsigned address) {
    unsigned id = address < strides[0] ? tables[0][address] : 0x3fffffffu;
    if (id >= 0x40000000u || id >= strides[2]) return 0u;
    return tables[29][id] | (tables[30][id] << 9u) |
        (tables[31][id] << 18u) | ((tables[32][id] & 31u) << 27u);
}

static __device__ __forceinline__ void stwo_wit_deduce_blake_round(
    const unsigned* const* tables, const unsigned* strides,
    const unsigned* in, unsigned* out) {
    unsigned round = in[1] < 10u ? in[1] : 0u;
    unsigned state[16], message[16];
    for (unsigned i = 0; i < 16; ++i) {
        state[i] = in[2 + i];
        message[i] = stwo_wit_read_small(tables, strides,
            in[18] + STWO_WIT_BLAKE_SIGMA[round][i]);
    }
    const unsigned indices[32] = {
        0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15,
        0,5,10,15, 1,6,11,12, 2,7,8,13, 3,4,9,14
    };
    for (unsigned group = 0; group < 8; ++group) {
        unsigned at = group * 4u;
        unsigned args[6] = {state[indices[at]], state[indices[at + 1]],
            state[indices[at + 2]], state[indices[at + 3]],
            message[group * 2], message[group * 2 + 1]};
        unsigned mixed[4];
        stwo_wit_blake_g(args, mixed);
        for (unsigned i = 0; i < 4; ++i) state[indices[at + i]] = mixed[i];
    }
    out[0] = in[0]; out[1] = in[1] + 1u;
    for (unsigned i = 0; i < 16; ++i) out[2 + i] = state[i];
    out[18] = in[18];
}
