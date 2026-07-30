// Stack-free native Blake-G producer/count feed.
//
// This file is included inside blake_witness.cu's anonymous namespace after
// the resident ABI structs and lo16/hi16 helpers are defined.  The generic
// recorded/legacy writer intentionally keeps its indexed c[73] compatibility
// plane.  This fused instantiation does not: every value is a named scalar,
// every output index is a template constant, and each phase is retired before
// the next one.  That makes a non-zero ptxas stack frame a release blocker for
// this kernel rather than accepting hidden thread-local row traffic.

#ifndef BLAKE_G_FUSED_SCALAR_CUH
#define BLAKE_G_FUSED_SCALAR_CUH

template <uint32_t Column>
DEVICE_FORCEINLINE void bg_trace(BlakeGResidentOutputs outputs, uint32_t row,
                                 uint32_t value) {
    static_assert(Column < BG_N_TRACE, "Blake-G trace column is out of range");
    outputs.trace[Column][row] = value;
}

template <uint32_t Word>
DEVICE_FORCEINLINE void bg_lookup(BlakeGResidentOutputs outputs, uint32_t row,
                                  uint32_t column_length, uint32_t value) {
    static_assert(Word < 87u, "Blake-G lookup word is out of range");
    if (outputs.lookup != nullptr) {
        outputs.lookup[(size_t)Word * column_length + row] = value;
    }
}

template <uint32_t Column>
DEVICE_FORCEINLINE void bg_aux(BlakeGResidentOutputs outputs, uint32_t row,
                               uint32_t column_length, uint32_t value) {
    static_assert(Column < BG_N_AUX, "Blake-G auxiliary column is out of range");
    if (outputs.aux != nullptr) {
        outputs.aux[(size_t)Column * column_length + row] = value;
    }
}

template <uint32_t Tuple, uint32_t Relation>
DEVICE_FORCEINLINE void bg_lookup_tuple(BlakeGResidentOutputs outputs,
                                        uint32_t row,
                                        uint32_t column_length, uint32_t a,
                                        uint32_t b, uint32_t x) {
    static_assert(Tuple < 16u, "Blake-G xor tuple is out of range");
    constexpr uint32_t base = 4u * Tuple;
    bg_lookup<base>(outputs, row, column_length, Relation);
    bg_lookup<base + 1u>(outputs, row, column_length, a);
    bg_lookup<base + 2u>(outputs, row, column_length, b);
    bg_lookup<base + 3u>(outputs, row, column_length, x);
}

template <uint32_t Lut, uint32_t Destination, uint32_t Bits,
          uint32_t Relation>
DEVICE_FORCEINLINE void bg_count_lut(BlakeGFusedFeed feed, uint32_t a,
                                     uint32_t b) {
    static_assert(Lut < 4u && Destination < 5u,
                  "Blake-G count binding is out of range");
    static_assert(Bits > 0u && Bits <= 15u,
                  "Blake-G xor table width is invalid");
    constexpr uint32_t table_size = 1u << (2u * Bits);
    if ((a | b) < (1u << Bits)) {
        uint32_t index = feed.luts[Lut][(a << Bits) | b];
        if (index < table_size) {
            atomicAdd(&feed.counts[Destination]
                                   [(size_t)Relation * table_size + index],
                      1u);
        }
    }
}

DEVICE_FORCEINLINE void bg_count_xor12(BlakeGFusedFeed feed, uint32_t a,
                                       uint32_t b) {
    if ((a | b) < (1u << 12)) {
        uint32_t column = ((a >> 10) << 2) | (b >> 10);
        uint32_t table_row = ((a & 0x3ffu) << 10) | (b & 0x3ffu);
        atomicAdd(&feed.counts[1][(size_t)column * (1u << 20) + table_row],
                  1u);
    }
}

#include "blake_g_row_evaluator.cuh"

struct BlakeGWitnessRowSink {
    BlakeGResidentOutputs outputs;
    BlakeGFusedFeed feed;
    uint32_t row;
    uint32_t column_length;

    template <uint32_t Column>
    DEVICE_FORCEINLINE void trace(uint32_t value) {
        bg_trace<Column>(outputs, row, value);
    }

    template <uint32_t Column>
    DEVICE_FORCEINLINE void auxiliary(uint32_t value) {
        bg_aux<Column>(outputs, row, column_length, value);
    }

    template <uint32_t Tuple, uint32_t Relation>
    DEVICE_FORCEINLINE void tuple(uint32_t a, uint32_t b, uint32_t x) {
        bg_lookup_tuple<Tuple, Relation>(outputs, row, column_length, a, b, x);
    }

    template <uint32_t Lut, uint32_t Destination, uint32_t Bits,
              uint32_t Relation>
    DEVICE_FORCEINLINE void count_lut(uint32_t a, uint32_t b) {
        bg_count_lut<Lut, Destination, Bits, Relation>(feed, a, b);
    }

    DEVICE_FORCEINLINE void count_xor12(uint32_t a, uint32_t b) {
        bg_count_xor12(feed, a, b);
    }

    template <uint32_t Word>
    DEVICE_FORCEINLINE void lookup(uint32_t value) {
        bg_lookup<Word>(outputs, row, column_length, value);
    }
};

__global__ void blake_g_write_trace_fused_scalar_kernel(
    BlakeGColumnInputs inputs, uint32_t n_rows, uint32_t column_length,
    BlakeGResidentOutputs outputs, BlakeGFusedFeed feed) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }

    const uint32_t in0 = inputs.columns[0][row];
    const uint32_t in1 = inputs.columns[1][row];
    const uint32_t in2 = inputs.columns[2][row];
    const uint32_t in3 = inputs.columns[3][row];
    const uint32_t in4 = inputs.columns[4][row];
    const uint32_t in5 = inputs.columns[5][row];

    BlakeGWitnessRowSink sink = {outputs, feed, row, column_length};
    blake_g_evaluate_row(in0, in1, in2, in3, in4, in5, row, n_rows, sink);
}

#endif  // BLAKE_G_FUSED_SCALAR_CUH
