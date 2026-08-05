#include <metal_stdlib>

using namespace metal;

kernel void stwo_cumetal_decommit_normalize(
    device const uint *raw_queries [[buffer(0)]],
    constant uint &raw_query_count [[buffer(1)]],
    constant uint &query_log_size [[buffer(2)]],
    constant uint &tree_count [[buffer(3)]],
    device uint *unique_queries [[buffer(4)]],
    device uint *unique_count [[buffer(5)]],
    device uint *assembly [[buffer(6)]],
    constant uint &assembly_capacity_words [[buffer(7)]]) {
    constexpr uint kHeaderWords = 8;
    constexpr uint kTreeMetaWords = 16;
    constexpr uint kMagic = 0x44575453u;
    const uint mask = (1u << query_log_size) - 1u;

    for (uint index = 0; index < raw_query_count; ++index) {
        unique_queries[index] = raw_queries[index] & mask;
    }
    for (uint index = 1; index < raw_query_count; ++index) {
        const uint value = unique_queries[index];
        uint insertion = index;
        while (insertion != 0 && unique_queries[insertion - 1] > value) {
            unique_queries[insertion] = unique_queries[insertion - 1];
            --insertion;
        }
        unique_queries[insertion] = value;
    }
    uint count = 0;
    for (uint index = 0; index < raw_query_count; ++index) {
        if (count == 0 || unique_queries[index] != unique_queries[count - 1]) {
            unique_queries[count++] = unique_queries[index];
        }
    }
    *unique_count = count;

    const uint raw_offset = kHeaderWords + tree_count * kTreeMetaWords;
    const uint unique_offset = raw_offset + raw_query_count;
    const uint used_words = unique_offset + count;
    if (used_words > assembly_capacity_words) {
        assembly[7] = 0;
        return;
    }
    assembly[0] = kMagic;
    assembly[1] = 1;
    assembly[2] = tree_count;
    assembly[3] = raw_query_count;
    assembly[4] = count;
    assembly[5] = raw_offset;
    assembly[6] = unique_offset;
    assembly[7] = used_words;
    for (uint index = 0; index < tree_count * kTreeMetaWords; ++index) {
        assembly[kHeaderWords + index] = 0;
    }
    for (uint index = 0; index < raw_query_count; ++index) {
        assembly[raw_offset + index] = raw_queries[index] & mask;
    }
    for (uint index = 0; index < count; ++index) {
        assembly[unique_offset + index] = unique_queries[index];
    }
}
