// Device sorting for the original read-only input/consistency relation. All
// numeric keys, values, sorting and predecessor witnesses stay on the GPU.
#include "resident_parent_readonly_v1.cuh"
#include <cub/device/device_radix_sort.cuh>

namespace {
constexpr uint32_t p = 0x7fffffffu;
constexpr uint32_t max_entries = 1u << 24;
__device__ __forceinline__ uint32_t physical(uint32_t row, uint32_t log) {
    const uint32_t size = 1u << log;
    // Exact framework_interaction.committedRow: coset logical row ->
    // circle index -> bit reverse. The inverse permutation is different.
    const uint32_t circle = (row & 1u) ? (2*size-row)/2 : row/2;
    return __brev(circle) >> (32-log);
}
__global__ void gather(const uint32_t *rows, uint32_t count,
                       const uint32_t *main, uint32_t log,
                       uint32_t *keys, uint32_t *values, uint32_t *error) {
    uint32_t i = blockIdx.x*blockDim.x+threadIdx.x;
    if (i >= count) return;
    const uint32_t size = 1u << log;
    const uint32_t row = rows[i];
    if (row >= size) { atomicOr(error, 1024u); return; }
    const uint32_t index = physical(row, log);
    uint32_t key = 0;
    for (uint32_t c = 0; c < 4; ++c) {
        uint32_t byte = main[(size_t)c*size+index];
        if (byte > 255) { atomicOr(error, 1024u); return; }
        key |= byte << (8*c);
    }
    const uint32_t value = main[(size_t)4*size+index];
    if (value >= p) { atomicOr(error, 1024u); return; }
    keys[i] = key; values[i] = value;
}
__global__ void arguments(const uint32_t *rows, uint32_t count,
                          const uint32_t *keys, const uint32_t *values,
                          uint32_t *out, uint32_t out_rows, uint32_t *error) {
    const uint32_t i = blockIdx.x*blockDim.x+threadIdx.x;
    if (i >= count) return;
    const uint32_t row = rows[i];
    if (row >= out_rows || values[i] >= p ||
        (i && (keys[i] < keys[i-1] || (keys[i] == keys[i-1] && values[i] != values[i-1])))) {
        atomicOr(error, 2048u); return;
    }
    // Exact original readonly_consistency.logicalRow dynamic argument order.
    out[(size_t)row*4+0] = i ? keys[i-1] : 0;
    out[(size_t)row*4+1] = i ? values[i-1] : 0;
    out[(size_t)row*4+2] = keys[i];
    out[(size_t)row*4+3] = values[i];
}
}
extern "C" cudaError_t stwo_parent_readonly_temp_bytes_v1(uint32_t entries, size_t *bytes) {
    if (!bytes || !entries || entries > max_entries) return cudaErrorInvalidValue;
    size_t required = 0;
    const cudaError_t result = cub::DeviceRadixSort::SortPairs(nullptr, required,
        static_cast<const uint32_t *>(nullptr), static_cast<uint32_t *>(nullptr),
        static_cast<const uint32_t *>(nullptr), static_cast<uint32_t *>(nullptr),
        entries, 0, 32);
    if (result == cudaSuccess) *bytes = required;
    return result;
}
extern "C" cudaError_t stwo_parent_readonly_gather_v1(
    const uint32_t *rows, uint32_t count, const uint32_t *main,
    uint32_t log, uint32_t *keys, uint32_t *values, uint32_t *error, cudaStream_t stream) {
    if (!rows || !count || count > max_entries || !main || log < 1 || log > 27 ||
        !keys || !values || !error || !stream) return cudaErrorInvalidValue;
    gather<<<(count+255)/256,256,0,stream>>>(rows,count,main,log,keys,values,error);
    return cudaGetLastError();
}
extern "C" cudaError_t stwo_parent_readonly_sort_v1(
    void *temporary, size_t bytes, const uint32_t *keys_in, uint32_t *keys_out,
    const uint32_t *values_in, uint32_t *values_out, uint32_t count, cudaStream_t stream) {
    if (!temporary || !bytes || !keys_in || !keys_out || !values_in || !values_out ||
        keys_in == keys_out || values_in == values_out || !count || count > max_entries || !stream)
        return cudaErrorInvalidValue;
    return cub::DeviceRadixSort::SortPairs(temporary,bytes,keys_in,keys_out,values_in,values_out,count,0,32,stream);
}
extern "C" cudaError_t stwo_parent_readonly_arguments_v1(
    const uint32_t *rows, uint32_t count, const uint32_t *keys, const uint32_t *values,
    uint32_t *out, uint32_t out_rows, uint32_t *error, cudaStream_t stream) {
    if (!rows || !count || count > max_entries || !keys || !values || !out ||
        !out_rows || out_rows > max_entries || !error || !stream) return cudaErrorInvalidValue;
    arguments<<<(count+255)/256,256,0,stream>>>(rows,count,keys,values,out,out_rows,error);
    return cudaGetLastError();
}
