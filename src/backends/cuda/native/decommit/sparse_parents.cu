#include "contract.cuh"

namespace stwo::cuda::decommit {
namespace {

__global__ __launch_bounds__(kBlockSize)
void sparse_parent_kernel(
    const uint32_t *child_indices,
    const Hash *child_hashes,
    const uint32_t *child_count_pointer,
    uint32_t child_capacity,
    uint32_t *parent_indices,
    Hash *parent_hashes,
    uint32_t parent_capacity,
    uint32_t *parent_count) {
    __shared__ uint32_t count;
    __shared__ uint32_t valid;
    if (threadIdx.x == 0) {
        count = *child_count_pointer;
        valid = count >= 2 && count <= child_capacity &&
            (count & 1u) == 0 && count / 2u <= parent_capacity;
        for (uint32_t index = 0; valid && index < count; index += 2) {
            valid = (index == 0 ||
                     child_indices[index - 1] < child_indices[index]) &&
                child_indices[index + 1] == (child_indices[index] ^ 1u) &&
                child_indices[index] < child_indices[index + 1];
        }
        *parent_count = valid ? count / 2u : 0;
    }
    __syncthreads();
    if (!valid) return;

    const uint32_t parents = count / 2u;
    for (uint32_t parent = threadIdx.x;
         parent < parents;
         parent += kBlockSize) {
        const uint32_t left = 2u * parent;
        parent_indices[parent] = child_indices[left] >> 1u;
        parent_hashes[parent] =
            blake2s::hash_children(child_hashes[left], child_hashes[left + 1]);
    }
}

}  // namespace
}  // namespace stwo::cuda::decommit

extern "C" int stwo_decommit_sparse_parent_on(
    const uint32_t *child_indices,
    const stwo::cuda::decommit::Hash *child_hashes,
    const uint32_t *child_count,
    uint32_t child_capacity,
    uint32_t *parent_indices,
    stwo::cuda::decommit::Hash *parent_hashes,
    uint32_t parent_capacity,
    uint32_t *parent_count,
    void *stream) {
    using namespace stwo::cuda::decommit;
    const size_t child_index_bytes =
        static_cast<size_t>(child_capacity) * sizeof(uint32_t);
    const size_t child_hash_bytes =
        static_cast<size_t>(child_capacity) * sizeof(Hash);
    const size_t parent_index_bytes =
        static_cast<size_t>(parent_capacity) * sizeof(uint32_t);
    const size_t parent_hash_bytes =
        static_cast<size_t>(parent_capacity) * sizeof(Hash);
    if (child_indices == nullptr || child_hashes == nullptr ||
        child_count == nullptr || child_capacity < 2 ||
        parent_indices == nullptr || parent_hashes == nullptr ||
        parent_capacity < child_capacity / 2u ||
        parent_count == nullptr || stream == nullptr ||
        device_ranges_overlap(
            child_indices, child_index_bytes,
            parent_indices, parent_index_bytes) ||
        device_ranges_overlap(
            child_hashes, child_hash_bytes,
            parent_hashes, parent_hash_bytes) ||
        device_ranges_overlap(
            parent_indices, parent_index_bytes,
            parent_hashes, parent_hash_bytes) ||
        device_ranges_overlap(parent_count, sizeof(uint32_t), parent_indices,
                       parent_index_bytes) ||
        device_ranges_overlap(parent_count, sizeof(uint32_t), parent_hashes,
                       parent_hash_bytes)) {
        return cudaErrorInvalidValue;
    }
    sparse_parent_kernel<<<
        1, kBlockSize, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        child_indices,
        child_hashes,
        child_count,
        child_capacity,
        parent_indices,
        parent_hashes,
        parent_capacity,
        parent_count);
    return cudaGetLastError();
}
