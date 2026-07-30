#include "utils.cuh"
#include "cuda_mem_pool.cuh"

#include <cstdio>

// Must match the definition in utils.cuh
#define USE_CUDA_MEM_POOL 1


__host__ int log_2(int value) {
    return __builtin_ctz(value);
}

namespace {

constexpr uint32_t MAX_MULTI_LAYER_BATCH_GET_LAYERS = 24;

// Legacy-stream pointer-vec upload: a stream-ordered allocation plus one
// synchronous H2D copy (the copy is ordered after the allocation and blocks
// until the table is on the device). The previous version spun up a private
// stream per upload; private streams are now forbidden in this crate unless
// explicitly ordered against the default stream (see utils.cuh).
const uint32_t* const* upload_device_pointer_vec(
    const uint32_t* const* host_ptr,
    uint32_t size
) {
    if (size == 0) {
        return nullptr;
    }
    const uint32_t** device_ptr =
        cuda_allocator_allocate_for_proving<const uint32_t*>(size);
    if (device_ptr == nullptr) {
        printf("Failed to allocate device pointer vector upload buffer\n");
        return nullptr;
    }
    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        const_cast<uint32_t**>(device_ptr),
        host_ptr,
        size * sizeof(uint32_t*),
        cudaMemcpyHostToDevice
    ));
    return device_ptr;
}

}  // namespace

void copy_uint32_t_vec_from_device_to_host(uint32_t *device_ptr, uint32_t *host_ptr, int size) {
    cuda_mem_copy_device_to_host<uint32_t>(device_ptr, host_ptr, size);
}

uint32_t* copy_uint32_t_vec_from_host_to_device(uint32_t *host_ptr, int size) {
    // Plain (non-zeroing) allocation: the copy below overwrites every word, so the
    // previous zero-fill was a wasted full-buffer memset per upload.
    uint32_t* device_ptr = cuda_proving_malloc<uint32_t>(size);
    cuda_mem_copy_host_to_device(host_ptr, device_ptr, size);
    return device_ptr;
}

void copy_uint32_t_vec_from_device_to_device(uint32_t *from, uint32_t *dst, int size) {
    cuda_mem_copy_device_to_device<uint32_t>(from, dst, size);
}

void copy_uint32_t_vec_from_device_to_device_offset(uint32_t *from, uint32_t *dst, int size, int offset) {
    cuda_mem_copy_device_to_device<uint32_t>(from, dst + offset, size);
}

// Pinned (page-locked) host staging memory for witness upload. Pinned pages let
// cudaMemcpy run at full PCIe bandwidth (pageable copies bounce through an internal
// staging area at roughly half speed). Allocated once and reused as scratch — the
// buffer carries no cached data and is never read back, so pointer reuse is safe.
uint32_t* cuda_alloc_pinned_host_u32(uint64_t n_words) {
    void *ptr = nullptr;
    if (cudaMallocHost(&ptr, n_words * sizeof(uint32_t)) != cudaSuccess) {
        return nullptr;  // caller falls back to pageable memory
    }
    return static_cast<uint32_t *>(ptr);
}

void cuda_free_pinned_host_u32(uint32_t *ptr) {
    if (ptr != nullptr) {
        ASSERT_CUDA_SUCCESS(cudaFreeHost(ptr));
    }
}

// H2D copy into an EXISTING device buffer (the older copy_uint32_t_vec_from_host_to_
// device allocates internally, forcing one allocation round-trip per column).
void copy_uint32_t_vec_from_host_to_device_into(const uint32_t *host_ptr, uint32_t *device_ptr,
                                                uint64_t n_words) {
    ASSERT_CUDA_SUCCESS(
        cudaMemcpy(device_ptr, host_ptr, n_words * sizeof(uint32_t), cudaMemcpyHostToDevice));
}

// Async H2D into a pre-allocated device buffer, on the legacy default stream. The
// SOURCE MUST BE PINNED and MUST STAY VALID until the copy drains — the caller
// fences via stwo_legacy_stream_sync() before reusing/freeing the source. Ordered
// on stream 0 exactly like the sync variant (consumers on stream 0 see it
// complete), so device bytes are identical; only the host stops blocking per copy.
// The async-spine lever (STWO_CUDA_ASYNC_SPINE) routes the from_simd_evals staging
// loop here, collapsing ~2,500 per-column queue drains into one fence per batch.
extern "C" void copy_uint32_t_vec_from_host_to_device_into_async(
    const uint32_t *host_ptr, uint32_t *device_ptr, uint64_t n_words) {
    ASSERT_CUDA_SUCCESS(cudaMemcpyAsync(device_ptr, host_ptr, n_words * sizeof(uint32_t),
                                        cudaMemcpyHostToDevice, 0));
}

// Block the host until all previously-enqueued legacy-default-stream work
// completes — the explicit fence for the async-spine batching (replaces the
// implicit per-copy drain of the synchronous cudaMemcpy).
extern "C" void stwo_legacy_stream_sync() { ASSERT_CUDA_SUCCESS(cudaStreamSynchronize(0)); }

// Zero `n_words` u32 words starting at `ptr + offset_words`. Used to zero-pad the
// extension tail of NTT buffers in place of allocating a fresh zeroed buffer and
// copying into it (which costs a full extra device pass per column).
void cuda_zero_device_region(uint32_t *ptr, uint64_t offset_words, uint64_t n_words) {
    if (n_words == 0) {
        return;
    }
    ASSERT_CUDA_SUCCESS(cudaMemsetAsync(ptr + offset_words, 0, n_words * sizeof(uint32_t), 0));
}

uint32_t* cuda_malloc_uint32_t(int size) {
    return cuda_proving_alloc_zeroes_u32_words(size);
}

Blake2sHash* cuda_malloc_blake_2s_hash(int size) {
    Blake2sHash* device_ptr = cuda_proving_malloc<Blake2sHash>(size);
    // cudaMemset(device_ptr, 0x00, sizeof(Blake2sHash) * size);
    return device_ptr;
}

__global__ void print_array(uint32_t *array, int size) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    if(idx < size) {
        printf("%d, ", array[idx]);
    }
}

uint32_t* cuda_alloc_zeroes_uint32_t(int size) {
    return cuda_proving_alloc_zeroes_u32_words(size);
}

void cuda_set_uint32_t(uint32_t *device_ptr, size_t index, uint32_t value) {
    cuda_mem_copy_host_to_device<uint32_t>(&value, device_ptr + index, 1);
}

void cuda_increase_at(uint32_t *device_ptr, uint32_t address) {
    uint32_t value;
    cudaMemcpy(&value, device_ptr + address, sizeof(uint32_t), cudaMemcpyDeviceToHost);
    value += 1;
    cudaMemcpy(device_ptr + address, &value, sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA error: %s\n", cudaGetErrorString(err));
    }
}

uint32_t cuda_get_uint32_t(uint32_t *device_ptr, size_t index) {
    uint32_t value = 0x0;
    cuda_mem_copy_device_to_host<uint32_t>(device_ptr + index, &value, 1);
    return value;
}

qm31 cuda_get_secure_field(qm31 *device_ptr, size_t index) {
    qm31 value = {};
    cuda_mem_copy_device_to_host<qm31>(device_ptr + index, &value, 1);
    return value;
}

Blake2sHash* cuda_alloc_zeroes_blake_2s_hash(int size) {
    Blake2sHash* device_ptr = cuda_malloc_blake_2s_hash(size);
    cudaMemset(device_ptr, 0x00, sizeof(Blake2sHash) * size);
    return device_ptr;
}

Blake2sHash* copy_blake_2s_hash_vec_from_host_to_device(Blake2sHash *host_ptr, uint32_t size) {
    Blake2sHash* device_ptr = cuda_proving_clone_to_device<Blake2sHash>(host_ptr, size);
    return device_ptr;
}

void cuda_get_blake_2s_hash(Blake2sHash *device_ptr, Blake2sHash *host_ptr, size_t index) {
    cuda_mem_copy_device_to_host<Blake2sHash>(device_ptr + index, host_ptr, 1);
}

void cuda_set_blake_2s_hash(Blake2sHash *device_ptr, size_t index, const Blake2sHash *host_ptr) {
    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        device_ptr + index,
        host_ptr,
        sizeof(Blake2sHash),
        cudaMemcpyHostToDevice
    ));
}

// Kernel: gather u32 words by index (decommit row gathers).
__global__ void gather_uint32_kernel(
    const uint32_t* src,
    const uint32_t* indices,
    uint32_t n_indices,
    uint32_t* dst
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n_indices) {
        dst[idx] = src[indices[idx]];
    }
}

// Gather `n_indices` words of `device_src` at `host_indices` into `host_out` with ONE
// kernel and one D2H copy. Replaces per-element cuda_get_uint32_t readbacks in the
// decommit phase (one PCIe roundtrip per element, ~100k of them per prove). Runs on
// the legacy default stream: the gather is ordered after the producer of `device_src`
// and the final synchronous D2H is the host-read fence.
void cuda_gather_uint32_t(
    const uint32_t* device_src,
    const uint32_t* host_indices,
    uint32_t n_indices,
    uint32_t* host_out
) {
    if (n_indices == 0) {
        return;
    }
    uint32_t* d_indices = cuda_allocator_allocate_for_proving<uint32_t>(n_indices);
    uint32_t* d_out = cuda_allocator_allocate_for_proving<uint32_t>(n_indices);
    if (!d_indices || !d_out) {
        printf("Failed to allocate buffers in gather_uint32\n");
        cuda_allocator_free_for_proving(d_indices);
        cuda_allocator_free_for_proving(d_out);
        return;
    }
    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        d_indices, host_indices, n_indices * sizeof(uint32_t), cudaMemcpyHostToDevice));
    const int block_size = 256;
    const int num_blocks = (n_indices + block_size - 1) / block_size;
    gather_uint32_kernel<<<num_blocks, block_size>>>(device_src, d_indices, n_indices, d_out);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        host_out, d_out, n_indices * sizeof(uint32_t), cudaMemcpyDeviceToHost));
    cuda_allocator_free_for_proving(d_indices);
    cuda_allocator_free_for_proving(d_out);
}

// Kernel: Batch get Blake2s hashes from device memory by indices
__global__ void batch_get_blake2s_kernel(
    const Blake2sHash* src,
    Blake2sHash* dst,
    const uint32_t* indices,
    uint32_t n_indices
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < n_indices) {
        uint32_t src_idx = indices[idx];
        // Copy 32 bytes (Blake2sHash is 32 bytes)
        // Using uint4 for efficient 16-byte aligned memory access
        const uint4* src_ptr = reinterpret_cast<const uint4*>(&src[src_idx]);
        uint4* dst_ptr = reinterpret_cast<uint4*>(&dst[idx]);

        // Copy in two uint4 chunks (2 * 16 bytes = 32 bytes)
        dst_ptr[0] = src_ptr[0];
        dst_ptr[1] = src_ptr[1];
    }
}

// Host function: Batch get Blake2s hashes
void cuda_batch_get_blake_2s_hash(
    Blake2sHash *device_ptr,
    Blake2sHash *host_ptr,
    uint32_t *indices,
    uint32_t n_indices
) {
    if (n_indices == 0) {
        return;
    }

    // All work on the legacy default stream: the gather kernel is automatically
    // ordered after the (possibly still in-flight) producer of `device_ptr`, and
    // the final synchronous D2H copy is the host-read fence.
    uint32_t* d_indices = cuda_allocator_allocate_for_proving<uint32_t>(n_indices);
    Blake2sHash* d_result = cuda_allocator_allocate_for_proving<Blake2sHash>(n_indices);
    if (!d_indices || !d_result) {
        printf("Failed to allocate buffers in batch_get\n");
        cuda_allocator_free_for_proving(d_indices);
        cuda_allocator_free_for_proving(d_result);
        return;
    }

    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        d_indices, indices, n_indices * sizeof(uint32_t), cudaMemcpyHostToDevice));

    const int block_size = 256;
    const int num_blocks = (n_indices + block_size - 1) / block_size;
    batch_get_blake2s_kernel<<<num_blocks, block_size>>>(
        device_ptr, d_result, d_indices, n_indices
    );
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    // Synchronous D2H: orders after the kernel and blocks until the data is host-visible.
    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        host_ptr, d_result, n_indices * sizeof(Blake2sHash), cudaMemcpyDeviceToHost));

    cuda_allocator_free_for_proving(d_indices);
    cuda_allocator_free_for_proving(d_result);
}

// Multi-layer batch get kernel
__global__ void multi_layer_batch_get_kernel(
    const Blake2sHash* const* layer_ptrs,  // Array of layer device pointers
    Blake2sHash* dst,
    const LayerIndexPair* pairs,
    uint32_t n_pairs
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < n_pairs) {
        LayerIndexPair pair = pairs[idx];
        const Blake2sHash* src_layer = layer_ptrs[pair.layer_idx];

        // Copy 32 bytes using uint4 for efficient aligned access
        const uint4* src_ptr = reinterpret_cast<const uint4*>(&src_layer[pair.hash_idx]);
        uint4* dst_ptr = reinterpret_cast<uint4*>(&dst[idx]);

        // 2 * uint4 = 2 * 16 bytes = 32 bytes = 1 Blake2sHash
        dst_ptr[0] = src_ptr[0];
        dst_ptr[1] = src_ptr[1];
    }
}

// Multi-layer batch get host function
void cuda_multi_layer_batch_get_blake_2s_hash(
    const Blake2sHash **layer_device_ptrs,
    Blake2sHash *host_ptr,
    const LayerIndexPair *pairs,
    uint32_t n_pairs
) {
    if (n_pairs == 0) {
        return;
    }

    // Legacy default stream throughout; see cuda_batch_get_blake_2s_hash.
    const Blake2sHash** d_layer_ptrs =
        cuda_allocator_allocate_for_proving<const Blake2sHash*>(MAX_MULTI_LAYER_BATCH_GET_LAYERS);
    LayerIndexPair* d_pairs = cuda_allocator_allocate_for_proving<LayerIndexPair>(n_pairs);
    Blake2sHash* d_result = cuda_allocator_allocate_for_proving<Blake2sHash>(n_pairs);
    if (!d_layer_ptrs || !d_pairs || !d_result) {
        printf("Failed to allocate buffers in multi_layer_batch_get\n");
        cuda_allocator_free_for_proving(d_layer_ptrs);
        cuda_allocator_free_for_proving(d_pairs);
        cuda_allocator_free_for_proving(d_result);
        return;
    }

    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        (void*)d_layer_ptrs,
        layer_device_ptrs,
        MAX_MULTI_LAYER_BATCH_GET_LAYERS * sizeof(Blake2sHash*),
        cudaMemcpyHostToDevice
    ));
    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        d_pairs, pairs, n_pairs * sizeof(LayerIndexPair), cudaMemcpyHostToDevice));

    const int block_size = 256;
    const int num_blocks = (n_pairs + block_size - 1) / block_size;
    multi_layer_batch_get_kernel<<<num_blocks, block_size>>>(
        d_layer_ptrs, d_result, d_pairs, n_pairs
    );
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    // Synchronous D2H: the host-read fence.
    ASSERT_CUDA_SUCCESS(cudaMemcpy(
        host_ptr, d_result, n_pairs * sizeof(Blake2sHash), cudaMemcpyDeviceToHost));

    cuda_allocator_free_for_proving(d_layer_ptrs);
    cuda_allocator_free_for_proving(d_pairs);
    cuda_allocator_free_for_proving(d_result);
}

void copy_blake_2s_hash_vec_from_device_to_host(Blake2sHash *device_ptr, Blake2sHash *host_ptr, uint32_t size) {
    cuda_mem_copy_device_to_host<Blake2sHash>(device_ptr, host_ptr, size);
}

void copy_blake_2s_hash_vec_from_device_to_device(Blake2sHash *from, Blake2sHash *dst, int size) {
    cuda_mem_copy_device_to_device<Blake2sHash>(from, dst, size);
}

const uint32_t* const* copy_device_pointer_vec_from_host_to_device(
    const uint32_t* const* host_ptr,
    uint32_t size
) {
    return upload_device_pointer_vec(host_ptr, size);
}

void cuda_release_uploaded_pointer_vec(const uint32_t* const* device_ptr) {
    cuda_allocator_free_for_proving(device_ptr);
}

// void** copy_device_pointer_vec_from_host_to_device(const void** ptrs, size_t n) {
//     void** d_ptrs;
//     cudaMalloc(&d_ptrs, n * sizeof(void*));
//     cudaMemcpy(d_ptrs, ptrs, n * sizeof(void*), cudaMemcpyHostToDevice);
//     return d_ptrs;
// }

void cuda_free_memory(void *device_ptr) {
    cuda_proving_free(static_cast<uint8_t*>(device_ptr));
}

// Stub implementations for backward compatibility
// These will be removed once all code is migrated to use CUDA memory pool directly
extern "C" uint32_t* pool_allocate_cuda(size_t size) {
    return cuda_mem_pool_allocate_uint32(size);
}

extern "C" void pool_deallocate_cuda(uint32_t* ptr, size_t size) {
    (void)size; // Unused parameter
    cuda_mem_pool_free_uint32(ptr);
}

extern "C" uint32_t* pool_allocate_zeroes_cuda(size_t size) {
    return cuda_mem_pool_allocate_zeroes_uint32(size);
}

// Test function to compute offset_bit_reversed_circle_domain_index on GPU
// This is used to verify CUDA matches Rust implementation
__global__ void test_offset_indices_kernel(
    unsigned int* result,
    unsigned int domain_log_size,
    unsigned int eval_log_size,
    int offset,
    unsigned int n
) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        result[i] = offset_bit_reversed_circle_domain_index(i, domain_log_size, eval_log_size, offset);
    }
}

extern "C" void test_offset_bit_reversed_indices(
    unsigned int* result_host,
    unsigned int domain_log_size,
    unsigned int eval_log_size,
    int offset,
    unsigned int n
) {
    unsigned int* result_device = cuda_proving_malloc<unsigned int>(n);

    int block_size = 256;
    int num_blocks = (n + block_size - 1) / block_size;
    test_offset_indices_kernel<<<num_blocks, block_size>>>(
        result_device, domain_log_size, eval_log_size, offset, n
    );

    stwo_maybe_debug_sync();
    cuda_mem_copy_device_to_host(result_device, result_host, n);
    cuda_proving_free(result_device);
}

// Get CUDA memory info (free and total memory in bytes)
extern "C" void cuda_get_memory_info(size_t* free_mem, size_t* total_mem) {
    cudaError_t err = cudaMemGetInfo(free_mem, total_mem);
    if (err != cudaSuccess) {
        printf("cudaMemGetInfo failed: %s\n", cudaGetErrorString(err));
        *free_mem = 0;
        *total_mem = 0;
    }
}

// Declared in cuda_mem_pool.cuh (the never-release default pool all allocations
// route through).
cudaMemPool_t stwo_default_mem_pool();

// Pool high-water marks since process start (driver-maintained, exact — unlike
// the harness's 25ms sampler, which measured up to 11GB low on SN_PIE_2):
// used = peak bytes allocated from the pool in flight; reserved = peak bytes the
// pool held from the device. Zeros on any error. These are the VRAM-diet metric.
extern "C" void cuda_pool_highwater(size_t* used_high, size_t* reserved_high) {
    *used_high = 0;
    *reserved_high = 0;
    cudaMemPool_t pool = stwo_default_mem_pool();
    unsigned long long used = 0, reserved = 0;
    if (cudaMemPoolGetAttribute(pool, cudaMemPoolAttrUsedMemHigh, &used) == cudaSuccess) {
        *used_high = (size_t)used;
    }
    if (cudaMemPoolGetAttribute(pool, cudaMemPoolAttrReservedMemHigh, &reserved) ==
        cudaSuccess) {
        *reserved_high = (size_t)reserved;
    }
}

// Reset the pool high-water marks (per-phase VRAM attribution, R-metric R5):
// the driver accepts writing 0 to the *High attributes, resetting them to the
// CURRENT usage.
extern "C" void cuda_pool_highwater_reset() {
    cudaMemPool_t pool = stwo_default_mem_pool();
    unsigned long long zero = 0;
    cudaMemPoolSetAttribute(pool, cudaMemPoolAttrUsedMemHigh, &zero);
    cudaMemPoolSetAttribute(pool, cudaMemPoolAttrReservedMemHigh, &zero);
}
