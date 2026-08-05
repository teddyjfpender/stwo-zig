#ifndef UTILS_H
#define UTILS_H

#include "fields.cuh"
#include <cstdio>
#include <unordered_map>

#include <cuda_runtime.h>

#include <cstdint>

#ifdef __CUDA_ARCH__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#define DEVICE_FORCEINLINE __device__ __forceinline__

#define HOST_DEVICE_FORCEINLINE __host__ __device__ __forceinline__

// Additional inline macros from common_fp256.cuh
#define HOST_INLINE __host__ __forceinline__
#define DEVICE_INLINE __device__ __forceinline__
#define HOST_DEVICE_INLINE __host__ __device__ __forceinline__

#define EXTERN extern "C" [[maybe_unused]]

#ifndef ASSERT_CUDA_SUCCESS
static void handle_cuda_error(cudaError_t cuda_error, const char *const file,
                              int const line) {
  if (cuda_error != cudaError::cudaSuccess) {
    fprintf(stderr, "CUDA error at %s:%d error=%s message: %s \n", file, line,
            cudaGetErrorName(cuda_error), cudaGetErrorString(cuda_error));
    exit(1);
  }
}
#define ASSERT_CUDA_SUCCESS(error) handle_cuda_error(error, __FILE__, __LINE__)

// ---------------------------------------------------------------------------
// Stream-ordering discipline (see docs/gpu-architecture-analysis.md, item 1).
//
// All kernels, copies, allocations, and frees in this crate run on the LEGACY
// DEFAULT STREAM, which orders them against each other automatically. Host reads
// happen exclusively through synchronous cudaMemcpy calls, which both order after
// all prior default-stream work AND block until the data is on the host — they are
// the fences. Wrappers therefore launch without device synchronization; a kernel
// fault surfaces as a sticky context error at the next checked call.
//
// Set STWO_CUDA_DEBUG_SYNC=1 to restore a full device synchronization after every
// launch for kernel-level error attribution while debugging.
//
// IMPORTANT: do NOT launch work on private streams without explicitly ordering it
// against the default stream (events or stream synchronization) — a private-stream
// kernel can otherwise race unfinished default-stream writes to its inputs.
// ---------------------------------------------------------------------------
inline void stwo_maybe_debug_sync() {
    static int enabled = -1;
    if (enabled < 0) {
        const char *env = getenv("STWO_CUDA_DEBUG_SYNC");
        enabled = (env != nullptr && env[0] != '\0' && env[0] != '0') ? 1 : 0;
    }
    if (enabled == 1) {
        ASSERT_CUDA_SUCCESS(cudaDeviceSynchronize());
    }
}
#endif

#define HANDLE_CUDA_ERROR(statement)                                                                                                                           \
  {                                                                                                                                                            \
    cudaError_t hce_result = (statement);                                                                                                                      \
    if (hce_result != cudaSuccess)                                                                                                                             \
      printf("line : %d, file : %s, error_code:%d, error: %s \n", __LINE__, __FILE__, hce_result, cudaGetErrorString(hce_result));                                                          \
    if (hce_result != cudaSuccess)                                                                                                                             \
      return hce_result;                                                                                                                                       \
  }

#ifndef ASSERT_TRUE
HOST_DEVICE_FORCEINLINE void assert_true(bool condition, const char *message,
                                         const char *const file,
                                         int const line) {
#ifdef __CUDA_ARCH__
  if (condition == false) {
    printf("Error at %s:%d: %s, tid = %u\n", file, line, message,
           threadIdx.x + blockIdx.x * blockDim.x);
  }
#else
  if (condition == false) {
    printf("Error at %s:%d: %s\n", file, line, message);
    exit(1);
  }
#endif
}
#define ASSERT_TRUE(condition, msg) \
  assert_true(condition, msg, __FILE__, __LINE__)
#endif

struct Blake2sHash {
    unsigned int s[8];
};

// Pair of (layer_index, hash_index) for multi-layer batch get
struct LayerIndexPair {
    uint32_t layer_idx;
    uint32_t hash_idx;
};

DEVICE_FORCEINLINE uint32_t bit_reverse(uint32_t n, int bits) {
    unsigned int reversed_n = __brev(n);
    return reversed_n >> (32 - bits);
}

DEVICE_FORCEINLINE unsigned int circle_domain_index_to_coset_index(
  unsigned int circle_index,
  unsigned int log_domain_size
) {
  unsigned int n = 1 << log_domain_size;
  if (circle_index < n / 2) {
      return circle_index * 2;
  } else {
      return (n - 1 - circle_index) * 2 + 1;
  }
}

DEVICE_FORCEINLINE unsigned int coset_index_to_circle_domain_index(
  unsigned int coset_index,
  unsigned int log_domain_size
) {
  if (coset_index % 2 == 0) {
    return coset_index / 2;
  } else {
    return ((2 << log_domain_size) - coset_index) / 2;
  }
}

// Helper function to implement Rust's rem_euclid behavior for signed integers
// rem_euclid always returns a non-negative result for positive modulus
DEVICE_FORCEINLINE int rem_euclid(int a, int m) {
    int result = a % m;
    if (result < 0) {
        result += m;
    }
    return result;
}

DEVICE_FORCEINLINE unsigned int offset_bit_reversed_circle_domain_index(
    unsigned int i,
    unsigned int domain_log_size,
    unsigned int eval_log_size,
    int offset
) {
    unsigned int prev_index = bit_reverse(i, eval_log_size);

    // Handle the special case where eval_log_size == domain_log_size (no blowup).
    // In this case, the standard formula produces undefined behavior (1 << -1).
    // Use the same approach as CPU AssertEvaluator: convert to coset order, apply offset,
    // convert back to circle domain order.
    if (eval_log_size == domain_log_size) {
        unsigned int domain_size = 1u << eval_log_size;
        unsigned int coset_index = circle_domain_index_to_coset_index(prev_index, eval_log_size);
        int next_coset_index = rem_euclid((int)coset_index + offset, (int)domain_size);
        unsigned int next_domain_index = coset_index_to_circle_domain_index((unsigned int)next_coset_index, eval_log_size);
        return bit_reverse(next_domain_index, eval_log_size);
    }

    // Standard case: eval_log_size > domain_log_size (with blowup)
    int half_size = 1 << (eval_log_size - 1);
    int step_size = offset * (1 << (eval_log_size - domain_log_size - 1));

    unsigned int result_index;
    if (prev_index < (unsigned int)half_size) {
        // prev_index + step_size can be negative when step_size is negative
        result_index = rem_euclid((int)prev_index + step_size, half_size);
    } else {
        // (prev_index - step_size) can be negative when step_size is positive
        // Rust: ((prev_index as isize - step_size).rem_euclid(half_size as isize) as usize) + half_size
        result_index = rem_euclid((int)prev_index - step_size, half_size) + half_size;
    }

    return bit_reverse(result_index, eval_log_size);
}


__host__ int log_2(int value);

extern "C"
void copy_uint32_t_vec_from_device_to_host(uint32_t *, uint32_t*, int);

extern "C"
uint32_t* copy_uint32_t_vec_from_host_to_device(uint32_t*, int);

extern "C"
void copy_uint32_t_vec_from_device_to_device(uint32_t *, uint32_t*, int);

extern "C"
void copy_uint32_t_vec_from_device_to_device_offset(uint32_t *from, uint32_t *dst, int size, int offset);

// Zero-pad helper and pinned-host staging primitives (see utils.cu for docs).
extern "C"
void cuda_zero_device_region(uint32_t *ptr, uint64_t offset_words, uint64_t n_words);

extern "C"
uint32_t* cuda_alloc_pinned_host_u32(uint64_t n_words);

extern "C"
void cuda_free_pinned_host_u32(uint32_t *ptr);

extern "C"
void copy_uint32_t_vec_from_host_to_device_into(const uint32_t *host_ptr, uint32_t *device_ptr, uint64_t n_words);

extern "C"
void cuda_gather_uint32_t(const uint32_t *device_src, const uint32_t *host_indices, uint32_t n_indices, uint32_t *host_out);

extern "C"
uint32_t* cuda_malloc_uint32_t(int);

extern "C"
Blake2sHash* cuda_malloc_blake_2s_hash(int);

extern "C"
uint32_t* cuda_alloc_zeroes_uint32_t(int);

#include "cuda_mem_pool.cuh"

extern "C"
void cuda_set_uint32_t(uint32_t *device_ptr, size_t index, uint32_t value);

extern "C"
uint32_t cuda_get_uint32_t(uint32_t *device_ptr, size_t index);

extern "C"
void cuda_increase_at(uint32_t *device_ptr, uint32_t address);

extern "C"
qm31 cuda_get_secure_field(uint32_t *device_ptr, size_t index);

extern "C"
Blake2sHash* cuda_alloc_zeroes_blake_2s_hash(int);

extern "C"
void cuda_free_memory(void*);

// Use CUDA memory pool
#define USE_CUDA_MEM_POOL 1

template<typename T>
T* cuda_proving_malloc(unsigned int size) {
    return cuda_allocator_allocate_for_proving<T>(size);
}

template<typename T>
T* cuda_proving_alloc_zeroes(unsigned int size) {
    return cuda_allocator_allocate_zeroes_for_proving<T>(size);
}

inline uint32_t* cuda_proving_alloc_zeroes_u32_words(unsigned int word_count) {
    return cuda_proving_alloc_zeroes<uint32_t>(word_count);
}

template<typename T>
void cuda_proving_free(T* device_ptr) {
    cuda_allocator_free_for_proving(device_ptr);
}

template<typename T>
T* cuda_malloc(unsigned int size) {
#if USE_CUDA_MEM_POOL
    return cuda_mem_pool_allocate<T>(size);
#else
    T *device_ptr;
    cudaError_t err = cudaMalloc((void**)&device_ptr, sizeof(T) * size);
    if (err != cudaSuccess) {
        printf("Error allocating memory: %s\n", cudaGetErrorString(err));
    }
    return device_ptr;
#endif
}

template<typename T>
void cuda_mem_copy_host_to_device(const T* host_data, T* device_data, unsigned int data_size) {
    // A failed copy must abort at its origin: continuing would compute on
    // uninitialized device memory AND leave a sticky last-error that then
    // surfaces at an unrelated later check, mis-attributing the failure.
    ASSERT_CUDA_SUCCESS(
        cudaMemcpy(device_data, host_data, sizeof(T) * data_size, cudaMemcpyHostToDevice));
}

template<typename T>
void cuda_mem_copy_device_to_device(T* device_data_from, T* device_data_to, unsigned int data_size) {
    // See cuda_mem_copy_host_to_device: fail at origin instead of leaving a
    // sticky error that misfires at a later unrelated check.
    ASSERT_CUDA_SUCCESS(
        cudaMemcpy(device_data_to, device_data_from, sizeof(T) * data_size, cudaMemcpyDeviceToDevice));
}

template<typename T>
void cuda_mem_copy_device_to_host(T* device_data, T* host_data, unsigned int data_size) {
    // See cuda_mem_copy_host_to_device: fail at origin instead of leaving a
    // sticky error that misfires at a later unrelated check.
    ASSERT_CUDA_SUCCESS(
        cudaMemcpy(host_data, device_data, sizeof(T) * data_size, cudaMemcpyDeviceToHost));
}

template<typename T>
T* clone_to_device(const T* host_data, unsigned int data_size) {
    if (data_size == 0) {
        return nullptr;
    }
    T* device_data = cuda_malloc<T>(data_size);
    cuda_mem_copy_host_to_device(host_data, device_data, data_size);
    return device_data;
}

template<typename T>
T* cuda_proving_clone_to_device(const T* host_data, unsigned int data_size) {
    if (data_size == 0) {
        return nullptr;
    }
    T* device_data = cuda_proving_malloc<T>(data_size);
    cuda_mem_copy_host_to_device(host_data, device_data, data_size);
    return device_data;
}


extern "C"
Blake2sHash* copy_blake_2s_hash_vec_from_host_to_device(Blake2sHash *host_ptr, uint32_t size);

extern "C"
void copy_blake_2s_hash_vec_from_device_to_host(Blake2sHash *device_ptr, Blake2sHash *host_ptr, uint32_t size);

extern "C"
void copy_blake_2s_hash_vec_from_device_to_device(Blake2sHash *from, Blake2sHash *dst, int size);

extern "C"
void cuda_get_blake_2s_hash(Blake2sHash *device_ptr, Blake2sHash *host_ptr, size_t index);

extern "C"
void cuda_set_blake_2s_hash(Blake2sHash *device_ptr, size_t index, const Blake2sHash *host_ptr);

extern "C"
void cuda_batch_get_blake_2s_hash(
    Blake2sHash *device_ptr,
    Blake2sHash *host_ptr,
    uint32_t *indices,
    uint32_t n_indices
);

// Multi-layer batch get: fetch hashes from multiple layers in one call
extern "C"
void cuda_multi_layer_batch_get_blake_2s_hash(
    const Blake2sHash **layer_device_ptrs,  // Array of layer pointers
    Blake2sHash *host_ptr,
    const LayerIndexPair *pairs,            // Array of (layer_idx, hash_idx) pairs
    uint32_t n_pairs
);

extern "C"
const uint32_t* const* copy_device_pointer_vec_from_host_to_device(
    const uint32_t* const* host_ptr,
    uint32_t size
);

extern "C"
void cuda_release_uploaded_pointer_vec(const uint32_t* const* device_ptr);

#define THREAD_COUNT_MAX 1024

HOST_DEVICE_FORCEINLINE constexpr unsigned int fnv1a_eval_id_gen(const char* s) {
  const unsigned int FNV_OFFSET_BASIS = 0x811C9DC5;
  const unsigned int FNV_PRIME = 0x01000193;

  unsigned int hash = FNV_OFFSET_BASIS;
  while (*s) {
      hash ^= (unsigned int)(*s++);
      hash *= FNV_PRIME;
  }
  return hash;
}

#endif // UTILS_H
