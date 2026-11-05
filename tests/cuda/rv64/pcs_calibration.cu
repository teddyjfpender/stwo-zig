// Hardware calibration of existing PCS kernels, not an RV64 execution proof.
// Large buffers are initialized once and reused. Every metric names its cell
// denominator; QM31 FRI is a control, not the native OM31 security profile.
#include "context_owner.cuh"
#include "commitment/blake2s_core.cuh"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>
using Hash = stwo::cuda::blake2s::Hash;
struct Qm31 { uint32_t words[4]; };
extern "C" int stwo_lde_n2b_columns_on(const uint32_t*, size_t, const uint32_t*,
    uint32_t*, size_t, uint32_t, uint32_t, const uint32_t*, uint32_t, uint32_t,
    void*, uint32_t*);
extern "C" int stwo_blake2s_contiguous_leaf_on(uint32_t, const uint32_t*, size_t,
    size_t, Hash*, void*);
extern "C" int stwo_blake2s_layer_on(const Hash*, uint32_t, Hash*, void*);
extern "C" int stwo_fold_line_on(const uint32_t*, size_t, uint32_t, uint32_t,
    const uint32_t*, size_t, uint32_t, const Qm31*, uint32_t, uint32_t*, size_t,
    uint32_t, void*);
extern "C" int stwo_blake2s_pow_persistent_on(const uint32_t*, uint32_t,
    unsigned long long, uint32_t*, unsigned long long*, uint32_t*, uint32_t*, void*);
__global__ void init_words(uint32_t* words, size_t count, uint32_t seed) {
    const size_t i = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < count) words[i] = uint32_t((uint64_t(i + 17) * 104729 + seed) % 2147483647u);
}
__global__ void init_domain(uint32_t* words, uint32_t count) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < count) words[i] = uint32_t(((uint64_t(i) + 11) * (i + 29) + 7) % 2147483646u) + 1;
}
__global__ void init_sizes(uint32_t* words, uint32_t count, uint32_t log) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < count) words[i] = log;
}
template<class Fn> static float median(Owner& owner, cudaStream_t stream, Fn fn) {
    for (int i = 0; i < 3; ++i) fn();
    CHECK(stwo_exec_context_sync(owner.ctx));
    const auto begin = owner.event(), end = owner.event();
    std::vector<float> values;
    for (int i = 0; i < 11; ++i) {
        CHECK(cudaEventRecord(begin, stream)); fn();
        CHECK(cudaEventRecord(end, stream)); CHECK(cudaEventSynchronize(end));
        float ms; CHECK(cudaEventElapsedTime(&ms, begin, end)); values.push_back(ms);
    }
    std::sort(values.begin(), values.end()); return values[5];
}
int main(int argc, char** argv) {
    try {
        const uint32_t log = argc > 1 ? std::stoul(argv[1]) : 22;
        const uint32_t columns = argc > 2 ? std::stoul(argv[2]) : 32;
        const uint32_t blowup_log = argc > 3 ? std::stoul(argv[3]) : 2;
        if (log < 8 || log > 24 || columns < 4 || columns > 64 ||
            blowup_log < 1 || blowup_log > 2)
            throw std::runtime_error("usage: pcs-calibration [evaluation log 8..24] [columns 4..64] [blowup log 1|2]");
        const uint32_t rows = 1u << log, half = rows / 2;
        Owner o(0);
        const auto coefficients = o.plane(half, columns), sizes = o.plane(columns, 1),
            values = o.plane(rows, columns), domain = o.plane(half, 1),
            leaves = o.plane(rows, 8), nodes = o.plane(rows, 8), folded = o.plane(half, 4),
            alpha = o.plane(4, 1), state = o.plane(16, 1), prefix = o.plane(8, 1),
            best = o.plane(2, 1), completed = o.plane(1, 1), nonce = o.plane(2, 1);
        o.upload(alpha, std::vector<uint32_t>{3, 7, 11, 13});
        o.upload(state, std::vector<uint32_t>{0x93458da8u,0xf7b79301u,0x9b64ee9fu,0xc65f8fc1u,
            0xf448640cu,0x8fd2a8b0u,0xfaf31f8eu,0x4c63437eu,2,8,0,0,0x58687888,0x18283848,0,0});
        StwoCudaDependency ingress{};
        CHECK(stwo_exec_context_dependency_record(o.ctx,0,0,&ingress));
        CHECK(stwo_exec_context_dependency_wait(o.ctx,1,&ingress));
        void* raw = nullptr; CHECK(stwo_exec_context_lane_stream(o.ctx,1,&raw));
        const auto stream = reinterpret_cast<cudaStream_t>(raw);
        init_words<<<(size_t(half)*columns+255)/256,256,0,stream>>>(coefficients.words,size_t(half)*columns,9);
        init_domain<<<(half+255)/256,256,0,stream>>>(domain.words,half);
        init_sizes<<<1,128,0,stream>>>(sizes.words,columns,log-blowup_log);
        CHECK(cudaPeekAtLastError());
        uint32_t launches = 0;
        const float lde = median(o,stream,[&]{ CHECK(stwo_lde_n2b_columns_on(coefficients.words,
            half,sizes.words,values.words,rows,log,columns,domain.words,half,half,raw,&launches)); });
        const float leaf = median(o,stream,[&]{ CHECK(stwo_blake2s_contiguous_leaf_on(rows,
            values.words,rows,size_t(rows)*columns,reinterpret_cast<Hash*>(leaves.words),raw)); });
        const float merkle = median(o,stream,[&]{
            auto* input = reinterpret_cast<Hash*>(leaves.words);
            auto* output = reinterpret_cast<Hash*>(nodes.words);
            for (uint32_t n = half; n; n >>= 1) {
                CHECK(stwo_blake2s_layer_on(input,n,output,raw)); input = output; output += n;
            }
        });
        const float fri = median(o,stream,[&]{ CHECK(stwo_fold_line_on(domain.words,half,0,
            rows,values.words,size_t(rows)*4,rows,reinterpret_cast<Qm31*>(alpha.words),0,
            folded.words,size_t(half)*4,half,raw)); });
        constexpr uint32_t pow_bits = 26;
        constexpr unsigned long long search_end = 1ull << 28;
        const float pow = median(o,stream,[&]{ CHECK(stwo_blake2s_pow_persistent_on(state.words,
            pow_bits,search_end,prefix.words,reinterpret_cast<unsigned long long*>(best.words),
            completed.words,nonce.words,raw)); });
        const auto final_nonce = o.read(best);
        const uint64_t best_nonce = uint64_t(final_nonce[0]) | uint64_t(final_nonce[1]) << 32;
        // Read one root only, after the measured pipeline; no large output download.
        const auto root = StwoRv64Plane{nodes.words + size_t(rows-2)*8,8,1,0};
        const auto root_words = o.read(root);
        CHECK(stwo_exec_context_dependency_release(o.ctx,&ingress));
        const uint64_t coefficient_cells = uint64_t(1u << (log-blowup_log))*columns,
                       evaluation_cells = uint64_t(rows)*columns;
        std::printf("{\"schema\":\"rv64-existing-pcs-calibration-v1\",\"evaluation_log\":%u,"
            "\"columns\":%u,\"blowup_log\":%u,\"coefficient_cells\":%llu,\"evaluation_cells\":%llu,"
            "\"lde_median_ms\":%.6f,\"leaf_median_ms\":%.6f,\"merkle_median_ms\":%.6f,"
            "\"qm31_line_fold_median_ms\":%.6f,\"pow_median_ms\":%.6f,\"pow_bits\":26,"
            "\"pow_search_end\":%llu,\"pow_best_nonce\":%llu,\"lde_ns_per_coefficient_cell\":%.6f,"
            "\"lde_ns_per_evaluation_cell\":%.6f,\"commit_ns_per_evaluation_cell\":%.6f,"
            "\"qm31_fold_ns_per_input_base_cell\":%.6f,\"allocated_bytes\":%llu,"
            "\"root_first_word\":%u,\"warmup\":3,\"repeats\":11,\"hot_h2d_bytes\":0,"
            "\"hot_d2h_bytes\":0,\"synthetic_nonzero_domain\":true,\"full_block_verified\":false}\n",
            log,columns,blowup_log,(unsigned long long)coefficient_cells,
            (unsigned long long)evaluation_cells,lde,leaf,merkle,fri,pow,search_end,
            (unsigned long long)best_nonce,lde*1e6/coefficient_cells,lde*1e6/evaluation_cells,
            (leaf+merkle)*1e6/evaluation_cells,fri*1e6/(uint64_t(rows)*4),
            (unsigned long long)o.allocated_bytes,root_words[0]);
        o.close();
    } catch (const std::exception& e) { std::fprintf(stderr,"FAIL: %s\n",e.what());return 1; }
}
