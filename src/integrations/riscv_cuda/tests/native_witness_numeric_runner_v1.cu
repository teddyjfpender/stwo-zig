// Actual-device differential gate for the exact Zig->C->CUDA witness writers.
// CPU expected field words are fixture data, never inputs to the GPU writer.
#include <cuda_runtime.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

#ifdef STWO_PRUNED_LOCALZERO_WITNESS_TEST
#define STWO_LOCALZERO_WITNESS_TEST
#define stwo_cuda_native_localzero_v1_launch stwo_cuda_native_localzero_pruned_v1_launch
#endif
#ifdef STWO_LOCALZERO_WITNESS_TEST
extern "C" cudaError_t stwo_cuda_native_localzero_v1_launch(
    uint32_t, const uint32_t *, const uint32_t *, uint32_t, uint32_t, uint32_t,
    const uint32_t *, uint32_t *, uint32_t *, cudaStream_t);
#else
extern "C" cudaError_t stwo_cuda_native_witness_v1_launch(
    uint32_t, const uint32_t *, const uint32_t *, uint32_t, uint32_t, uint32_t,
    uint32_t *, uint32_t *, cudaStream_t);
#endif

static void check(cudaError_t error) {
    if (error != cudaSuccess) throw std::runtime_error(cudaGetErrorString(error));
}
struct Buffer {
    uint32_t *data = nullptr;
    explicit Buffer(size_t words) { check(cudaMalloc(&data, words * 4)); }
    ~Buffer() { if (data) cudaFree(data); }
    Buffer(const Buffer &) = delete;
};
static uint32_t read_word(std::ifstream &input) {
    uint8_t bytes[4];
    if (!input.read(reinterpret_cast<char *>(bytes), 4))
        throw std::runtime_error("truncated fixture");
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}
static std::vector<uint32_t> read_words(std::ifstream &input, size_t count) {
    std::vector<uint32_t> values(count);
    for (auto &value : values) value = read_word(input);
    return values;
}
static void equal(const std::vector<uint32_t> &expected, const std::vector<uint32_t> &actual,
                  uint32_t family) {
    if (expected.size() != actual.size()) throw std::runtime_error("wrong output length");
    for (size_t i = 0; i < expected.size(); ++i) if (expected[i] != actual[i]) {
        std::fprintf(stderr, "WITNESS_MISMATCH family=%u word=%zu expected=%u actual=%u\n",
                     family, i, expected[i], actual[i]);
        throw std::runtime_error("canonical witness mismatch");
    }
}

int main(int argc, char **argv) try {
#ifdef STWO_PRUNED_LOCALZERO_WITNESS_TEST
    if(argc!=3)throw std::runtime_error("expected vector and cold plan files");
    std::ifstream plans(argv[2],std::ios::binary);if(read_word(plans)!=0x58305031||read_word(plans)!=17)throw std::runtime_error("bad cold plan header");const uint32_t plan_words=read_word(plans);if(plan_words>4096||plan_words<4)throw std::runtime_error("bad cold plan width");
#else
    if (argc != 2) throw std::runtime_error("expected pinned vector file");
#endif
    std::ifstream input(argv[1], std::ios::binary);
    char magic[8];
    const char *expected_magic =
#ifdef STWO_LOCALZERO_WITNESS_TEST
        "RVWZ1\0\0\0";
#else
        "RVWN1\0\0\0";
#endif
    if (!input.read(magic, 8) || std::memcmp(magic, expected_magic, 8))
        throw std::runtime_error("bad vector magic");
    const uint32_t case_count = read_word(input);
    if (case_count != 17) throw std::runtime_error("incomplete family roster");
    cudaStream_t stream;
    check(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking));
    uint64_t total_words = 0, total_rows = 0, hostile_cases = 0;
    size_t explicit_peak = 0;
    for (uint32_t case_index = 0; case_index < case_count; ++case_index) {
        const uint32_t family = read_word(input), active = read_word(input);
        const uint32_t padded = read_word(input), width = read_word(input);
        const uint64_t cpu_ns = (uint64_t)read_word(input) | (uint64_t)read_word(input) << 32;
        const uint32_t zero_clock_status = read_word(input);
#ifdef STWO_LOCALZERO_WITNESS_TEST
        auto predecessors = read_words(input, 3);
#ifdef STWO_PRUNED_LOCALZERO_WITNESS_TEST
        auto recipe=read_words(plans,plan_words);if(recipe[0]!=1||recipe[1]+2*recipe[3]!=width)throw std::runtime_error("wrong cold plan geometry");
        Buffer predecessor_buffer(plan_words);check(cudaMemcpy(predecessor_buffer.data,recipe.data(),plan_words*4,cudaMemcpyHostToDevice));
#else
        Buffer predecessor_buffer(3);
        check(cudaMemcpy(predecessor_buffer.data, predecessors.data(), 12, cudaMemcpyHostToDevice));
#endif
#endif
        if (family != case_index || !active || active >= padded || width > 128 ||
            padded > 65536 || (padded & (padded - 1)))
            throw std::runtime_error("unbounded vector geometry");
        auto rows = read_words(input, (size_t)active * 24);
        auto expected = read_words(input, (size_t)padded * width);
        std::vector<uint32_t> output(expected.size()), indices(active);
        for (uint32_t i = 0; i < active; ++i) indices[i] = i;
        Buffer raw(rows.size()), result(output.size() + 16), status(1), index_buffer(active);
        explicit_peak = std::max(explicit_peak, (rows.size() + output.size() + 17 + active) * 4);
        check(cudaMemcpyAsync(raw.data, rows.data(), rows.size()*4, cudaMemcpyHostToDevice, stream));
        check(cudaMemcpyAsync(index_buffer.data, indices.data(), indices.size()*4, cudaMemcpyHostToDevice, stream));
        check(cudaMemsetAsync(result.data, 0xa5, (output.size()+16)*4, stream));
        check(cudaMemsetAsync(status.data, 0, 4, stream));
        auto launch = [&](const uint32_t *ids) {
#ifdef STWO_LOCALZERO_WITNESS_TEST
            check(stwo_cuda_native_localzero_v1_launch(family, raw.data, ids, active,
                active, padded, predecessor_buffer.data, result.data, status.data, stream));
#else
            check(stwo_cuda_native_witness_v1_launch(family, raw.data, ids, active,
                                                    active, padded, result.data, status.data, stream));
#endif
        };
        launch(nullptr);
        check(cudaMemcpyAsync(output.data(), result.data, output.size()*4, cudaMemcpyDeviceToHost, stream));
        uint32_t flag = 99;
        check(cudaMemcpyAsync(&flag, status.data, 4, cudaMemcpyDeviceToHost, stream));
        check(cudaStreamSynchronize(stream));
        if (flag) {std::fprintf(stderr,"HONEST_REJECT family=%u status=%u\n",family,flag);throw std::runtime_error("honest retirement rejected");}
        equal(expected, output, family);
        // Explicit ordered device indices must produce the same field words.
        launch(index_buffer.data);
        check(cudaMemcpyAsync(output.data(), result.data, output.size()*4, cudaMemcpyDeviceToHost, stream));
        uint32_t tail[16];
        check(cudaMemcpyAsync(tail, result.data+output.size(), 64, cudaMemcpyDeviceToHost, stream));
        check(cudaStreamSynchronize(stream));
        equal(expected, output, family);
        for (auto value : tail) if (value != 0xa5a5a5a5u) throw std::runtime_error("writer overrun");
        cudaEvent_t begin, end;
        check(cudaEventCreate(&begin)); check(cudaEventCreate(&end));
        constexpr unsigned repeats = 32;
        check(cudaEventRecord(begin, stream));
        for (unsigned i = 0; i < repeats; ++i) launch(nullptr);
        check(cudaEventRecord(end, stream)); check(cudaEventSynchronize(end));
        float milliseconds = 0;
        check(cudaEventElapsedTime(&milliseconds, begin, end));
        check(cudaEventDestroy(begin)); check(cudaEventDestroy(end));
        std::printf("{\"family\":%u,\"active_rows\":%u,\"padded_rows\":%u,\"columns\":%u,\"cpu_oracle_ns\":%llu,\"gpu_kernel_mean_ns\":%.0f,\"repeats\":%u,\"field_words\":%zu}\n",
                    family, active, padded, width, (unsigned long long)cpu_ns,
                    milliseconds*1000000.0/repeats, repeats, expected.size());
        std::fflush(stdout);
        // Malformed narrow fields must fail before invoking a typed recipe.
        const std::array<std::pair<unsigned,uint32_t>,3> mutations{{{3,32}, {2,255}, {19,2}}};
        for (auto mutation : mutations) {
            const uint32_t saved = rows[mutation.first]; rows[mutation.first] = mutation.second;
            check(cudaMemcpyAsync(raw.data, rows.data(), 24*4, cudaMemcpyHostToDevice, stream));
            check(cudaMemsetAsync(status.data, 0, 4, stream)); launch(nullptr);
            check(cudaMemcpyAsync(&flag, status.data, 4, cudaMemcpyDeviceToHost, stream));
            check(cudaStreamSynchronize(stream));
            if (!flag) throw std::runtime_error("malformed retirement accepted");
            rows[mutation.first] = saved; ++hostile_cases;
        }
        const uint32_t saved_clock = rows[0]; rows[0] = 0;
        check(cudaMemcpyAsync(raw.data, rows.data(), 24*4, cudaMemcpyHostToDevice, stream));
        check(cudaMemsetAsync(status.data, 0, 4, stream)); launch(nullptr);
        check(cudaMemcpyAsync(&flag, status.data, 4, cudaMemcpyDeviceToHost, stream));
        check(cudaStreamSynchronize(stream));
        if (flag != zero_clock_status) throw std::runtime_error("canonical zero-clock status mismatch");
        rows[0] = saved_clock;
        check(cudaMemcpyAsync(raw.data, rows.data(), 24*4, cudaMemcpyHostToDevice, stream));
        indices[0] = active;
        check(cudaMemcpyAsync(index_buffer.data, indices.data(), 4, cudaMemcpyHostToDevice, stream));
        check(cudaMemsetAsync(status.data, 0, 4, stream)); launch(index_buffer.data);
        check(cudaMemcpyAsync(&flag, status.data, 4, cudaMemcpyDeviceToHost, stream));
        check(cudaStreamSynchronize(stream));
        if (!flag) throw std::runtime_error("out-of-bounds source index accepted");
        ++hostile_cases;
        total_words += expected.size(); total_rows += active;
    }
    if (input.peek() != std::char_traits<char>::eof()) throw std::runtime_error("trailing fixture bytes");
    check(cudaStreamDestroy(stream));
    std::printf("{\"status\":\"pass\",\"scope\":\"resident_native_witness_primitive\",\"fully_resident_prover\":false,\"families\":17,\"rows\":%llu,\"field_words\":%llu,\"hostile_cases\":%llu,\"explicit_device_peak_bytes\":%zu}\n",
                (unsigned long long)total_rows, (unsigned long long)total_words,
                (unsigned long long)hostile_cases, explicit_peak);
    return 0;
} catch (const std::exception &error) {
    std::fprintf(stderr, "NATIVE_WITNESS_GATE_FAILED %s\n", error.what()); return 1;
}
