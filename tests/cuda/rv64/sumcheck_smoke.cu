// Full resident single-oracle sumcheck feedback, benchmark and parity harness.
// The CPU reference is a separate host object, itself checked against Zig's
// native prover/verifier. No intermediate numerical values enter the host loop.
#include "rv64/om31.cuh"
#include "rv64/round.cuh"
#include "context_owner.cuh"
#include <algorithm>
#include <cstdio>
#include <thread>
using namespace stwo::cuda::rv64;
extern "C" void rv64_test_sumcheck(const uint32_t*, const uint32_t*, uint32_t, uint32_t,
                                   const uint32_t*, const uint32_t*, const uint32_t*,
                                   const uint32_t*, uint32_t*, uint32_t*, uint32_t*);
static OM31 value(uint32_t seed) {
    uint32_t words[8];
    for (auto& w : words) {
        seed = seed * 1664525u + 1013904223u;
        w = seed % 2147483647u;
    }
    return from_words(words);
}
static void put(std::vector<uint32_t>& out, size_t index, OM31 v) {
    for (uint32_t c = 0; c < 8; ++c) out[index * 8 + c] = coordinate(v, c);
}
static void equal(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b,
                  const char* name) {
    if (a != b) throw std::runtime_error(std::string("resident sumcheck mismatch: ") + name);
}
struct Report {
    int device;
    uint32_t count;
    bool base;
    float combined_ms, split_ms;
    uint64_t bytes;
};
static Report exercise(int device, uint32_t count, bool base_n) {
    Owner o(device);
    uint32_t variables = 0;
    for (uint32_t m = count / 2; m > 1; m >>= 1) ++variables;
    const uint32_t groups = (count / 4 + 127) / 128;
    const auto n = o.plane(count, base_n ? 1 : 8), d = o.plane(count, 8);
    const auto n0 = o.plane(count / 2, 8), d0 = o.plane(count / 2, 8),
               n1 = o.plane(count / 4, 8), d1 = o.plane(count / 4, 8);
    const auto eq = o.plane(count / 4, 8), a = o.plane(2 * groups, 8),
               b = o.plane(2 * groups, 8), raw = o.plane(2, 8);
    const auto point = o.plane(variables, 8), lambda = o.plane(1, 8), claim = o.plane(1, 8),
               seed = o.plane(9, 1);
    const auto compact = o.plane(32, 1);
    const auto state = o.plane(round_state_words, 1),
               records = o.plane(variables * round_record_words, 1);
    std::vector<uint32_t> hn(size_t(count) * 8), hd(hn.size()), yn(variables * 8), ln(8), cn(8),
        sn(9, 0);
    std::vector<uint32_t> ns(size_t(count) * (base_n ? 1 : 8)), ds(size_t(count) * 8);
    const auto l = value(9000);
    put(ln, 0, l);
    for (uint32_t i = 0; i < count; ++i) {
        const auto x = base_n ? base(i * 11) : value(600 + i), y = value(100 + i);
        put(hn, i, x);
        put(hd, i, y);
        if (base_n)
            ns[i] = coordinate(x, 0);
        else
            store(ns.data(), count, i, x);
        store(ds.data(), count, i, y);
    }
    for (uint32_t i = 0; i < variables; ++i) put(yn, i, value(2000 + i));
    OM31 c = zero();
    for (uint32_t i = 0; i < count / 2; ++i) {
        const auto f =
            combine({from_words(hn.data() + 16 * i), from_words(hd.data() + 16 * i)},
                    {from_words(hn.data() + 16 * i + 8), from_words(hd.data() + 16 * i + 8)});
        OM31 e = one();
        for (uint32_t j = 0; j < variables; ++j) {
            const auto y = from_words(yn.data() + 8 * j);
            e = mul(e, i & (1u << (variables - 1 - j)) ? y : sub(one(), y));
        }
        c = add(c, mul(e, add(f.n, mul(l, f.d))));
    }
    put(cn, 0, c);
    sn[8] = 3;
    std::vector<uint32_t> expected_records(variables * round_record_words),
        expected_state(round_state_words), expected_terminal(32);
    rv64_test_sumcheck(hn.data(), hd.data(), count, base_n, yn.data(), ln.data(), cn.data(),
                       sn.data(), expected_records.data(), expected_state.data(),
                       expected_terminal.data());
    if (expected_state[10]) throw std::runtime_error("host numerical reference failed");
    o.upload(n, ns);
    o.upload(d, ds);
    o.upload(point, yn);
    o.upload(lambda, ln);
    o.upload(claim, cn);
    o.upload(seed, sn);
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    void* s = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &s));
    const auto stream = reinterpret_cast<cudaStream_t>(s);
    StwoRv64Plane terminal_n = n, terminal_d = d;
    auto wave = [&](bool split) {
        CHECK(stwo_rv64_sumcheck_init_on(o.ctx, 1, state.words, seed.words, claim.words,
                                         variables));
        CHECK(stwo_rv64_gkr_eq_on(o.ctx, 1, point.words, variables, eq));
        auto current_n = n, current_d = d;
        uint32_t size = count;
        for (uint32_t r = 0; r < variables; ++r) {
            if (split)
                CHECK(stwo_rv64_gkr_sum_split_on(o.ctx, 1, current_n, current_d, size, eq,
                                                 lambda.words, a, b, raw));
            else
                CHECK(stwo_rv64_gkr_sum_on(o.ctx, 1, current_n, current_d, size, eq,
                                           lambda.words, a, b, raw));
            auto* record = records.words + r * round_record_words;
            CHECK(stwo_rv64_sumcheck_round_on(o.ctx, 1, state.words, variables, r, raw,
                                              point.words, record));
            const auto on = (r % 2 == 0) ? n0 : n1, od = (r % 2 == 0) ? d0 : d1;
            CHECK(stwo_rv64_gkr_fold_on(o.ctx, 1, current_n, current_d, size, record + 32, on,
                                        od));
            current_n = on;
            current_d = od;
            size /= 2;
        }
        terminal_n = current_n;
        terminal_d = current_d;
        CHECK(stwo_rv64_gkr_pack_mask_on(o.ctx, 1, terminal_n, terminal_d, compact.words));
    };
    auto compare = [&]() {
        CHECK(stwo_exec_context_sync(o.ctx));
        equal(o.read(state), expected_state, "state/channel");
        equal(o.read(records), expected_records, "polynomials/challenges");
        equal(o.read(compact), expected_terminal, "terminal mask");
    };
    auto begin = o.event(), end = o.event();
    float medians[2]{};
    for (int variant = 0; variant < 2; ++variant) {
        for (int i = 0; i < 3; ++i) wave(variant);
        compare();
        std::vector<float> times;
        for (int i = 0; i < 11; ++i) {
            CHECK(cudaEventRecord(begin, stream));
            wave(variant);
            CHECK(cudaEventRecord(end, stream));
            CHECK(cudaEventSynchronize(end));
            float ms = 0;
            CHECK(cudaEventElapsedTime(&ms, begin, end));
            times.push_back(ms);
        }
        compare();
        std::sort(times.begin(), times.end());
        medians[variant] = times[5];
    }
    // A device-side interpolation pole must poison the job and clear every
    // record's challenge before already-enqueued dependent folds can read it.
    auto bad_point = yn;
    put(bad_point, 0, one());
    o.upload(point, bad_point);
    CHECK(stwo_exec_context_sync(o.ctx));
    wave(false);
    CHECK(stwo_exec_context_sync(o.ctx));
    const auto bad_state = o.read(state), bad_records = o.read(records);
    if (bad_state[10] != round_pole || bad_state[9] != 0)
        throw std::runtime_error("pole did not poison round state");
    for (uint32_t r = 0; r < variables; ++r) {
        for (uint32_t j = 0; j < 40; ++j)
            if (bad_records[r * round_record_words + j] != 0)
                throw std::runtime_error("failed round left a stale coefficient/challenge");
        if (bad_records[r * round_record_words + 41] != UINT32_MAX)
            throw std::runtime_error("failed record ordinal not invalidated");
    }
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    Report report{device, count, base_n, medians[0], medians[1], o.allocated_bytes};
    o.close();
    return report;
}
int main(int argc, char** argv) {
    try {
        const int devices = argc > 1 ? std::stoi(argv[1]) : 1,
                  log = argc > 2 ? std::stoi(argv[2]) : 10;
        if ((devices != 1 && devices != 2 && devices != 4) || log < 2 || log > 20)
            throw std::runtime_error("usage: sumcheck-smoke [1|2|4] [log_count 2..20]");
        int available = 0;
        const auto status = cudaGetDeviceCount(&available);
        if (status == cudaErrorNoDevice || status == cudaErrorInsufficientDriver) {
            std::fprintf(stderr, "SKIP: NVIDIA device/driver unavailable\n");
            return 77;
        }
        CHECK(status);
        if (available < devices) throw std::runtime_error("insufficient requested GPUs");
        std::vector<std::thread> threads;
        std::vector<std::exception_ptr> errors(devices);
        std::vector<Report> reports(devices * 2);
        for (int i = 0; i < devices; ++i)
            threads.emplace_back([&, i] {
                try {
                    reports[2 * i] = exercise(i, 1u << log, true);
                    reports[2 * i + 1] = exercise(i, 1u << log, false);
                } catch (...) {
                    errors[i] = std::current_exception();
                }
            });
        for (auto& t : threads) t.join();
        for (auto& e : errors)
            if (e) std::rethrow_exception(e);
        for (auto& r : reports)
            std::printf(
                "{\"schema\":\"rv64-cuda-resident-sumcheck-v1\",\"device\":%d,\"count\":%u,"
                "\"base_n\":%s,\"combined_median_ms\":%.6f,\"split_median_ms\":%.6f,"
                "\"allocated_bytes\":%llu,\"hot_h2d_bytes\":0,\"hot_d2h_bytes\":0,\"all_rounds_"
                "verified\":true,\"full_block_verified\":false}\n",
                r.device, r.count, r.base ? "true" : "false", r.combined_ms, r.split_ms,
                (unsigned long long)r.bytes);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
