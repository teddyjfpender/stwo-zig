// Full resident single-oracle sumcheck feedback, benchmark and parity harness.
// The CPU reference is a separate host object, itself checked against Zig's
// native prover/verifier. No intermediate numerical values enter the host loop.
#include "rv64/om31.cuh"
#include "rv64/round.cuh"
#include "context_owner.cuh"
#include "oracle_data.cuh"
#include <algorithm>
#include <cstdio>
#include <thread>
using namespace stwo::cuda::rv64;
using fixture::put;
static void equal(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b,
                  const char* name) {
    if (a != b) throw std::runtime_error(std::string("resident sumcheck mismatch: ") + name);
}
struct Report {
    int device;
    uint32_t count;
    bool base;
    float combined_ms, split_ms, fused_combined_ms, fused_split_ms, fold_sum_ms, all_fused_ms,
        tail64_ms, tail256_ms;
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
    const fixture::Data data(count, base_n);
    const auto& expected_records = data.records;
    const auto& expected_state = data.state;
    const auto& expected_terminal = data.terminal;
    const auto& yn = data.point;
    o.upload(n, data.n_soa);
    o.upload(d, data.d_soa);
    o.upload(point, data.point);
    o.upload(lambda, data.lambda);
    o.upload(claim, data.claim);
    o.upload(seed, data.seed);
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    void* s = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &s));
    const auto stream = reinterpret_cast<cudaStream_t>(s);
    if (count >= 8) {
        // Rejected calls must enqueue nothing, even when all addresses belong
        // to the owner. Read/write aliasing is a range property, not ownership.
        const auto rejected = [&](StwoRv64Plane on, StwoRv64Plane input_eq, uint32_t size) {
            const int rc = stwo_rv64_gkr_fold_sum_on(o.ctx, 1, n, d, size, point.words, on, d0,
                                                     input_eq, lambda.words, a, b, raw);
            if (rc != int(cudaErrorInvalidValue))
                throw std::runtime_error("fused fold preflight accepted invalid workspace");
        };
        rejected(d, eq, count);  // output aliases input denominator
        auto short_eq = eq;
        short_eq.stride = count / 8 - 1;
        rejected(n0, short_eq, count);
        rejected(n0, eq, 4);  // terminal fold has no subsequent sum
    }
    StwoRv64Plane terminal_n = n, terminal_d = d;
    auto wave = [&](bool split, bool fused, bool fold_sum = false, uint32_t tail_count = 0) {
        CHECK(stwo_rv64_sumcheck_init_on(o.ctx, 1, state.words, seed.words, claim.words,
                                         variables));
        if (fused)
            CHECK(stwo_rv64_gkr_eq_fused_on(o.ctx, 1, point.words, variables, eq));
        else
            CHECK(stwo_rv64_gkr_eq_on(o.ctx, 1, point.words, variables, eq));
        auto current_n = n, current_d = d;
        uint32_t size = count;
        bool tail_used = false;
        for (uint32_t r = 0; r < variables; ++r) {
            if (tail_count && size <= tail_count) {
                StwoRv64TailJob job{};
                job.n = current_n;
                job.d = current_d;
                job.out_n = r % 2 == 0 ? n0 : n1;
                job.out_d = r % 2 == 0 ? d0 : d1;
                job.eq = eq;
                job.point = point.words;
                job.lambda = lambda.words;
                job.state = state.words;
                job.records = records.words + r * round_record_words;
                job.mask = compact.words;
                job.count = size;
                job.variables = variables;
                job.first = r;
                CHECK(stwo_rv64_sumcheck_tail_on(o.ctx, 1, &job, 1));
                current_n = job.out_n;
                current_d = job.out_d;
                tail_used = true;
                break;
            }
            if (!fold_sum || r == 0) {
                if (split)
                    CHECK(stwo_rv64_gkr_sum_split_on(o.ctx, 1, current_n, current_d, size, eq,
                                                     lambda.words, a, b, raw));
                else
                    CHECK(stwo_rv64_gkr_sum_on(o.ctx, 1, current_n, current_d, size, eq,
                                               lambda.words, a, b, raw));
            }
            auto* record = records.words + r * round_record_words;
            CHECK(stwo_rv64_sumcheck_round_on(o.ctx, 1, state.words, variables, r, raw,
                                              point.words, record));
            const auto on = (r % 2 == 0) ? n0 : n1, od = (r % 2 == 0) ? d0 : d1;
            if (fold_sum && size >= 8 && (!tail_count || size / 2 > tail_count))
                CHECK(stwo_rv64_gkr_fold_sum_on(o.ctx, 1, current_n, current_d, size,
                                                record + 32, on, od, eq, lambda.words, a, b,
                                                raw));
            else
                CHECK(stwo_rv64_gkr_fold_on(o.ctx, 1, current_n, current_d, size, record + 32,
                                            on, od));
            current_n = on;
            current_d = od;
            size /= 2;
        }
        terminal_n = current_n;
        terminal_d = current_d;
        if (!tail_used)
            CHECK(stwo_rv64_gkr_pack_mask_on(o.ctx, 1, terminal_n, terminal_d, compact.words));
    };
    auto compare = [&]() {
        CHECK(stwo_exec_context_sync(o.ctx));
        equal(o.read(state), expected_state, "state/channel");
        equal(o.read(records), expected_records, "polynomials/challenges");
        equal(o.read(compact), expected_terminal, "terminal mask");
    };
    auto begin = o.event(), end = o.event();
    float medians[8]{};
    for (int variant = 0; variant < 8; ++variant) {
        for (int i = 0; i < 3; ++i)
            wave(variant < 4 && (variant & 1), (variant >= 2 && variant < 4) || variant >= 5,
                 variant >= 4,
                 variant == 6   ? 64
                 : variant == 7 ? 256
                                : 0);
        compare();
        std::vector<float> times;
        for (int i = 0; i < 11; ++i) {
            CHECK(cudaEventRecord(begin, stream));
            wave(variant < 4 && (variant & 1), (variant >= 2 && variant < 4) || variant >= 5,
                 variant >= 4,
                 variant == 6   ? 64
                 : variant == 7 ? 256
                                : 0);
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
    wave(false, true, true, 256);
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
    // Under initcheck, clearing an already failed record must not inspect
    // a numerical scratch allocation that has never been initialized.
    const auto unused_raw = o.plane(2, 8);
    CHECK(stwo_rv64_sumcheck_round_on(o.ctx, 1, state.words, variables, 0, unused_raw,
                                      point.words, records.words));
    CHECK(stwo_exec_context_sync(o.ctx));
    const auto cleared = o.read(records);
    for (uint32_t j = 0; j < round_record_words; ++j)
        if (cleared[j] != (j == 41 ? UINT32_MAX : 0))
            throw std::runtime_error("poisoned record clearance mismatch");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    Report report{device,     count,      base_n,     medians[0],
                  medians[1], medians[2], medians[3], medians[4],
                  medians[5], medians[6], medians[7], o.allocated_bytes};
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
                "\"fused_eq_combined_ms\":%.6f,\"fused_eq_split_ms\":%.6f,\"fold_sum_ms\":%.6f,"
                "\"all_fused_ms\":%.6f,\"tail64_ms\":%.6f,\"tail256_ms\":%.6f,\"allocated_"
                "bytes\":%"
                "llu,\"hot_h2d_bytes\":0,\"hot_d2h_bytes\":0,\"all_rounds_"
                "verified\":true,\"full_block_verified\":false}\n",
                r.device, r.count, r.base ? "true" : "false", r.combined_ms, r.split_ms,
                r.fused_combined_ms, r.fused_split_ms, r.fold_sum_ms, r.all_fused_ms,
                r.tail64_ms, r.tail256_ms, (unsigned long long)r.bytes);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
