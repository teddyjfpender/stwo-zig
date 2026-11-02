// Real-driver independent-tail batch parity, canaries, failure isolation and timing.
#include "context_owner.cuh"
#include "oracle_data.cuh"
#include <algorithm>
#include <array>
#include <cstdio>
#include <thread>
using namespace stwo::cuda::rv64;
constexpr uint32_t canary = 0xdeadbeef;
static void guarded_equal(const std::vector<uint32_t>& got,
                          const std::vector<uint32_t>& expected) {
    if (got.size() < expected.size() ||
        !std::equal(expected.begin(), expected.end(), got.begin()))
        throw std::runtime_error("tail numerical mismatch");
    for (size_t i = expected.size(); i < got.size(); ++i)
        if (got[i] != canary) throw std::runtime_error("tail output guard overwritten");
}
struct Case {
    fixture::Data data;
    StwoRv64Plane n, d, eq, point, lambda, claim, seed, state, records, on, od, mask;
    std::vector<uint32_t> ns, ds;
    StwoRv64TailJob job{};
    Case(const Case&) = delete;
    Case& operator=(const Case&) = delete;
    Case(Case&&) = default;
    Case& operator=(Case&&) = default;
    Case(Owner& o, uint32_t count, bool base_n, uint32_t ordinal)
        : data(count, base_n, ordinal),
          n(o.plane(count + 3, base_n ? 1 : 8)),
          d(o.plane(count + 3, 8)),
          eq(o.plane(count / 4 + 3, 8)),
          point(o.plane(data.variables, 8)),
          lambda(o.plane(1, 8)),
          claim(o.plane(1, 8)),
          seed(o.plane(9, 1)),
          state(o.plane(round_state_words + 4, 1)),
          records(o.plane(data.variables * round_record_words + 4, 1)),
          on(o.plane(5, 8)),
          od(o.plane(5, 8)),
          mask(o.plane(36, 1)) {
        ns.assign(n.stride * n.coordinates, canary);
        ds.assign(d.stride * d.coordinates, canary);
        for (uint32_t i = 0; i < count; ++i) {
            if (base_n)
                ns[i] = data.n_soa[i];
            else
                store(ns.data(), n.stride, i, from_words(data.n_aos.data() + 8 * i));
            store(ds.data(), d.stride, i, from_words(data.d_aos.data() + 8 * i));
        }
        o.upload(n, ns);
        o.upload(d, ds);
        o.upload(point, data.point);
        o.upload(lambda, data.lambda);
        o.upload(claim, data.claim);
        o.upload(seed, data.seed);
        for (auto p : {eq, state, records, on, od, mask})
            o.upload(p, std::vector<uint32_t>(p.stride * p.coordinates, canary));
        job = {n,
               d,
               on,
               od,
               eq,
               point.words,
               lambda.words,
               state.words,
               records.words,
               mask.words,
               count,
               data.variables,
               0,
               0};
    }
    void check(Owner& o) const {
        guarded_equal(o.read(state), data.state);
        guarded_equal(o.read(records), data.records);
        guarded_equal(o.read(mask), data.terminal);
        for (uint32_t side = 0; side < 2; ++side) {
            const auto plane = side ? od : on;
            const auto got = o.read(plane);
            for (uint32_t c = 0; c < 8; ++c)
                for (uint32_t i = 0; i < plane.stride; ++i)
                    if (got[c * plane.stride + i] !=
                        (i < 2 ? data.terminal[16 * side + 8 * i + c] : canary))
                        throw std::runtime_error("tail terminal plane mismatch/guard");
        }
        if (o.read(n) != ns || o.read(d) != ds)
            throw std::runtime_error("tail modified source");
    }
};
struct Report {
    int device;
    uint32_t jobs;
    float sequential_ms, batch_ms;
};
static Report exercise(int device, uint32_t count) {
    Owner o(device);
    std::vector<Case> cases;
    cases.reserve(count);
    for (uint32_t i = 0; i < count; ++i)
        cases.emplace_back(o, 1u << (2 + (i + 6) % 7), i % 2 == 0, i * 37);
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    for (auto& c : cases)
        CHECK(stwo_rv64_gkr_eq_on(o.ctx, 1, c.point.words, c.data.variables, c.eq));
    std::array<StwoRv64TailJob, 8> packet{};
    for (uint32_t i = 0; i < count; ++i) packet[i] = cases[i].job;
    auto reset = [&] {
        for (auto& c : cases)
            CHECK(stwo_rv64_sumcheck_init_on(o.ctx, 1, c.state.words, c.seed.words,
                                             c.claim.words, c.data.variables));
    };
    auto wave = [&](bool batched) {
        if (batched)
            CHECK(stwo_rv64_sumcheck_tail_on(o.ctx, 1, packet.data(), count));
        else
            for (uint32_t i = 0; i < count; ++i)
                CHECK(stwo_rv64_sumcheck_tail_on(o.ctx, 1, &packet[i], 1));
    };
    reset();
    wave(true);
    for (auto& c : cases) c.check(o);
    if (count > 1) {
        auto rejected = packet;
        rejected[count - 1].mask = packet[0].state;
        if (stwo_rv64_sumcheck_tail_on(o.ctx, 1, rejected.data(), count) !=
            int(cudaErrorInvalidValue))
            throw std::runtime_error("cross-job mutable alias accepted");
        for (auto& c : cases) c.check(o);
    }
    // Poison one transcript and confirm all other independent blocks complete.
    auto bad = cases[0].data.point;
    fixture::put(bad, 0, one());
    o.upload(cases[0].point, bad);
    CHECK(stwo_exec_context_sync(o.ctx));
    reset();
    wave(true);
    CHECK(stwo_exec_context_sync(o.ctx));
    const auto state = o.read(cases[0].state), records = o.read(cases[0].records);
    if (state[10] != round_pole || state[9] != 0)
        throw std::runtime_error("tail failed to poison");
    for (uint32_t r = 0; r < cases[0].data.variables; ++r) {
        for (uint32_t i = 0; i < 40; ++i)
            if (records[r * round_record_words + i])
                throw std::runtime_error("stale failed record");
        if (records[r * round_record_words + 41] != UINT32_MAX)
            throw std::runtime_error("failed record not invalidated");
    }
    for (uint32_t i = 1; i < count; ++i) cases[i].check(o);
    o.upload(cases[0].point, cases[0].data.point);
    CHECK(stwo_exec_context_sync(o.ctx));
    void* raw = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
    const auto stream = reinterpret_cast<cudaStream_t>(raw);
    const auto begin = o.event(), end = o.event();
    float medians[2]{};
    for (int batched = 0; batched < 2; ++batched) {
        for (int i = 0; i < 3; ++i) {
            reset();
            wave(batched);
        }
        std::vector<float> times;
        for (int i = 0; i < 11; ++i) {
            reset();  // State reset is outside the timed tail interval.
            CHECK(cudaEventRecord(begin, stream));
            wave(batched);
            CHECK(cudaEventRecord(end, stream));
            CHECK(cudaEventSynchronize(end));
            float ms = 0;
            CHECK(cudaEventElapsedTime(&ms, begin, end));
            times.push_back(ms);
        }
        for (auto& c : cases) c.check(o);
        std::sort(times.begin(), times.end());
        medians[batched] = times[5];
    }
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
    return {device, count, medians[0], medians[1]};
}
int main(int argc, char** argv) {
    try {
        const int devices = argc > 1 ? std::stoi(argv[1]) : 1;
        if (devices != 1 && devices != 2 && devices != 4)
            throw std::runtime_error("usage: tail-smoke [1|2|4]");
        int available = 0;
        const auto status = cudaGetDeviceCount(&available);
        if (status == cudaErrorNoDevice || status == cudaErrorInsufficientDriver) {
            std::fprintf(stderr, "SKIP: NVIDIA device/driver unavailable\n");
            return 77;
        }
        CHECK(status);
        if (available < devices) throw std::runtime_error("insufficient requested GPUs");
        std::vector<std::thread> workers;
        std::vector<std::exception_ptr> errors(devices);
        std::vector<Report> reports(devices * 4);
        for (int d = 0; d < devices; ++d)
            workers.emplace_back([&, d] {
                try {
                    for (uint32_t k = 0; k < 4; ++k) reports[4 * d + k] = exercise(d, 1u << k);
                } catch (...) {
                    errors[d] = std::current_exception();
                }
            });
        for (auto& w : workers) w.join();
        for (auto& e : errors)
            if (e) std::rethrow_exception(e);
        for (auto r : reports)
            std::printf(
                "{\"schema\":\"rv64-tail-batch-v1\",\"device\":%d,\"jobs\":%u,"
                "\"sequential_ms\":%.6f,\"batch_ms\":%.6f,\"all_records_verified\":true,"
                "\"canaries_verified\":true,\"failure_isolation_verified\":true,\"full_block_"
                "verified\":false}\n",
                r.device, r.jobs, r.sequential_ms, r.batch_ms);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
