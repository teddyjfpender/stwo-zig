#include "context_owner.cuh"
#include "rv64/outer_gkr_projector.cuh"
#include <algorithm>
using namespace stwo::cuda::rv64;
extern "C" int stwo_circuit_outer_gkr_validate_on(void*, uint32_t, const void*, uint32_t);
extern "C" int stwo_circuit_outer_gkr_layer_on(void*, uint32_t, const void*, uint32_t, uint32_t, StwoRv64Plane, StwoRv64Plane);
extern "C" int stwo_circuit_outer_gkr_sum_on(void*, uint32_t, const void*, uint32_t, StwoRv64Plane, const uint32_t*, StwoRv64Plane, StwoRv64Plane, StwoRv64Plane);
extern "C" int stwo_circuit_outer_gkr_fold_on(void*, uint32_t, const void*, uint32_t, const uint32_t*, StwoRv64Plane, StwoRv64Plane);

static Fraction host_fraction(const StwoCircuitOuterGkrSource &s, uint32_t index) {
  switch (s.component) {
    case 2: return outer_gkr::Source<2>{s}.get(index);
    case 3: return outer_gkr::Source<3>{s}.get(index);
    case 4: return outer_gkr::Source<4>{s}.get(index);
    case 6: return outer_gkr::Source<6>{s}.get(index);
    default: throw std::runtime_error("unsupported source");
  }
}
static void same(Owner &owner, StwoRv64Plane a, StwoRv64Plane b) {
  if (owner.read(a) != owner.read(b)) throw std::runtime_error("projected/materialized mismatch");
}
int main() {
  try {
    uint32_t cases = 0, fractions = 0, mutants = 0, poles = 0;
    for (uint32_t row_log : {4u, 12u}) for (uint32_t kind : {2u, 3u, 4u, 6u}) {
      const uint32_t lookups = kind == 2 ? 12 : kind == 3 ? 5 : kind == 4 ? 26 : 16;
      for (uint32_t first = 0; first < lookups;) {
        const uint32_t lanes = 1u << (31 - __builtin_clz(lookups - first));
        const uint32_t lane_log = 31 - __builtin_clz(lanes), rows = 1u << row_log, count = lanes * rows;
        Owner owner(0);
        std::vector<uint32_t> fixed(rows * outer_gkr::tuples::kPpWidths[kind]);
        std::vector<uint32_t> main(rows * outer_gkr::tuples::kBaseWidths[kind]);
        std::vector<uint32_t> params(56);
        for (uint32_t i = 0; i < fixed.size(); ++i) fixed[i] = 1 + 13 * i;
        for (uint32_t i = 0; i < main.size(); ++i) main[i] = 1 + 17 * i;
        for (uint32_t i = 0; i < params.size(); ++i) params[i] = 1 + 19 * i;
        uint32_t status = 0;
        const StwoCircuitOuterGkrSource host{fixed.empty() ? nullptr : fixed.data(), main.data(), params.data(), &status,
                                            fixed.size(), main.size(), kind, row_log, first, lane_log};
        std::vector<uint32_t> numerators(8 * count), denominators(8 * count);
        for (uint32_t i = 0; i < count; ++i) {
          const auto f = host_fraction(host, i);
          store(numerators.data(), count, i, f.n);
          store(denominators.data(), count, i, f.d);
        }
        if (status) throw std::runtime_error("host source pole");
        const auto fp = owner.plane(std::max(size_t(1), fixed.size()), 1);
        const auto mp = owner.plane(main.size(), 1), pp = owner.plane(56, 1), verdict = owner.plane(1, 1);
        if (!fixed.empty()) owner.upload(fp, fixed);
        owner.upload(mp, main); owner.upload(pp, params); owner.upload(verdict, {0});
        const auto n = owner.plane(count, 8), d = owner.plane(count, 8);
        owner.upload(n, numerators); owner.upload(d, denominators);
        const StwoCircuitOuterGkrSource source{fixed.empty() ? nullptr : fp.words, mp.words, pp.words, verdict.words,
                                              fixed.size(), main.size(), kind, row_log, first, lane_log};
        const auto on = owner.plane(count / 2, 8), od = owner.plane(count / 2, 8);
        const auto rn = owner.plane(count / 2, 8), rd = owner.plane(count / 2, 8);
        const auto qn = owner.plane(count / 4, 8), qd = owner.plane(count / 4, 8);
        const auto sn = owner.plane(count / 4, 8), sd = owner.plane(count / 4, 8);
        const auto assignment = owner.plane(8, 1);
        owner.upload(assignment, {5,7,11,13,17,19,23,29});
        const auto eq = owner.plane(count / 4, 8);
        std::vector<uint32_t> eq_values(8 * (count / 4));
        for (uint32_t i = 0; i < eq_values.size(); ++i) eq_values[i] = 3 + 23 * i;
        owner.upload(eq, eq_values);
        const uint32_t groups = std::max(1u, (count / 4 + 127) / 128);
        const auto a = owner.plane(2 * groups, 8), b = owner.plane(2 * groups, 8);
        const auto actual = owner.plane(2, 8), reference = owner.plane(2, 8);
        CHECK(stwo_exec_context_sync(owner.ctx));
        CHECK(stwo_circuit_outer_gkr_validate_on(owner.ctx, 0, &source, count));
        CHECK(stwo_circuit_outer_gkr_layer_on(owner.ctx, 0, &source, count, 1, on, od));
        CHECK(stwo_rv64_gkr_layer_on(owner.ctx, 0, n, d, count, 1, rn, rd));
        same(owner, on, rn); same(owner, od, rd);
        CHECK(stwo_circuit_outer_gkr_layer_on(owner.ctx, 0, &source, count, 2, qn, qd));
        CHECK(stwo_rv64_gkr_layer_on(owner.ctx, 0, n, d, count, 2, sn, sd));
        same(owner, qn, sn); same(owner, qd, sd);
        CHECK(stwo_circuit_outer_gkr_sum_on(owner.ctx, 0, &source, count, eq, assignment.words, a, b, actual));
        CHECK(stwo_rv64_gkr_sum_on(owner.ctx, 0, n, d, count, eq, assignment.words, a, b, reference));
        same(owner, actual, reference);
        CHECK(stwo_circuit_outer_gkr_fold_on(owner.ctx, 0, &source, count, assignment.words, on, od));
        CHECK(stwo_rv64_gkr_fold_on(owner.ctx, 0, n, d, count, assignment.words, rn, rd));
        same(owner, on, rn); same(owner, od, rd);
        if (owner.read(verdict)[0]) throw std::runtime_error("device source status");
        // Range/geometry/alias mutants must refuse BEFORE a kernel launch.
        auto bad = source; bad.main_words--;
        if (!stwo_circuit_outer_gkr_validate_on(owner.ctx,0,&bad,count)) throw std::runtime_error("short source admitted");
        ++mutants;
        bad = source; bad.lane_first = lookups;
        if (!stwo_circuit_outer_gkr_validate_on(owner.ctx,0,&bad,count)) throw std::runtime_error("wrong lane group admitted");
        ++mutants;
        // n/d are materialized controls, so point one output into the actual source.
        auto alias = on; alias.words = const_cast<uint32_t*>(source.main);
        if (!stwo_circuit_outer_gkr_layer_on(owner.ctx,0,&source,count,1,alias,od)) throw std::runtime_error("MAIN-output alias admitted");
        ++mutants;
        if (kind == 6) {
          // Real zero-weight0/0 table fractions must stay poles, rather than
          // becoming neutral padding (0,1). The sticky verdict also rejects.
          owner.upload(mp, std::vector<uint32_t>(main.size(), 0));
          owner.upload(pp, std::vector<uint32_t>(56, 0));
          owner.upload(verdict, {0});
          CHECK(stwo_exec_context_sync(owner.ctx));
          CHECK(stwo_circuit_outer_gkr_layer_on(owner.ctx,0,&source,count,1,on,od));
          if (!owner.read(verdict)[0]) throw std::runtime_error("real pole not reported");
          const auto values = owner.read(od);
          if (std::any_of(values.begin(), values.end(), [](uint32_t x) { return x != 0; }))
            throw std::runtime_error("real pole laundered into padding");
          ++poles;
        }
        owner.close();
        ++cases; fractions += count; first += lanes;
      }
    }
    std::printf("{\"passed\":true,\"source_groups\":%u,\"source_fractions\":%u,\"geometry_alias_mutants\":%u,\"real_zero_weight_poles\":%u,\"layer_sum_fold_parity\":true}\n", cases, fractions, mutants, poles);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr,"ERROR %s\n",e.what()); return 1;
  }
}
