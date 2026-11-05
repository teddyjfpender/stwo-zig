#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/projected_gkr.cuh"
#include <algorithm>
using namespace stwo::cuda::rv64;

struct Source {
  const uint32_t *parameters;
  uint32_t count;
  bool validate(Custody &c, uint32_t n) const {
    return n == count && c.range(parameters, 8, false);
  }
  __host__ __device__ Fraction get(uint32_t i) const {
    if (i % 13 == 0) return {zero(), one()};
    return {base(i % 7), add(from_words(parameters), base(3 * i + 1))};
  }
};
static std::vector<uint32_t> plane_values(const std::vector<OM31> &values) {
  std::vector<uint32_t> out(values.size() * 8);
  for (size_t i = 0; i != values.size(); ++i) store(out.data(), values.size(), i, values[i]);
  return out;
}
static void exercise(uint32_t count) {
  Owner o(0);
  std::vector<uint32_t> parameters{1, 2, 3, 4, 5, 6, 7, 8};
  auto p = o.plane(8, 1); o.upload(p, parameters);
  Source device{p.words, count}, host{parameters.data(), count};
  CHECK(stwo_exec_context_sync(o.ctx));
  CHECK(projected::validate_on<Source>(o.ctx, 1, &device, count));
  auto on = o.plane(count / 2, 8), od = o.plane(count / 2, 8);
  CHECK(projected::layer_on<Source>(o.ctx, 1, &device, count, 1, on, od));
  std::vector<OM31> n(count / 2), d(count / 2);
  for (uint32_t i = 0; i != count / 2; ++i) {
    const auto value = combine(host.get(2 * i), host.get(2 * i + 1));
    n[i] = value.n; d[i] = value.d;
  }
  fixture_equal("projected product numerators", o.read(on), plane_values(n));
  fixture_equal("projected product denominators", o.read(od), plane_values(d));
  auto x = o.plane(8, 1); o.upload(x, parameters); CHECK(stwo_exec_context_sync(o.ctx));
  CHECK(projected::fold_on<Source>(o.ctx, 1, &device, count, x.words, on, od));
  const auto assignment = from_words(parameters.data());
  for (uint32_t i = 0; i != count / 2; ++i) {
    const auto a = host.get(i), b = host.get(i + count / 2);
    n[i] = fold(a.n, b.n, assignment); d[i] = fold(a.d, b.d, assignment);
  }
  fixture_equal("projected half-split numerators", o.read(on), plane_values(n));
  fixture_equal("projected half-split denominators", o.read(od), plane_values(d));
  if (count >= 4) {
    auto small_n = o.plane(count / 4, 8), small_d = o.plane(count / 4, 8);
    CHECK(projected::layer_on<Source>(o.ctx, 1, &device, count, 2, small_n, small_d));
    std::vector<OM31> en(count / 4), ed(count / 4), ev(count / 4);
    Pair total{zero(), zero()};
    for (uint32_t i = 0; i != count / 4; ++i) {
      const auto value = combine(combine(host.get(4 * i), host.get(4 * i + 1)),
                                 combine(host.get(4 * i + 2), host.get(4 * i + 3)));
      en[i] = value.n; ed[i] = value.d; ev[i] = add(assignment, base(i));
      const uint32_t j = 2 * i, k = count / 2 + 2 * i;
      const auto term = sum_term(host.get(j), host.get(j + 1), host.get(k), host.get(k + 1), ev[i], assignment);
      total.at0 = add(total.at0, term.at0); total.at2 = add(total.at2, term.at2);
    }
    fixture_equal("projected two-level numerators", o.read(small_n), plane_values(en));
    fixture_equal("projected two-level denominators", o.read(small_d), plane_values(ed));
    const uint32_t groups = (count / 4 + 127) / 128;
    auto eq = o.plane(count / 4, 8), a = o.plane(2 * groups, 8), b = o.plane(2 * groups, 8), out = o.plane(2, 8);
    o.upload(eq, plane_values(ev)); CHECK(stwo_exec_context_sync(o.ctx));
    CHECK(projected::sum_on<Source>(o.ctx, 1, &device, count, eq, x.words, a, b, out));
    fixture_equal("projected sumcheck 0/2", o.read(out), plane_values({total.at0, total.at2}));
    if (!projected::sum_on<Source>(o.ctx, 1, &device, count, eq, x.words, a, b, eq))
      throw std::runtime_error("projected sum read/write alias admitted");
  } else {
    auto out = o.plane(32, 1);
    CHECK(projected::mask_on<Source>(o.ctx, 1, &device, out.words));
    std::vector<uint32_t> expected(32);
    for (uint32_t i = 0; i != 2; ++i) for (uint32_t c = 0; c != 8; ++c) {
      const auto f = host.get(i);
      expected[8 * i + c] = coordinate(f.n, c); expected[16 + 8 * i + c] = coordinate(f.d, c);
    }
    fixture_equal("projected two-row mask", o.read(out), expected);
  }
  if (!projected::layer_on<Source>(o.ctx, 1, &device, count, 1, p, od))
    throw std::runtime_error("projected source/output alias admitted");
  if (!projected::validate_on<Source>(o.ctx, 1, &device, count * 2))
    throw std::runtime_error("projected source geometry mismatch admitted");
  std::printf("PROJECTED_GKR count=%u input_fraction_bytes=0 cpu_numerical_parity=true\n", count);
  o.close();
}
int main() {
  try { for (uint32_t n : {2u, 4u, 8u, 512u, 131072u}) exercise(n); return 0; }
  catch (const std::exception &e) { std::fprintf(stderr, "FAIL %s\n", e.what()); return 1; }
}
