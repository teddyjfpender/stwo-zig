// Native Zig PCS oracle -> compact device aggregate -> base LDE -> OM31 DEEP.
// No intermediate field-value transfers; these are numerical PCS gates, not
// execution proof acceptance. Metadata comes from immutable fixture setup.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/channel.h"
#include "rv64/deep.h"
#include "rv64/samples.h"
#include <cstring>
#include <fstream>
#include <string>
extern "C" int stwo_lde_n2b_addressed_on(uint32_t *, size_t, const void *,
                                         uint32_t, size_t, uint32_t,
                                         const uint32_t *, uint32_t, uint32_t,
                                         void *, uint32_t, uint32_t *);
using Reader = FixtureWords;
__global__ void tamper_word(uint32_t *word, uint32_t value) { *word = value; }
static void exercise(const std::string &path, uint32_t fault) {
  Reader f(path);
  const auto h = f.take(10);
  if (h[0] != 0x52564450 || (h[1] != 1 && h[1] != 2))
    throw std::runtime_error("fixture version");
  const uint32_t gc = h[2], sc = h[3], tc = h[4], log = h[5], rows = 1u << log;
  const bool resident_samples = h[1] == 2;
  std::vector<uint32_t> initial_seed, recipes, expected_parameter,
      expected_channel;
  if (resident_samples) {
    initial_seed = f.take(9);
    recipes = f.take(gc * 4);
    expected_parameter = f.take(8);
    expected_channel = f.take(16);
  }
  auto sources = f.take(sc * 4), terms = f.take(tc * 4),
       groups = f.take(gc * 8), tree = f.take(h[6]);
  auto points = f.take(gc * 16), values = f.take(tc * 8), alpha = f.take(8);
  const auto expected_weights = f.take(tc * 8),
             expected_linear = f.take(gc * 16),
             expected_coefficients = f.take(h[7]),
             expected_evaluations = f.take(h[8]);
  auto domain = f.take(rows * 2);
  const auto expected = f.take(rows * 8), twiddles = f.take(h[9]);
  if (f.position != f.data.size())
    throw std::runtime_error("trailing fixture");
  auto dispatch_groups = groups;
  switch (fault) {
  case 1:
    sources[2] = 4;
    break; // missing tree
  case 2:
    terms[3] = 1;
    break;
  case 3:
    groups[4] = 1;
    break; // overlapping/noncontiguous destination
  case 4:
    points[0] = 0x7fffffffu;
    break;
  case 5:
    std::fill(points.begin(), points.begin() + 16, 0);
    points[0] = 1;
    break;
  case 6:
    values[0] = 0x7fffffffu;
    break;
  case 7:
    tree[0] = 0x7fffffffu;
    break;
  case 8:
    domain[0] = 0x7fffffffu;
    break;
  case 9:
    alpha[0] = 0x7fffffffu;
    break;
  case 10:
    groups[0] = 1;
    break;
  case 11:
    sources[0] = uint32_t(tree.size());
    break;
  case 12:
    terms[0] = sc;
    break;
  case 13:
    terms[2] = tc;
    break;
  case 14:
    groups[3] = 29;
    break;
  default:
    break;
  }
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &v) {
    auto p = o.plane(v.size(), 1);
    o.upload(p, v);
    return p;
  };
  auto padded_sources = sources;
  padded_sources.resize(sources.size() + 2, 0);
  const auto src = upload(padded_sources), term = upload(terms),
             grp = upload(groups), input = upload(tree), xy = upload(domain);
  const auto point_arena =
      resident_samples ? o.plane((gc + 1) * 16, 1) : upload(points);
  const StwoRv64Plane pts{point_arena.words + (resident_samples ? 16 : 0),
                          gc * 16, 1, 0};
  const auto vals = resident_samples ? o.plane(tc * 8, 1) : upload(values),
             random = resident_samples ? o.plane(8, 1) : upload(alpha);
  StwoRv64Plane seed{}, recipe{}, state{}, boundary{}, parameter{},
      sample_factors{}, sample_ready{}, sample_valid{}, sample_scratch_a{},
      sample_scratch_b{};
  uint64_t sample_scratch_words = 0;
  if (resident_samples) {
    seed = upload(initial_seed);
    recipe = upload(recipes);
    state = o.plane(16, 1);
    boundary = o.plane(16, 1);
    parameter = o.plane(8, 1);
    sample_factors = o.plane(gc * 28 * 8, 1);
    sample_ready = o.plane(gc + 1, 1);
    sample_valid = o.plane(2, 1);
    for (uint32_t g = 0; g < gc; ++g)
      sample_scratch_words = std::max(
          sample_scratch_words,
          uint64_t(((1u << dispatch_groups[g * 8 + 2]) + 1023) / 1024) * 2 * 8);
    sample_scratch_a = o.plane(sample_scratch_words, 1);
    sample_scratch_b = o.plane(sample_scratch_words, 1);
  }
  const auto weights = o.plane(tc * 8, 1), linear = o.plane(gc * 16, 1),
             arena = o.plane(h[7] + h[8] + h[9] + gc * 48, 1),
             valid = o.plane(2, 1), status = upload({fault == 15 ? 32u : 0u}),
             output = o.plane(rows + 3, 8);
  const StwoRv64Plane coeff{arena.words, h[7], 1, 0},
      eval{arena.words + h[7], h[8], 1, 0};
  const StwoRv64Plane tw{arena.words + h[7] + h[8], h[9], 1, 0};
  o.upload(tw, twiddles);
  o.upload(output, std::vector<uint32_t>((rows + 3) * 8, 0xdeadbeefu));
  std::vector<StwoRv64Plane> lde_descriptors;
  for (uint32_t g = 0; g < gc; ++g) {
    const uint32_t *d = dispatch_groups.data() + g * 8;
    std::vector<uint32_t> descriptors;
    for (uint32_t c = 0; c < 8; ++c) {
      descriptors.insert(
          descriptors.end(),
          {d[4] + (c << d[2]), 0, h[7] + d[6] + (c << d[3]), 0, d[2], 0});
    }
    StwoRv64Plane packet{arena.words + h[7] + h[8] + h[9] + g * 48, 48, 1, 0};
    o.upload(packet, descriptors);
    lde_descriptors.push_back(packet);
  }
  StwoCudaDependency ingress{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ingress));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ingress));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
  if (resident_samples) {
    CHECK(stwo_rv64_channel_init_on(o.ctx, 1, state.words, seed.words, 17));
    CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 0, 17, 34, 1,
                                    parameter.words, boundary.words));
    StwoRv64SamplePoints pj{
        parameter.words,
        reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words),
        point_arena.words,
        sample_factors.words,
        sample_ready.words,
        status.words,
        gc,
        0};
    CHECK(stwo_rv64_sample_points_on(o.ctx, 1, &pj));
    for (uint32_t g = 0; g < gc; ++g) {
      StwoRv64SampleEvaluation sj{};
      sj.trees[0] = input.words;
      sj.tree_words[0] = tree.size();
      sj.sources = reinterpret_cast<const StwoRv64DeepSource *>(src.words);
      sj.terms = reinterpret_cast<const StwoRv64DeepTerm *>(term.words);
      sj.recipes = reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words);
      sj.factors = sample_factors.words;
      sj.point_ready = sample_ready.words;
      sj.scratch_a = sample_scratch_a.words;
      sj.scratch_b = sample_scratch_b.words;
      sj.values = vals.words;
      sj.valid = sample_valid.words;
      sj.status = status.words;
      sj.scratch_words = sample_scratch_words;
      sj.value_words = tc * 8;
      sj.source_count = sc;
      sj.term_capacity = tc;
      sj.group_count = gc;
      sj.first = g * 2;
      sj.count = 2;
      sj.coefficient_log = dispatch_groups[g * 8 + 2];
      CHECK(stwo_rv64_sample_evaluate_on(o.ctx, 1, &sj));
    }
    CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, 1, 34, 51, vals.words,
                                   tc * 8, 1, boundary.words));
    CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 2, 51, 68, 1,
                                    random.words, boundary.words));
  }
  StwoRv64DeepPrepare prepare{};
  prepare.trees[0] = input.words;
  prepare.tree_words[0] = tree.size();
  prepare.sources = reinterpret_cast<const StwoRv64DeepSource *>(src.words);
  prepare.terms = reinterpret_cast<const StwoRv64DeepTerm *>(term.words);
  prepare.groups = reinterpret_cast<const StwoRv64DeepGroup *>(grp.words);
  prepare.points = pts.words;
  prepare.values = vals.words;
  prepare.alpha = random.words;
  prepare.weights = weights.words;
  prepare.linear = linear.words;
  prepare.coefficients = coeff.words;
  prepare.valid = valid.words;
  prepare.status = status.words;
  prepare.coefficient_words = h[7];
  prepare.source_count = sc;
  prepare.term_count = tc;
  prepare.group_count = gc;
  auto invalid = prepare;
  invalid.weights = coeff.words;
  if (!stwo_rv64_deep_prepare_on(o.ctx, 1, &invalid))
    throw std::runtime_error("DEEP alias accepted");
  invalid = prepare;
  invalid.coefficient_words = arena.stride + 1;
  if (!stwo_rv64_deep_prepare_on(o.ctx, 1, &invalid))
    throw std::runtime_error("DEEP undersized allocation accepted");
  invalid = prepare;
  invalid.sources = reinterpret_cast<const StwoRv64DeepSource *>(src.words + 1);
  if (!stwo_rv64_deep_prepare_on(o.ctx, 1, &invalid))
    throw std::runtime_error("misaligned DEEP source descriptor accepted");
  invalid = prepare;
  invalid.groups = reinterpret_cast<const StwoRv64DeepGroup *>(grp.words + 1);
  if (!stwo_rv64_deep_prepare_on(o.ctx, 1, &invalid))
    throw std::runtime_error("misaligned DEEP group descriptor accepted");
  CHECK(stwo_rv64_deep_prepare_on(o.ctx, 1, &prepare));
  uint32_t tw_offset = 0;
  for (uint32_t g = 0; g < gc; ++g) {
    const uint32_t *d = dispatch_groups.data() + g * 8;
    const uint32_t m = 1u << d[3];
    uint32_t launches = 0;
    CHECK(stwo_lde_n2b_addressed_on(
        arena.words, arena.stride, lde_descriptors[g].words, 8, h[7] + d[6],
        d[3], tw.words + tw_offset, m / 2, m / 2, raw, 1, &launches));
    tw_offset += m / 2;
  }
  StwoRv64DeepCombine combine{};
  if (fault == 16)
    tamper_word<<<1, 1, 0, reinterpret_cast<cudaStream_t>(raw)>>>(eval.words,
                                                                  0x7fffffffu);
  if (fault == 17)
    tamper_word<<<1, 1, 0, reinterpret_cast<cudaStream_t>(raw)>>>(grp.words + 3,
                                                                  29);
  if (fault == 18)
    tamper_word<<<1, 1, 0, reinterpret_cast<cudaStream_t>(raw)>>>(valid.words,
                                                                  0);
  if (fault == 19)
    tamper_word<<<1, 1, 0, reinterpret_cast<cudaStream_t>(raw)>>>(pts.words,
                                                                  0x7fffffffu);
  combine.groups = prepare.groups;
  combine.points = pts.words;
  combine.linear = linear.words;
  combine.evaluations = eval.words;
  combine.domain_xy = xy.words;
  combine.valid = valid.words;
  combine.output = output;
  combine.status = status.words;
  combine.evaluation_words = h[8];
  combine.group_count = gc;
  combine.output_log = log;
  auto bad_combine = combine;
  bad_combine.output.words = eval.words;
  if (!stwo_rv64_deep_combine_on(o.ctx, 1, &bad_combine))
    throw std::runtime_error("DEEP combine alias accepted");
  CHECK(stwo_rv64_deep_combine_on(o.ctx, 1, &combine));
  const auto verdict = o.read(status)[0];
  const auto actual = o.read(output);
  for (uint32_t c = 0; c < 8; ++c) {
    for (uint32_t r = rows; r < rows + 3; ++r)
      if (actual[uint64_t(c) * (rows + 3) + r] != 0xdeadbeefu)
        throw std::runtime_error("DEEP output guard");
  }
  if (!fault) {
    if (verdict)
      throw std::runtime_error("honest DEEP verdict");
    if (resident_samples) {
      fixture_equal("resident sample parameter", o.read(parameter),
                    expected_parameter);
      fixture_equal("resident sample points", o.read(pts), points);
      fixture_equal("resident sample values", o.read(vals), values);
      fixture_equal("resident quotient alpha", o.read(random), alpha);
      fixture_equal("resident sample channel", o.read(state), expected_channel);
    }
    fixture_equal("line weights", o.read(weights), expected_weights);
    fixture_equal("group line", o.read(linear), expected_linear);
    fixture_equal("compact aggregate", o.read(coeff), expected_coefficients);
    fixture_equal("aggregate LDE", o.read(eval), expected_evaluations);
    std::vector<uint32_t> packed;
    for (uint32_t c = 0; c < 8; ++c)
      packed.insert(packed.end(), actual.begin() + uint64_t(c) * (rows + 3),
                    actual.begin() + uint64_t(c) * (rows + 3) + rows);
    fixture_equal("native OM31 DEEP", packed, expected);
  } else if (!verdict)
    throw std::runtime_error("DEEP mutant accepted");
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ingress));
  o.close();
  std::printf("{\"groups\":%u,\"rows\":%u,\"fault\":%u,\"status\":%u,"
              "\"result\":\"PASS\"}\n",
              gc, rows, fault, verdict);
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("usage: deep-smoke FIXTURE_DIRECTORY");
    for (uint32_t i = 0; i < 5; ++i)
      exercise(std::string(argv[1]) + "/case-" + std::to_string(i) + ".bin", 0);
    for (uint32_t fault = 1; fault <= 19; ++fault)
      exercise(std::string(argv[1]) + "/case-1.bin", fault);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "DEEP FAIL: %s\n", e.what());
    return 1;
  }
}
