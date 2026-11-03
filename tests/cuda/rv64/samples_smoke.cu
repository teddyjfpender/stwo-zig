#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/channel.h"
#include "rv64/samples.h"
__global__ void sample_tamper(uint32_t *word, uint32_t value) { *word = value; }
__global__ void sample_pole(uint32_t *words) {
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = i == 1 ? 1 : 0;
}
static void exercise(const std::string &path, uint32_t fault) {
  FixtureWords f(path);
  const auto h = f.take(8);
  if (h[0] != 0x52565350 || h[1] != 1)
    throw std::runtime_error("samples fixture version");
  const uint32_t groups = h[2], terms = h[3];
  const auto seed = f.take(9);
  auto recipes = f.take(groups * 4), sources = f.take(terms * 4),
       descriptors = f.take(terms * 4);
  const auto dispatch = recipes;
  std::vector<uint32_t> trees[4];
  for (uint32_t i = 0; i < 4; ++i)
    trees[i] = f.take(h[i + 4]);
  const auto expected_parameter = f.take(8),
             expected_points = f.take((groups + 1) * 16),
             expected_factors = f.take(groups * 28 * 8),
             expected_values = f.take(terms * 8), expected_alpha = f.take(8),
             expected_channel = f.take(16);
  if (f.position != f.data.size())
    throw std::runtime_error("trailing sample fixture");
  switch (fault) {
  case 1:
    recipes[0] = 0x7fffffffu;
    break;
  case 2:
    recipes[0] = recipes[1] = 0;
    break;
  case 3:
    recipes[2] = 29;
    break;
  case 4:
    recipes[3] = 29;
    break;
  case 5:
    sources[2] = 4;
    break;
  case 6:
    descriptors[0] = terms;
    break;
  case 7:
    descriptors[1] = groups;
    break;
  case 8:
    descriptors[3] = 1;
    break;
  case 9:
    sources[0] = trees[0].size();
    break;
  case 10:
    sources[3] = 2;
    break;
  case 11:
    trees[0][0] = 0x7fffffffu;
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
  const auto checkpoint = upload(seed), recipe = upload(recipes),
             source = upload(padded_sources), desc = upload(descriptors),
             status = upload({fault == 12 ? 32u : 0u}), state = o.plane(16, 1),
             boundary = o.plane(16, 1), parameter = o.plane(8, 1),
             alpha = o.plane(8, 1), points = o.plane((groups + 1) * 16, 1),
             factors = o.plane(groups * 28 * 8, 1),
             ready = o.plane(groups + 1, 1), valid = o.plane(2, 1),
             values = o.plane(terms * 8 + 8, 1);
  o.upload(values, std::vector<uint32_t>(terms * 8 + 8, 0xdeadbeefu));
  StwoRv64Plane tree_buffers[4]{};
  for (uint32_t i = 0; i < 4; ++i)
    if (!trees[i].empty())
      tree_buffers[i] = upload(trees[i]);
  uint32_t maximum_log = 0;
  for (uint32_t g = 0; g < groups; ++g)
    maximum_log = std::max(maximum_log, dispatch[g * 4 + 3]);
  const uint64_t scratch_words =
      uint64_t(((1u << maximum_log) + 1023) / 1024) * 2 * 8;
  const auto scratch_a = o.plane(scratch_words, 1),
             scratch_b = o.plane(scratch_words, 1);
  StwoCudaDependency ingress{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ingress));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ingress));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
  const auto stream = reinterpret_cast<cudaStream_t>(raw);
  CHECK(stwo_rv64_channel_init_on(o.ctx, 1, state.words, checkpoint.words, 17));
  CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 0, 17, 34, 1,
                                  parameter.words, boundary.words));
  if (fault == 13)
    sample_pole<<<1, 1, 0, stream>>>(parameter.words);
  if (fault == 14)
    sample_tamper<<<1, 1, 0, stream>>>(parameter.words, 0x7fffffffu);
  StwoRv64SamplePoints point_job{
      parameter.words,
      reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words),
      points.words,
      factors.words,
      ready.words,
      status.words,
      groups,
      0};
  auto invalid = point_job;
  invalid.factors = points.words;
  if (!stwo_rv64_sample_points_on(o.ctx, 1, &invalid))
    throw std::runtime_error("sample points alias accepted");
  CHECK(stwo_rv64_sample_points_on(o.ctx, 1, &point_job));
  if (fault == 15)
    sample_tamper<<<1, 1, 0, stream>>>(ready.words + 1, 2);
  if (fault == 16)
    sample_tamper<<<1, 1, 0, stream>>>(factors.words, 0x7fffffffu);
  if (fault == 17)
    sample_tamper<<<1, 1, 0, stream>>>(recipe.words + 3, 2);
  for (uint32_t group = 0; group < groups; ++group) {
    StwoRv64SampleEvaluation j{};
    for (uint32_t i = 0; i < 4; ++i) {
      j.trees[i] = tree_buffers[i].words;
      j.tree_words[i] = trees[i].size();
    }
    j.sources = reinterpret_cast<const StwoRv64DeepSource *>(source.words);
    j.terms = reinterpret_cast<const StwoRv64DeepTerm *>(desc.words);
    j.recipes = reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words);
    j.factors = factors.words;
    j.point_ready = ready.words;
    j.scratch_a = scratch_a.words;
    j.scratch_b = scratch_b.words;
    j.values = values.words;
    j.valid = valid.words;
    j.status = status.words;
    j.scratch_words = scratch_words;
    j.value_words = values.stride;
    j.source_count = terms;
    j.term_capacity = terms;
    j.group_count = groups;
    j.first = group * 2;
    j.count = 2;
    j.coefficient_log = dispatch[group * 4 + 3];
    auto bad = j;
    bad.scratch_b = scratch_a.words;
    if (!stwo_rv64_sample_evaluate_on(o.ctx, 1, &bad))
      throw std::runtime_error("sample scratch alias accepted");
    bad = j;
    bad.scratch_words =
        uint64_t(((1u << j.coefficient_log) + 1023) / 1024) * 2 * 8 - 1;
    if (!stwo_rv64_sample_evaluate_on(o.ctx, 1, &bad))
      throw std::runtime_error("sample undersized scratch accepted");
    bad = j;
    bad.sources =
        reinterpret_cast<const StwoRv64DeepSource *>(source.words + 1);
    if (!stwo_rv64_sample_evaluate_on(o.ctx, 1, &bad))
      throw std::runtime_error("sample misaligned descriptor accepted");
    CHECK(stwo_rv64_sample_evaluate_on(o.ctx, 1, &j));
  }
  CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, 1, 34, 51, values.words,
                                 terms * 8, 1, boundary.words));
  CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 2, 51, 68, 1,
                                  alpha.words, boundary.words));
  const auto verdict = o.read(status)[0];
  const auto actual_values = o.read(values);
  for (uint32_t i = terms * 8; i < terms * 8 + 8; ++i)
    if (actual_values[i] != 0xdeadbeefu)
      throw std::runtime_error("sample output guard");
  if (!fault) {
    if (verdict)
      throw std::runtime_error("honest sampling verdict");
    fixture_equal("sample parameter", o.read(parameter), expected_parameter);
    fixture_equal("sample points", o.read(points), expected_points);
    fixture_equal("sample factors", o.read(factors), expected_factors);
    fixture_equal("sample values",
                  {actual_values.begin(), actual_values.begin() + terms * 8},
                  expected_values);
    fixture_equal("sample quotient alpha", o.read(alpha), expected_alpha);
    fixture_equal("sample native channel", o.read(state), expected_channel);
  } else if (!verdict)
    throw std::runtime_error("sampling mutant accepted");
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ingress));
  o.close();
  std::printf("{\"groups\":%u,\"terms\":%u,\"max_coefficient_log\":%u,"
              "\"fault\":%u,\"status\":%u,\"result\":\"PASS\"}\n",
              groups, terms, maximum_log, fault, verdict);
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("usage: samples-smoke FIXTURES");
    exercise(std::string(argv[1]) + "/case-0.bin", 0);
    exercise(std::string(argv[1]) + "/case-1.bin", 0);
    for (uint32_t fault = 1; fault <= 17; ++fault)
      exercise(std::string(argv[1]) + "/case-0.bin", fault);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "SAMPLES FAIL: %s\n", e.what());
    return 1;
  }
}
