// Native Zig PCS oracle -> compact device aggregate -> base LDE -> OM31 DEEP.
// No intermediate field-value transfers; these are numerical PCS gates, not
// execution proof acceptance. Metadata comes from immutable fixture setup.
#include "context_owner.cuh"
#include "rv64/deep.h"
#include <cstring>
#include <fstream>
#include <string>
extern "C" int stwo_lde_n2b_addressed_on(uint32_t *, size_t, const void *,
                                         uint32_t, size_t, uint32_t,
                                         const uint32_t *, uint32_t, uint32_t,
                                         void *, uint32_t, uint32_t *);
struct Reader {
  std::vector<uint32_t> data;
  size_t position = 0;
  Reader(const std::string &path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
      throw std::runtime_error("fixture missing");
    const size_t bytes = size_t(f.tellg());
    if (bytes % 4)
      throw std::runtime_error("fixture alignment");
    data.resize(bytes / 4);
    f.seekg(0);
    f.read(reinterpret_cast<char *>(data.data()), bytes);
    if (!f)
      throw std::runtime_error("fixture truncated");
  }
  std::vector<uint32_t> take(size_t n) {
    if (n > data.size() - position)
      throw std::runtime_error("fixture bounds");
    std::vector<uint32_t> out(data.begin() + position,
                              data.begin() + position + n);
    position += n;
    return out;
  }
};
__global__ void tamper_word(uint32_t *word, uint32_t value) { *word = value; }
static void equal(const char *label, const std::vector<uint32_t> &a,
                  const std::vector<uint32_t> &b) {
  if (a == b)
    return;
  for (size_t i = 0; i < std::min(a.size(), b.size()); ++i)
    if (a[i] != b[i]) {
      std::fprintf(stderr, "%s index=%zu got=%u want=%u\n", label, i, a[i],
                   b[i]);
      break;
    }
  throw std::runtime_error(label);
}
static void exercise(const std::string &path, uint32_t fault) {
  Reader f(path);
  const auto h = f.take(10);
  if (h[0] != 0x52564450 || h[1] != 1)
    throw std::runtime_error("fixture version");
  const uint32_t gc = h[2], sc = h[3], tc = h[4], log = h[5], rows = 1u << log;
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
  const auto src = upload(sources), term = upload(terms), grp = upload(groups),
             input = upload(tree), pts = upload(points), vals = upload(values),
             random = upload(alpha), xy = upload(domain);
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
    equal("line weights", o.read(weights), expected_weights);
    equal("group line", o.read(linear), expected_linear);
    equal("compact aggregate", o.read(coeff), expected_coefficients);
    equal("aggregate LDE", o.read(eval), expected_evaluations);
    std::vector<uint32_t> packed;
    for (uint32_t c = 0; c < 8; ++c)
      packed.insert(packed.end(), actual.begin() + uint64_t(c) * (rows + 3),
                    actual.begin() + uint64_t(c) * (rows + 3) + rows);
    equal("native OM31 DEEP", packed, expected);
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
    for (uint32_t i = 0; i < 4; ++i)
      exercise(std::string(argv[1]) + "/case-" + std::to_string(i) + ".bin", 0);
    for (uint32_t fault = 1; fault <= 19; ++fault)
      exercise(std::string(argv[1]) + "/case-1.bin", fault);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "DEEP FAIL: %s\n", e.what());
    return 1;
  }
}
