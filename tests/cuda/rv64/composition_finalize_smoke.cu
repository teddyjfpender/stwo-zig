#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/composition_finalize.h"
#include <filesystem>
using RawSplit = int (*)(uint32_t *, size_t, size_t, uint32_t *, size_t, size_t,
                         uint32_t, const uint32_t *, uint32_t, uint32_t, void *,
                         uint32_t *);
extern "C" int stwo_ntt_b2n_composition_split_compact_on(
    uint32_t *, size_t, size_t, uint32_t *, size_t, size_t, uint32_t,
    const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
extern "C" int stwo_ntt_b2n_composition_split_depth_two_on(
    uint32_t *, size_t, size_t, uint32_t *, size_t, size_t, uint32_t,
    const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
static void exercise(const std::string &path) {
  FixtureWords f(path);
  const auto h = f.take(8);
  if (h[0] != 0x52565350 || h[1] != 1 || h[3] < 3 || h[3] > 20 || h[4] < 1 ||
      h[4] > 2 || (h[5] != 4 && h[5] != 8) || h[7])
    throw std::runtime_error("split fixture shape");
  const uint32_t n = 1u << h[3], words = n * h[5];
  Owner o(0);
  const auto input = o.plane(words, 1), output = o.plane(words, 1),
             twiddles = o.plane(h[6], 1);
  o.upload(input, f.take(words));
  o.upload(twiddles, f.take(h[6]));
  const auto expected = f.take(words);
  if (f.position != f.data.size())
    throw std::runtime_error("trailing fixture");
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  void *stream = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &stream));
  uint32_t launches = 0;
  if (h[5] == 8) {
    if (!stwo_rv64_composition_finalize_on(o.ctx, 1, input.words, input.words,
                                           h[3], h[4], twiddles.words, h[6],
                                           &launches) ||
        launches)
      throw std::runtime_error("split alias admitted");
    Owner other(0);
    const auto foreign = other.plane(words, 1);
    if (!stwo_rv64_composition_finalize_on(o.ctx, 1, input.words, foreign.words,
                                           h[3], h[4], twiddles.words, h[6],
                                           &launches) ||
        launches)
      throw std::runtime_error("split foreign owner admitted");
    other.close();
    CHECK(stwo_rv64_composition_finalize_on(o.ctx, 1, input.words, output.words,
                                            h[3], h[4], twiddles.words, h[6],
                                            &launches));
  } else {
    RawSplit split = h[4] == 1 ? stwo_ntt_b2n_composition_split_compact_on
                               : stwo_ntt_b2n_composition_split_depth_two_on;
    CHECK(split(input.words, words, n, output.words, words, n >> h[4], h[3],
                twiddles.words, h[6], n / 2, stream, &launches));
  }
  if (!launches)
    throw std::runtime_error("missing split launch receipt");
  fixture_equal("native composition coefficients", o.read(output), expected);
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected split fixtures");
    uint32_t count = 0;
    for (const auto &file : std::filesystem::directory_iterator(argv[1]))
      if (file.path().extension() == ".bin") {
        exercise(file.path());
        ++count;
      }
    if (count != 14)
      throw std::runtime_error("incomplete split inventory");
    std::printf("PASS composition finalize cases=%u native_coefficients=true "
                "qm31_regression=true\n",
                count);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
