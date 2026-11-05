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
static void exercise_auxiliary() {
  for(uint32_t log : {5u,8u}) {
    const uint32_t n=1u<<log;
    Owner o(0); const auto hc=o.plane(16*log,1), out=o.plane(10*n,1);
    std::vector<uint32_t> metadata(16*log), expected(10*n);
    for(uint32_t i=0;i<metadata.size();++i) metadata[i]=i*151+3;
    for(uint32_t row=0;row<n;++row) {
      const uint32_t half=row&1, bits=half?row:((n-1)^row);
      const uint32_t carry=__builtin_clz(bits)-(32-log);
      expected[row]=row==0; expected[n+row]=row+1==n;
      for(uint32_t c=0;c<8;++c) expected[(c+2)*n+row]=metadata[(half*log+carry)*8+c];
    }
    o.upload(hc,metadata); StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx,0,0,&ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx,1,&ready));
    uint32_t launches=0;
    CHECK(stwo_rv64_composition_auxiliary_on(o.ctx,1,hc.words,out.words,log,&launches));
    if(launches!=1) throw std::runtime_error("auxiliary launch receipt");
    fixture_equal("IR ordered public auxiliary",o.read(out),expected);
    CHECK(stwo_exec_context_dependency_release(o.ctx,&ready));o.close();
  }
}
static void exercise_lift() {
  for (uint32_t source_log : {3u, 5u, 7u})
    for (uint32_t target_log : {7u, 9u}) {
      const uint32_t src_rows = 1u << source_log, dst_rows = 1u << target_log;
      Owner o(0);
      const auto input = o.plane(uint64_t(8) * src_rows, 1),
                 output = o.plane(uint64_t(8) * dst_rows, 1);
      std::vector<uint32_t> src(8 * src_rows), dst(8 * dst_rows), expected(dst.size());
      for (size_t i = 0; i < src.size(); ++i) src[i] = uint32_t(i * 73) % 2147483647u;
      for (size_t i = 0; i < dst.size(); ++i) dst[i] = 2147483646u - uint32_t(i);
      for (uint32_t c = 0; c < 8; ++c)
        for (uint32_t row = 0; row < dst_rows; ++row) {
          const uint32_t index = ((row >> (target_log - source_log + 1)) << 1) | (row & 1);
          const uint64_t value = uint64_t(dst[c * dst_rows + row]) + src[c * src_rows + index];
          expected[c * dst_rows + row] = value % 2147483647u;
        }
      o.upload(input, src); o.upload(output, dst);
      StwoCudaDependency ready{};
      CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
      CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
      uint32_t launches = 99;
      if (!stwo_rv64_composition_lift_add_on(o.ctx, 1, input.words, source_log,
                                               input.words, target_log, &launches) || launches)
        throw std::runtime_error("lift alias admitted");
      CHECK(stwo_rv64_composition_lift_add_on(o.ctx, 1, input.words, source_log,
                                             output.words, target_log, &launches));
      if (launches != 1) throw std::runtime_error("lift launch receipt");
      fixture_equal("native lifted accumulator", o.read(output), expected);
      CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
      o.close();
    }
}
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
    const auto accumulator = o.plane(words, 1);
    const StwoRv64CompositionBucket bucket{input.words,h[3],0};
    CHECK(stwo_rv64_composition_finish_on(o.ctx, 1, &bucket, 1, accumulator.words,
                                          output.words, h[3], h[4], twiddles.words,
                                          h[6], &launches));
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
    exercise_lift();
    exercise_auxiliary();
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
