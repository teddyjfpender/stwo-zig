#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/closure.h"
static void exercise(const std::string &directory, uint32_t id,
                     uint32_t fault = 0) {
  FixtureWords f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(7);
  if (h[0] != 0x5256434c || h[1] != 1 || h[2] != id || h[3] > 1)
    throw std::runtime_error("closure fixture header");
  const uint32_t mode = h[3], count = h[4];
  uint32_t expected = h[6];
  auto values = f.take(uint64_t(count) * (mode ? 24 : 16));
  auto masks = mode ? f.take(count) : std::vector<uint32_t>{0};
  if (f.position != f.data.size())
    throw std::runtime_error("closure fixture trailing words");
  if (fault == 1 || fault == 2) {
    values[0] = 0x7fffffffu;
    expected |= 2;
  }
  if (fault == 3) {
    masks[0] = 8;
    expected |= 256;
  }
  if (fault == 4) {
    std::fill(values.begin() + 8, values.begin() + 16, 0);
    expected |= 4;
  }
  Owner o(0);
  auto source = o.plane(values.size(), 1), relations = o.plane(masks.size(), 1),
       status = o.plane(1, 1);
  o.upload(source, values);
  o.upload(relations, masks);
  o.upload(status, {h[5]});
  CHECK(stwo_exec_context_sync(o.ctx));
  if (mode)
    CHECK(stwo_rv64_global_close_on(o.ctx, 1, source.words, relations.words,
                                    count, status.words));
  else
    CHECK(
        stwo_rv64_local_close_on(o.ctx, 1, source.words, count, status.words));
  const auto result = o.read(status);
  if (result[0] != expected) {
    std::fprintf(stderr, "id=%u fault=%u got=%u expected=%u\n", id, fault,
                 result[0], expected);
    throw std::runtime_error("closure differs from native policy");
  }
  if (!stwo_rv64_local_close_on(o.ctx, 1, source.words, 0, status.words))
    throw std::runtime_error("empty roots accepted");
  if (!stwo_rv64_local_close_on(o.ctx, 1, source.words, 65, status.words))
    throw std::runtime_error("root cap accepted");
  if (!stwo_rv64_local_close_on(o.ctx, 1, source.words, 1, source.words))
    throw std::runtime_error("root alias accepted");
  if (!stwo_rv64_global_close_on(o.ctx, 1, source.words, relations.words, 0,
                                 status.words))
    throw std::runtime_error("empty workers accepted");
  if (!stwo_rv64_global_close_on(o.ctx, 1, source.words, relations.words, 65536,
                                 status.words))
    throw std::runtime_error("worker cap accepted");
  if (!stwo_rv64_global_close_on(o.ctx, 1, source.words, relations.words, count,
                                 relations.words))
    throw std::runtime_error("mask alias accepted");
  Owner other(0);
  auto foreign = other.plane(1, 1);
  if (!stwo_rv64_local_close_on(o.ctx, 1, source.words, 1, foreign.words))
    throw std::runtime_error("foreign status accepted");
  other.close();
  std::printf("CLOSURE case=%u mode=%u count=%u fault=%u verdict=%u "
              "native_exact=true\n",
              id, mode, count, fault, result[0]);
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected closure fixture directory");
    for (uint32_t id = 0; id < 15; ++id)
      exercise(argv[1], id);
    exercise(argv[1], 0, 1);
    exercise(argv[1], 7, 2);
    exercise(argv[1], 7, 3);
    exercise(argv[1], 0, 4);
    std::puts("PASS native closure fixtures=15 framing_mutants=4");
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
