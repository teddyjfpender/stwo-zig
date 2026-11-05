// Source-column projection with real device-derived native OM31 challenges.
// Expected fractions are only read after all channel/gather/projection work.
#include "context_owner.cuh"
#include "fixture_reader.h"
#include "launches.h"
#include "projection_fixture.h"
#include "rv64/channel.h"
#include "rv64/parameters.h"
#include <algorithm>
using rv64_fixture::equal;
using rv64_fixture::Fixture;
__global__ void corrupt_projection_word(uint32_t *out, uint32_t value) {
  *out = value;
}
static void exercise(const std::string &directory, uint32_t id,
                     uint32_t attack = 0) {
  Fixture f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(10);
  if (h[0] != 0x5256504a || h[1] != 1 || h[2] != id || h[3] != 5 || !h[6] ||
      h[7] < h[6] || h[7] > 256 || !h[9] || h[9] > 310)
    throw std::runtime_error("bad source projection header");
  const uint32_t rows = 1u << h[3], facts = rows * h[7];
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &words) {
    const auto p = o.plane(std::max(size_t(1), words.size()), 1);
    if (!words.empty())
      o.upload(p, words);
    return p;
  };
  const auto seed = upload(f.take(9));
  const auto expected_channel = f.take(9);
  const auto fixed = upload(f.take(rows * h[4]));
  const auto main = upload(f.take(rows * h[5]));
  const auto public_values = upload(f.take(291));
  const auto offsets = upload(f.take(2 * h[8]));
  const auto slots = f.take(h[9]);
  const auto expected_n = f.take(facts), expected_d = f.take(8 * facts);
  if (f.cursor != f.data.size())
    throw std::runtime_error("trailing source fixture");
  const auto channel = o.plane(16, 1), boundary = o.plane(16, 1),
             reservoir = o.plane(310 * 8, 1), parameters = o.plane(h[9] * 8, 1),
             n = o.plane(facts, 1), d = o.plane(facts, 8), status = upload({0});
  // Unused reservoir slots are fixed zeros, never host-computed FS values.
  o.upload(reservoir, std::vector<uint32_t>(310 * 8, 0));
  const uint32_t arities[10] = {6, 30, 13, 19, 1, 1, 3, 6, 5, 4};
  std::vector<uint32_t> metadata{0x4c474b33, 8, 10};
  for (uint32_t r = 0; r < 10; ++r) {
    metadata.push_back(r);
    metadata.push_back(arities[r]);
  }
  const auto constants = upload(metadata);
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  void *stream = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &stream));
  uint32_t step = 0;
  uint64_t chain = 0x8643;
  CHECK(stwo_rv64_channel_init_on(o.ctx, 1, channel.words, seed.words, chain));
  CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, channel.words, step++, chain,
                                 chain + 1, constants.words, 3, 0,
                                 boundary.words));
  ++chain;
  for (uint32_t r = 0; r < 10; ++r) {
    CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, channel.words, step++, chain,
                                   chain + 1, constants.words + 3 + 2 * r, 2, 0,
                                   boundary.words));
    ++chain;
    const uint32_t draws = 1 + (r == 5 ? 0 : arities[r]);
    CHECK(stwo_rv64_channel_draw_on(
        o.ctx, 1, channel.words, step++, chain, chain + 1, draws,
        reservoir.words + r * 31 * 8, boundary.words));
    ++chain;
  }
  if (attack == 3)
    CHECK(cudaMemsetAsync(reservoir.words, 0, 310 * 8 * 4,
                          reinterpret_cast<cudaStream_t>(stream)));
  if (attack == 4)
    corrupt_projection_word<<<1, 1, 0,
                              reinterpret_cast<cudaStream_t>(stream)>>>(
        reservoir.words, 2147483647);
  const uint32_t invalid_slots[] = {9 * 31 + 5};
  if (stwo_rv64_parameter_gather_on(o.ctx, 1, reservoir.words, parameters.words,
                                    invalid_slots, 1, 10,
                                    status.words) != int(cudaErrorInvalidValue))
    throw std::runtime_error("invalid semantic slot accepted");
  const uint32_t unsupported_literal_slot[] = {5 * 31 + 1};
  if (stwo_rv64_parameter_gather_on(o.ctx, 1, reservoir.words, parameters.words,
                                    unsupported_literal_slot, 1, 10,
                                    status.words) != int(cudaErrorInvalidValue))
    throw std::runtime_error("range8 literal became a draw slot");
  CHECK(stwo_rv64_parameter_gather_on(o.ctx, 1, reservoir.words,
                                      parameters.words, slots.data(), h[9], 10,
                                      status.words));
  if (attack == 1)
    corrupt_projection_word<<<1, 1, 0,
                              reinterpret_cast<cudaStream_t>(stream)>>>(
        public_values.words, 2147483647);
  if (attack == 2)
    corrupt_projection_word<<<1, 1, 0,
                              reinterpret_cast<cudaStream_t>(stream)>>>(
        main.words, 2147483647);
  Rv64ProjectionFixture packet{
      fixed.words,
      main.words,
      public_values.words,
      reinterpret_cast<const uint64_t *>(offsets.words),
      parameters.words,
      n.words,
      d.words,
      status.words,
      h[3],
      0,
      rows / 2};
  CHECK(projection_launches[id](stream, &packet));
  packet.first = rows / 2;
  packet.rows = rows - packet.first;
  CHECK(projection_launches[id](stream, &packet));
  const auto transcript = o.read(channel);
  if (transcript[9] != step || transcript[10] || transcript[11])
    throw std::runtime_error("source channel framing");
  equal({transcript.begin(), transcript.begin() + 9}, expected_channel,
        "source checkpoint", id);
  if (attack) {
    if (!o.read(status)[0])
      throw std::runtime_error("source mutation silently accepted");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
    return;
  }
  if (o.read(status)[0])
    throw std::runtime_error("source canonicality/pole verdict");
  equal(o.read(n), expected_n, "source numerators", id);
  equal(o.read(d), expected_d, "source denominators", id);
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected source projection fixture directory");
    for (uint32_t id = 0; id < projection_case_count; ++id)
      exercise(argv[1], id);
    for (uint32_t attack = 1; attack <= 4; ++attack)
      exercise(argv[1], 0, attack);
    std::printf(
        "{\"schema\":\"rv64-source-projection-gpu/"
        "v1\",\"cases\":%u,\"poison_cases\":4,\"invalid_slot_rejections_per_"
        "case\":2,\"native_raw_tuple_parity\":true,\"device_"
        "challenges\":true,\"numeric_feedback_bytes\":0,\"physical_pcs_"
        "binding\":false,\"full_block_verified\":false}\n",
        projection_case_count);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
