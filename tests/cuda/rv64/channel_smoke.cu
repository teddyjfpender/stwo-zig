#include "channel_reference.h"
#include "context_owner.cuh"
#include "rv64/channel.h"
#include <algorithm>
#include <array>
using rv64_channel_reference::Channel;
constexpr uint32_t guard = 0xcafef00du;
static void demand(bool valid, const char *label) {
  if (!valid)
    throw std::runtime_error(label);
}
static void check_state(const std::vector<uint32_t> &state,
                        const Channel &expected, uint32_t step, uint64_t chain,
                        uint32_t status = 0) {
  demand(
      std::equal(expected.digest.begin(), expected.digest.end(), state.begin()),
      "digest");
  demand(state[8] == expected.draws && state[9] == step &&
             state[10] == status && state[11] == 0 &&
             state[12] == uint32_t(chain) &&
             state[13] == uint32_t(chain >> 32) && state[14] == 0 &&
             state[15] == 0,
         "channel checkpoint");
  for (size_t i = 16; i < state.size(); ++i)
    demand(state[i] == guard, "state canary");
}
static void exercise(uint32_t words, uint32_t draws) {
  Owner o(0);
  const auto state = o.plane(19, 1), seed = o.plane(9, 1),
             input = o.plane(words + 1, 1), output = o.plane(8 * draws + 3, 1),
             boundary = o.plane(16 * 4, 1);
  std::vector<uint32_t> sw(9), data(words + 1), initial(19, guard),
      out(8 * draws + 3, guard);
  for (uint32_t i = 0; i < 8; ++i)
    sw[i] = 0xfedcba98u + 0x01234567u * i;
  sw[8] = 7;
  for (uint32_t i = 0; i < words; ++i)
    data[i] = 1664525u * i + 1013904223u;
  o.upload(state, initial);
  o.upload(seed, sw);
  o.upload(input, data);
  o.upload(output, out);
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  // Invalid descriptors are rejected before any channel mutation.
  demand(stwo_rv64_channel_init_on(o.ctx, 1, state.words + 1, seed.words, 3) ==
             int(cudaErrorInvalidValue),
         "alignment admitted");
  demand(stwo_rv64_channel_init_on(o.ctx, 1, state.words, state.words, 3) ==
             int(cudaErrorInvalidValue),
         "seed alias admitted");
  demand(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 0, 3, 4, 1,
                                   state.words, boundary.words) ==
             int(cudaErrorInvalidValue),
         "output alias admitted");
  demand(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 0, 3, 4, 0,
                                   output.words, boundary.words) ==
             int(cudaErrorInvalidValue),
         "zero draws admitted");
  CHECK(stwo_rv64_channel_init_on(o.ctx, 1, state.words, seed.words,
                                  0x0123456789abcdefull));
  CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, 0,
                                 0x0123456789abcdefull, 14, input.words, words,
                                 0, boundary.words));
  CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 1, 14, 15, draws,
                                  output.words, boundary.words + 16));
  // Empty absorption hashes digest alone and resets draws; it is not a no-op.
  CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, 2, 15, 16, nullptr, 0,
                                 1, boundary.words + 32));
  CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 3, 16, 17, 1,
                                  output.words, boundary.words + 48));
  Channel reference(sw.data());
  reference.mix(data.data(), words);
  auto boundaries = o.read(boundary);
  check_state({boundaries.begin(), boundaries.begin() + 16}, reference, 1, 14);
  for (uint32_t i = 0; i < draws; ++i) {
    const auto v = reference.draw();
    if (i)
      std::copy(v.begin(), v.end(), out.begin() + 8 * i);
  }
  check_state({boundaries.begin() + 16, boundaries.begin() + 32}, reference, 2,
              15);
  reference.mix(nullptr, 0);
  check_state({boundaries.begin() + 32, boundaries.begin() + 48}, reference, 3,
              16);
  const auto final = reference.draw();
  std::copy(final.begin(), final.end(), out.begin());
  check_state(o.read(state), reference, 4, 17);
  demand(o.read(output) == out, "OM31 challenge mismatch or output canary");
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
static void poison(uint32_t attack) {
  Owner o(0);
  const auto state = o.plane(16, 1), seed = o.plane(9, 1),
             input = o.plane(1, 1), output = o.plane(8, 1),
             boundary = o.plane(32, 1);
  std::vector<uint32_t> sw(9, 0), data{2147483647u}, out(8, guard);
  if (attack == 3)
    sw[8] = (1u << 20) + 1;
  o.upload(seed, sw);
  o.upload(input, data);
  o.upload(output, out);
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  CHECK(stwo_rv64_channel_init_on(o.ctx, 1, state.words, seed.words, 71));
  CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, attack == 1 ? 1 : 0,
                                 attack == 2 ? 72 : 71, 73, input.words, 1, 1,
                                 boundary.words));
  CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, 0, 71, 74, 1,
                                  output.words, boundary.words + 16));
  const auto got = o.read(output);
  demand(got == std::vector<uint32_t>(8, 0),
         "poison published a stale challenge");
  Channel unchanged(sw.data());
  check_state(o.read(state), unchanged, 0, 71,
              attack == 0   ? 4
              : attack == 3 ? 5
                            : 1);
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main() {
  try {
    uint32_t cases = 0;
    for (uint32_t n : {0u, 1u, 7u, 8u, 9u, 15u, 16u, 17u, 31u, 32u, 33u, 63u,
                       64u, 65u, 1024u, 16384u})
      for (uint32_t draws : {1u, 2u, 3u, 9u, 257u, 1024u}) {
        exercise(n, draws);
        ++cases;
      }
    for (uint32_t i = 0; i < 4; ++i) {
      poison(i);
      ++cases;
    }
    std::printf("{\"schema\":\"rv64-om31-channel-v1\",\"cases\":%u,\"device_"
                "feedback\":true,\"full_block_verified\":false}\n",
                cases);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
