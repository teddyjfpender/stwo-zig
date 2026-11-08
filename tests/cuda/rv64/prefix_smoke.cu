// Independent sequential host oracle for logical-coset GPU prefix scans.
#include "context_owner.cuh"
#include "rv64/binding.h"
#include <algorithm>
static constexpr uint32_t prime = 0x7fffffffu;
static uint32_t plus_mod(uint32_t a, uint32_t b) {
  const uint64_t sum = uint64_t(a) + b;
  return uint32_t(sum >= prime ? sum - prime : sum);
}
static uint32_t minus_mod(uint32_t a, uint32_t b) {
  return uint32_t((uint64_t(a) + prime - b) % prime);
}
static uint32_t physical_reference(uint32_t logical, uint32_t log) {
  const uint32_t circle =
      logical % 2 == 0 ? logical / 2 : (2u * (1u << log) - logical) / 2;
  uint32_t result = 0;
  for (uint32_t bit = 0; bit < log; ++bit)
    result |= ((circle >> bit) & 1u) << (log - bit - 1);
  return result;
}
static void exercise(uint32_t log, bool center, uint32_t fault = 0) {
  const uint32_t rows = 1u << log, stride = rows + 5;
  std::vector<uint32_t> permutation(rows);
  for (uint32_t i = 0; i < rows; ++i)
    permutation[i] = physical_reference(i, log);
  std::vector<uint32_t> source(uint64_t(stride) * 8, 0xcafef00du), totals(8, 0);
  for (uint32_t c = 0; c < 8; ++c) {
    for (uint32_t p = 0; p < rows; ++p) {
      const uint32_t value = uint32_t((uint64_t(p) * 17 + c * 731 + 7) % prime);
      source[uint64_t(c) * stride + p] = value;
      totals[c] = plus_mod(totals[c], value);
    }
    if (!center && fault != 1) {
      auto &last = source[uint64_t(c) * stride + permutation.back()];
      last = minus_mod(last, totals[c]);
    }
  }
  if (fault == 2)
    source[0] = prime;
  auto expected = source;
  std::vector<uint32_t> expected_claim(16, 0xdeadbeefu);
  for (uint32_t c = 0; c < 8; ++c) {
    uint32_t sum = 0;
    for (uint32_t logical = 0; logical < rows; ++logical) {
      const size_t index = uint64_t(c) * stride + permutation[logical];
      sum = plus_mod(sum, source[index] < prime ? source[index] : 0);
      expected[index] = sum;
    }
    expected_claim[c] = sum;
    if (center)
      for (uint32_t p = 0; p < rows; ++p)
        expected[uint64_t(c) * stride + p] =
            minus_mod(expected[uint64_t(c) * stride + p], sum);
  }
  uint64_t scratch_words = 0;
  for (uint32_t n = rows; n > 1;) {
    n = (n + 127) / 128;
    scratch_words += uint64_t(n) * 8;
  }
  Owner o(0);
  const auto data = o.plane(stride, 8), scratch = o.plane(scratch_words + 8, 1),
             claim = o.plane(16, 1), status = o.plane(1, 1);
  o.upload(data, source);
  o.upload(scratch, std::vector<uint32_t>(scratch_words + 8, 0xdeadbeefu));
  o.upload(claim, std::vector<uint32_t>(16, 0xdeadbeefu));
  o.upload(status, {fault == 3 ? 0x20u : 0u});
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  StwoRv64PrefixScan job{
      data,         scratch.words, scratch_words,    claim.words,
      status.words, log,           uint32_t(center), {0, 0}};
  auto invalid = job;
  invalid.scratch_words -= 1;
  if (!stwo_rv64_prefix_scan_on(o.ctx, 1, &invalid))
    throw std::runtime_error("undersized scratch accepted");
  invalid = job;
  invalid.claim = data.words;
  if (!stwo_rv64_prefix_scan_on(o.ctx, 1, &invalid))
    throw std::runtime_error("scan output alias accepted");
  CHECK(stwo_rv64_prefix_scan_on(o.ctx, 1, &job));
  if (o.read(data) != expected)
    throw std::runtime_error(
        "prefix or padding differs from sequential oracle");
  if (o.read(claim) != expected_claim)
    throw std::runtime_error("prefix claim or guard differs");
  const auto got_scratch = o.read(scratch);
  for (size_t i = scratch_words; i < got_scratch.size(); ++i)
    if (got_scratch[i] != 0xdeadbeefu)
      throw std::runtime_error("prefix scratch guard");
  uint32_t verdict = fault == 2 ? 2 : fault == 3 ? 0x20 : 0;
  if (!center && std::any_of(expected_claim.begin(), expected_claim.begin() + 8,
                             [](uint32_t x) { return x != 0; }))
    verdict |= 8;
  if (o.read(status)[0] != verdict)
    throw std::runtime_error("prefix debt verdict differs");
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main() {
  try {
    for (uint32_t log : {1u, 5u, 7u, 8u, 14u, 18u, 22u}) {
      exercise(log, false);
      exercise(log, true);
    }
    exercise(8, false, 1);
    exercise(8, true, 2);
    exercise(8, true, 3);
    std::printf(
        "PREFIX_SCAN cases=17 max_log=22 native_sequential_parity=PASS\n");
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
}
