// Native tuple projections -> warp-batched inverse -> centered global prefix.
// This produces interaction witnesses, not an accepting execution proof.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "global_launches.h"
#include "rv64/global.h"
#include <algorithm>
#include <cstring>
__global__ void global_tamper(uint32_t *p, uint32_t v) { *p = v; }
static uint64_t scan_words(uint32_t rows) {
  uint64_t words = 0;
  while (rows > 1) {
    rows = (rows + 127) / 128;
    words += uint64_t(rows) * 8;
  }
  return words;
}
static void exercise(const std::string &directory, uint32_t id,
                     uint32_t fault) {
  FixtureWords f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(12);
  if (h[0] != 0x52564750 || h[1] != 1 || h[2] != id)
    throw std::runtime_error("global fixture header");
  const uint32_t log = h[3], rows = 1u << log, rp = h[8], op = h[9],
                 width = h[10], stride = h[11];
  const auto offsets = f.take(2 * h[6]), fixed = f.take(h[4] * rows),
             main = f.take(h[5] * rows), params = f.take(h[7] * 8);
  const auto expected = f.take(width * rows), claims = f.take((op ? 2 : 1) * 8);
  if (f.position != f.data.size())
    throw std::runtime_error("global fixture trailing words");
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &v) {
    auto p = o.plane(std::max<size_t>(v.size(), 1), 1);
    o.upload(p, v.empty() ? std::vector<uint32_t>{0} : v);
    return p;
  };
  const auto tf = upload(fixed), tm = upload(main), off = upload(offsets),
             par = upload(params);
  auto output = o.plane(width * stride, 1),
       contributions = o.plane((rp + op) * 8 * stride, 1);
  const auto scratch = o.plane(scan_words(rows), 1),
             claim = o.plane(op ? 16 : 8, 1), status = o.plane(1, 1);
  o.upload(output, std::vector<uint32_t>(width * stride, 0x1234567u));
  o.upload(contributions,
           std::vector<uint32_t>((rp + op) * 8 * stride, 0x1234567u));
  o.upload(status, {fault == 4 ? 0x80000000u : 0u});
  CHECK(stwo_exec_context_sync(o.ctx));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 0, &raw));
  const auto stream = reinterpret_cast<cudaStream_t>(raw);
  const uint32_t *t0 = tf.words, *t1 = tm.words, *parameters = par.words;
  const auto *column_offsets = reinterpret_cast<const uint64_t *>(off.words);
  uint32_t *n = contributions.words, *d = output.words, *verdict = status.words;
  uint64_t native_stride = stride;
  void *arguments[] = {
      &t0,     &t1, &column_offsets, &parameters,
      &n,      &d,  &native_stride,  const_cast<uint32_t *>(&rows),
      &verdict};
  auto begin = o.event(), end = o.event();
  CHECK(cudaEventRecord(begin, stream));
  CHECK(cudaLaunchKernel(global_kernels[id], dim3((rows + 127) / 128, rp + op),
                         dim3(128), arguments, 0, stream));
  if (fault == 1)
    global_tamper<<<1, 1, 0, stream>>>(output.words, 0);
  // A pole is an all-zero OM31 denominator, including zero-weight rows.
  if (fault == 1)
    for (uint32_t c = 1; c < 8; ++c)
      global_tamper<<<1, 1, 0, stream>>>(output.words + uint64_t(c) * stride,
                                         0);
  if (fault == 2)
    global_tamper<<<1, 1, 0, stream>>>(contributions.words, 0x7fffffffu);
  if (fault == 3)
    global_tamper<<<1, 1, 0, stream>>>(output.words, 0x7fffffffu);
  StwoRv64GlobalPairs job{output.words,
                          contributions.words,
                          scratch.words,
                          claim.words,
                          status.words,
                          stride,
                          scan_words(rows),
                          log,
                          rp,
                          {0, 0}};
  CHECK(stwo_rv64_global_pairs_on(o.ctx, 0, &job));
  if (op) {
    job.output = output.words + uint64_t(rp + 1) * 8 * stride;
    job.contributions = contributions.words + uint64_t(rp) * 8 * stride;
    job.claim = claim.words + 8;
    job.pairs = op;
    CHECK(stwo_rv64_global_pairs_on(o.ctx, 0, &job));
  }
  CHECK(cudaEventRecord(end, stream));
  CHECK(cudaEventSynchronize(end));
  const auto verdict_words = o.read(status);
  if (fault) {
    if (!verdict_words[0])
      throw std::runtime_error("invalid global witness accepted");
    o.close();
    return;
  }
  if (verdict_words[0])
    throw std::runtime_error("honest global witness rejected");
  const auto actual = o.read(output), actual_claim = o.read(claim),
             actual_contributions = o.read(contributions);
  if (actual_claim != claims)
    throw std::runtime_error("native global claim mismatch");
  for (uint32_t c = 0; c < width; ++c) {
    for (uint32_t r = 0; r < rows; ++r)
      if (actual[uint64_t(c) * stride + r] !=
          expected[uint64_t(c) * rows + r]) {
        std::fprintf(stderr, "case=%u column=%u row=%u got=%u want=%u\n", id, c,
                     r, actual[uint64_t(c) * stride + r],
                     expected[uint64_t(c) * rows + r]);
        throw std::runtime_error("native global interaction mismatch");
      }
    for (uint32_t r = rows; r < stride; ++r)
      if (actual[uint64_t(c) * stride + r] != 0x1234567u)
        throw std::runtime_error("global output padding overwritten");
  }
  for (uint32_t c = 0; c < (rp + op) * 8; ++c)
    for (uint32_t r = rows; r < stride; ++r)
      if (actual_contributions[uint64_t(c) * stride + r] != 0x1234567u)
        throw std::runtime_error("global contribution padding overwritten");
  // All preflight failures must reject before a kernel launch.
  auto bad = job;
  bad.scan_words = 0;
  if (!stwo_rv64_global_pairs_on(o.ctx, 0, &bad))
    throw std::runtime_error("short scan accepted");
  bad = job;
  bad.contributions = bad.output;
  if (!stwo_rv64_global_pairs_on(o.ctx, 0, &bad))
    throw std::runtime_error("aliased output accepted");
  bad = job;
  bad.row_log = 4;
  if (!stwo_rv64_global_pairs_on(o.ctx, 0, &bad))
    throw std::runtime_error("partial warp accepted");
  bad = job;
  bad.pairs = 30;
  if (!stwo_rv64_global_pairs_on(o.ctx, 0, &bad))
    throw std::runtime_error("pair cap accepted");
  bad = job;
  bad.reserved[0] = 1;
  if (!stwo_rv64_global_pairs_on(o.ctx, 0, &bad))
    throw std::runtime_error("reserved accepted");
  Owner other(0);
  auto foreign = other.plane(8, 1);
  bad = job;
  bad.claim = foreign.words;
  if (!stwo_rv64_global_pairs_on(o.ctx, 0, &bad))
    throw std::runtime_error("foreign context accepted");
  other.close();
  float ms = 0;
  CHECK(cudaEventElapsedTime(&ms, begin, end));
  std::printf("GLOBAL case=%u rows=%u ram_pairs=%u other_pairs=%u ms=%.6f "
              "bytes=%llu native_exact=true\n",
              id, rows, rp, op, ms,
              static_cast<unsigned long long>(o.allocated_bytes));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected fixture directory");
    for (uint32_t id = 0; id < global_case_count; ++id)
      exercise(argv[1], id, 0);
    for (uint32_t fault = 1; fault <= 4; ++fault)
      exercise(argv[1], global_case_count - 1, fault);
    std::printf(
        "PASS global native projections/interactions cases=%u mutants=4\n",
        global_case_count);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
