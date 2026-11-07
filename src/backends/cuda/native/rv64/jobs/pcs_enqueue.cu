// Enqueue-only native OM31 PCS (M8 job runtime). See jobs/pcs_enqueue.h.
//
// The body of enqueue() below is rv64_pcs_pipeline::run (pcs_pipeline.cuh:157)
// with exactly these edits, so the transcript and every proof word are
// unchanged by construction:
//   * lane: every *_on(ctx, 1, ...) launch uses the caller's lane; the stream
//     is that lane's stream from the start (the :452 join is gone because
//     ingress, allocation and compute are on one stream);
//   * the :718 join is gone: late allocations come from the stream-ordered job
//     arena, so they are ready in stream order;
//   * retirement is a stream-ordered release (no join);
//   * seed/imported point may be device pointers (Io.seed/Io.point);
//   * the final event sync and D2H readback (:814-857) are replaced by D2D
//     copies into Io.output in the identical Result.words order; the verdict,
//     step and root checks move to the job's finish (hybrid_pcs.decodeWords);
//   * no observer/NVTX/phase-timing diagnostics (the job runtime owns those).
#include "rv64/jobs/pcs_enqueue.h"
#include "rv64/om31.cuh"
#include "rv64/pcs_pipeline.cuh"
#include <string>
extern "C" int stwo_exec_context_validate_allocation(void *, const void *, size_t);
// Newer than the frozen a25 base image: bind weakly, fail closed when selected.
extern "C" int stwo_blake2s_mixed_seeded_eager_compact_on(
    uint32_t, uint32_t, const stwo::cuda::blake2s::MixedSegment *, uint32_t, uint32_t,
    const uint32_t *, uint64_t, uint32_t *, uint64_t, uint32_t *, uint64_t, void *)
    __attribute__((weak));
namespace {
using namespace rv64_pcs_pipeline;
namespace q = stwo::cuda::rv64::q;
thread_local std::string last_error;
struct DomainPoint {
  uint32_t x, y;
};
__device__ DomainPoint domain_add(DomainPoint a, DomainPoint b) {
  return {q::sub(q::mul(a.x, b.x), q::mul(a.y, b.y)),
          q::add(q::mul(a.x, b.y), q::mul(a.y, b.x))};
}
// Same construction as the resident owner's cached domain (pcs_native.cu).
__global__ void job_make_domain(uint32_t *out, uint32_t log, DomainPoint initial,
                                DomainPoint step) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  if (row >= (1u << log))
    return;
  const uint32_t index = __brev(row) >> (32 - log);
  const bool conjugate = index >= (1u << (log - 1));
  uint32_t exponent = index & ((1u << (log - 1)) - 1);
  DomainPoint value = initial;
  while (exponent) {
    if (exponent & 1)
      value = domain_add(value, step);
    step = domain_add(step, step);
    exponent >>= 1;
  }
  out[uint64_t(row) * 2] = value.x;
  out[uint64_t(row) * 2 + 1] = conjugate ? q::sub(0, value.y) : value.y;
}
Input inputFrom(const StwoRv64PcsNativeRequest *request) {
  if (!request || request->version != 1 || request->section_count != 17)
    throw std::runtime_error("native PCS ABI mismatch");
  Input input;
  for (size_t i = 0; i < 17; ++i) {
    const auto s = request->sections[i];
    if (s.count > SIZE_MAX || (s.count && !s.words))
      throw std::runtime_error("invalid native metadata span");
    input.sections[i] = {s.words, size_t(s.count)};
  }
  if (request->coefficient_count > 65536 || !request->coefficients)
    throw std::runtime_error("native coefficient count");
  std::copy(request->scope, request->scope + 8, input.scope.begin());
  for (uint64_t i = 0; i < request->coefficient_count; ++i) {
    const auto c = request->coefficients[i];
    if (c.coefficient_log > 28 || c.count != (uint64_t(1) << c.coefficient_log) ||
        !c.words || c.kind > 1)
      throw std::runtime_error("native coefficient shape");
    input.coefficients.push_back({{c.words, size_t(c.count)}, c.kind, c.context_token, c.generation});
  }
  return input;
}
// Shape validation shared by plan and enqueue (the same checks as run()'s
// prologue), plus the exact output layout and the ingress upper bound.
StwoRv64PcsJobPlan planOf(const Input &input) {
  const auto h = input.sections[0];
  stwo::cuda::rv64::PcsAggregateCounts aggregate{};
  if (!stwo::cuda::rv64::decodePcsCounts(h.data(), h.size(), &aggregate))
    throw std::runtime_error("masked PCS header");
  const uint32_t log = h[4], queries = h[6], sc = h[8], tc = h[9], gc = h[10],
                 sgc = h[11], nt = h[12], sample_count = h[13], layers = h[14];
  if (log > 28 || !nt || nt > 4 || !sc || sc > 65536 || !tc || tc > 65536 ||
      !gc || gc > 1024 || !sgc || sgc > 96 || !sample_count ||
      sample_count > 65536 || !queries || queries > 1024 || layers > 28 ||
      input.coefficients.size() != sc)
    throw std::runtime_error("masked PCS shape");
  const size_t sizes[] = {h.size(), 9, h[21] ? 16u : 0u, size_t(sc) * 4,
                          size_t(tc) * 4, size_t(gc) * 8, size_t(sgc) * 8,
                          size_t(nt) * 6, size_t(gc) * 4, size_t(gc) * 2,
                          sample_count, sc, h[19], size_t(layers) * 8, h[20],
                          size_t(nt) * 8};
  for (size_t i = 0; i < 16; ++i)
    sizeIs(input.sections[i], sizes[i]);
  if (!input.domain.size())
    sizeIs(input.sections[16], 4);
  const auto tree_info = input.sections[7], descriptions = input.sections[13];
  if (pcsCompactEager() && !&stwo_blake2s_mixed_seeded_eager_compact_on)
    throw std::runtime_error("base image lacks compact eager Blake2s");
  StwoRv64PcsJobPlan plan{};
  uint64_t out = 14 + 1 + 16 + uint64_t(nt) * 8 + uint64_t(sample_count) * 8 + 2 + 8 + queries;
  for (uint32_t i = 0; i < layers; ++i) {
    const auto *d = descriptions.data() + i * 8;
    if (!d[0] || (d[0] & (d[0] - 1)) || d[1] < 1 || d[1] > 4 || d[2] > d[1])
      throw std::runtime_error("FRI layer geometry");
    out += 8 + (uint64_t(queries) << d[1]) * 8 +
           (uint64_t(queries) << (d[1] - d[2])) * (uint32_t(__builtin_ctz(d[0])) - d[2]) * 8;
  }
  for (uint32_t t = 0; t < nt; ++t) {
    const auto *d = tree_info.data() + t * 6;
    if (d[5] || d[0] + d[1] > sc || d[2] + d[3] > sgc || d[4] > log)
      throw std::runtime_error("tree geometry");
    out += uint64_t(d[1]) * queries + uint64_t(queries) * d[4] * 8;
  }
  uint64_t host_words = 0;
  for (const auto &c : input.coefficients)
    if (!c.kind) host_words += c.size();
  const char *beta2_flag = std::getenv("STWO_RV64_PCS_ROLLING_BETA2");
  const bool rolling_beta2 = beta2_flag && std::strcmp(beta2_flag, "1") == 0;
  plan.output_words = out;
  plan.ingress_words = 14 + 9 + 16 + 3 + uint64_t(sample_count) + 5ull * sc +
                       4ull * tc + 12ull * gc + h[19] + h[20] + 6ull * sc +
                       48ull * gc + host_words + input.domain.size() +
                       16ull * 24; // per-upload 16-word alignment slack
  plan.ingress_words += 16ull * (uint64_t(sc) + 2ull * gc + sgc + nt);
  plan.trees = nt;
  plan.layers = layers;
  plan.queries = queries;
  plan.steps = (h[21] ? 0 : nt + 1) + 5 + 2 * layers;
  plan.samples = sample_count;
  plan.rolling = h[21] && (h[5] == 1 || (h[5] == 2 && rolling_beta2));
  return plan;
}
struct JobOwner {
  void *ctx;
  uint32_t lane;
  cudaStream_t stream = nullptr;
  const StwoRv64PcsJobMemory &memory;
  const StwoRv64PcsJobIo &io;
  uint64_t pinned_used = 0, allocated_bytes = 0;
  // Same reuse policy as the resident owner (pcs_native.cu ResidentOwner):
  // a retired plane's block returns to a best-fit cache and later planes of
  // this proof reuse it. Legal without a join: every producer and consumer is
  // on this one stream. Blocks go back to the job arena (stream-ordered, in
  // reverse allocation order for its LIFO reclaim) when the enqueue ends.
  struct Block {
    uint32_t *ptr;
    uint64_t words, active;
    bool used;
  };
  std::vector<Block> blocks;
  std::vector<uint32_t *> borrowed;
  uint64_t block_words = 0;
  JobOwner(void *context, uint32_t l, const StwoRv64PcsJobMemory &m, const StwoRv64PcsJobIo &i)
      : ctx(context), lane(l), memory(m), io(i) {
    void *raw = nullptr;
    CHECK(stwo_exec_context_lane_stream(ctx, lane, &raw));
    if (!raw) throw std::runtime_error("missing job lane stream");
    stream = reinterpret_cast<cudaStream_t>(raw);
  }
  JobOwner(const JobOwner &) = delete;
  ~JobOwner() {
    // Stream-ordered: every enqueued reader precedes these releases.
    for (auto b = blocks.rbegin(); b != blocks.rend(); ++b)
      memory.release(memory.user, b->ptr, b->words);
  }
  StwoRv64Plane plane(uint64_t count, uint32_t coordinates) {
    if (!coordinates || !count || count > SIZE_MAX / 4 / coordinates)
      throw std::runtime_error("plane overflow");
    const uint64_t words = count * coordinates;
    size_t selected = blocks.size();
    for (size_t i = 0; i < blocks.size(); ++i)
      if (!blocks[i].used && blocks[i].words >= words &&
          (selected == blocks.size() || blocks[i].words < blocks[selected].words))
        selected = i;
    if (selected == blocks.size()) {
      uint32_t *p = memory.alloc(memory.user, words);
      if (!p) throw std::runtime_error("job arena allocation failed");
      blocks.push_back({p, words, 0, false});
      block_words += words;
    }
    blocks[selected].used = true;
    blocks[selected].active = words;
    allocated_bytes += words * 4;
    return {blocks[selected].ptr, count, coordinates, 0};
  }
  StwoRv64Plane sourcePlane(uint64_t count, uint32_t coordinates) { return plane(count, coordinates); }
  StwoRv64Plane borrow(const uint32_t *p, uint64_t count) {
    if (!p || stwo_exec_context_validate_allocation(ctx, p, count * 4))
      throw std::runtime_error("foreign device input");
    borrowed.push_back(const_cast<uint32_t *>(p));
    return {const_cast<uint32_t *>(p), count, 1, 0};
  }
  void retirePlanes(const std::vector<StwoRv64Plane> &planes) {
    std::vector<size_t> selected;
    for (const auto &p : planes) {
      if (std::find(borrowed.begin(), borrowed.end(), p.words) != borrowed.end()) continue;
      size_t i = 0;
      for (; i < blocks.size() && blocks[i].ptr != p.words; ++i) {}
      if (i == blocks.size() || !blocks[i].used || blocks[i].active != p.stride * p.coordinates ||
          std::find(selected.begin(), selected.end(), i) != selected.end())
        throw std::runtime_error("foreign, duplicate or partial temporary retirement");
      selected.push_back(i);
    }
    for (auto i : selected) {
      blocks[i].used = false;
      blocks[i].active = 0;
    }
  }
  const uint32_t *stage(const uint32_t *data, size_t words) {
    const uint64_t at = (pinned_used + 15) & ~uint64_t(15);
    if (!memory.pinned || at > memory.pinned_words || words > memory.pinned_words - at)
      throw std::runtime_error("pinned ingress exhausted");
    std::memcpy(memory.pinned + at, data, words * 4);
    pinned_used = at + words;
    return memory.pinned + at;
  }
  void uploadBorrowed(StwoRv64Plane destination, const uint32_t *data, size_t words) {
    if (words > destination.stride * destination.coordinates || (words && !data))
      throw std::runtime_error("ingress capacity");
    if (words)
      CHECK(cudaMemcpyAsync(destination.words, stage(data, words), words * 4,
                            cudaMemcpyHostToDevice, stream));
  }
  void upload(StwoRv64Plane destination, const std::vector<uint32_t> &values) {
    uploadBorrowed(destination, values.data(), values.size());
  }
  uint32_t validateCoefficient(Coefficient source, const uint32_t *) const {
    if (!source.kind) {
      if (source.size() && !source.data()) throw std::runtime_error("missing host coefficients");
      return 0;
    }
    if (source.kind != 1) throw std::runtime_error("unsupported device column encoding");
    if (stwo_exec_context_validate_allocation(ctx, source.data(), source.size() * 4))
      throw std::runtime_error("device column is not job storage");
    return 2;
  }
  void uploadCoefficient(StwoRv64Plane destination, Coefficient source, const uint32_t *scope) {
    if (!source.kind) {
      uploadBorrowed(destination, source.data(), source.size());
      return;
    }
    (void)validateCoefficient(source, scope);
    CHECK(cudaMemcpyAsync(destination.words, source.data(), source.size() * 4,
                          cudaMemcpyDeviceToDevice, stream));
  }
  StwoRv64Plane domain(uint32_t log, Words legacy, Words parameters) {
    const uint64_t words = uint64_t(2) << log;
    if (io.domain) return borrow(io.domain, words);
    if (legacy.size()) {
      auto p = plane(legacy.size(), 1);
      uploadBorrowed(p, legacy.data(), legacy.size());
      return p;
    }
    sizeIs(parameters, 4);
    for (auto word : parameters)
      if (word >= 0x7fffffffu) throw std::runtime_error("noncanonical domain setup");
    if (!log) throw std::runtime_error("domain log");
    auto p = plane(words, 1);
    job_make_domain<<<((1u << log) + 127) / 128, 128, 0, stream>>>(
        p.words, log, {parameters[0], parameters[1]}, {parameters[2], parameters[3]});
    CHECK(cudaPeekAtLastError());
    return p;
  }
};
void enqueueBody(JobOwner &o, const Input &input, const StwoRv64PcsJobPlan &job_plan) {
  const auto h = input.sections[0];
  stwo::cuda::rv64::PcsAggregateCounts aggregate{};
  if (!stwo::cuda::rv64::decodePcsCounts(h.data(), h.size(), &aggregate))
    throw std::runtime_error("masked PCS header");
  const uint32_t degree = h[3], log = h[4], queries = h[6], sc = h[8],
                 tc = h[9], gc = h[10], sgc = h[11], nt = h[12],
                 sample_count = h[13], layers = h[14];
  if (log > 28 || !nt || nt > 4 || !sc || sc > 65536 || !tc || tc > 65536 ||
      !gc || gc > 1024 || !sgc || sgc > 96 || !sample_count ||
      sample_count > 65536 || !queries || queries > 1024 || layers > 28 ||
      input.coefficients.size() != sc)
    throw std::runtime_error("masked PCS shape");
  const uint32_t rows = 1u << log;
  const auto initial_seed = input.sections[1],
             imported_point = input.sections[2], sources = input.sections[3],
             terms = input.sections[4], groups = input.sections[5],
             source_groups = input.sections[6], tree_info = input.sections[7],
             recipes = input.sections[8], deep_tw = input.sections[9],
             sample_map = input.sections[10],
             sample_counts = input.sections[11], twiddles = input.sections[12],
             descriptions = input.sections[13],
             fri_twiddles = input.sections[14],
             expected_roots = input.sections[15];
  const size_t sizes[] = {h.size(),
                          9,
                          h[21] ? 16u : 0u,
                          size_t(sc) * 4,
                          size_t(tc) * 4,
                          size_t(gc) * 8,
                          size_t(sgc) * 8,
                          size_t(nt) * 6,
                          size_t(gc) * 4,
                          size_t(gc) * 2,
                          sample_count,
                          sc,
                          h[19],
                          size_t(layers) * 8,
                          h[20],
                          size_t(nt) * 8};
  for (size_t i = 0; i < 16; ++i)
    sizeIs(input.sections[i], sizes[i]);
  if (!input.domain.size())
    sizeIs(input.sections[16], 4);
  auto upload = [&](Words v) {
    auto p = o.plane(v.size(), 1);
    o.uploadBorrowed(p, v.data(), v.size());
    return p;
  };
  auto uploadOwned = [&](std::vector<uint32_t> values) {
    auto p = o.plane(values.size(), 1);
    o.upload(p, values);
    return p;
  };
  // Imported OODS already authenticates all trace roots in the transcript.
  // Keep only one source tree's LDE live, and borrow admitted device coefficients.
  // Beta2 is an explicit allocation-policy experiment. Its source stride is
  // one quarter of the LDE, so every compact extension must bound its reads.
  const char *beta2_flag = std::getenv("STWO_RV64_PCS_ROLLING_BETA2");
  const bool rolling_beta2 = beta2_flag && std::strcmp(beta2_flag, "1") == 0;
  const bool rolling_sources = h[21] && (h[5] == 1 || (h[5] == 2 && rolling_beta2));
  std::array<StwoRv64Plane,4> coefficient_trees{};
  std::vector<uint32_t> source_words(sources.begin(), sources.end());
  uint64_t max_tree_evaluations=0, max_tree_nodes=0;
  if (rolling_sources) {
    uint32_t next_source=0, next_group=0;
    for (uint32_t t=0;t<nt;++t) {
      const auto *d=tree_info.data()+t*6;
      if(d[0]!=next_source || d[2]!=next_group || d[1]>sc-next_source || d[3]>sgc-next_group || d[4]>log || d[5])
        throw std::runtime_error("rolling tree partition");
      next_source+=d[1]; next_group+=d[3];
      uint64_t count=0, eval_count=0;
      stwo::cuda::rv64::PrefixBanks prefix;
      std::vector<CoefficientTransfer> transfers;
      for(uint32_t j=0;j<d[1];++j) {
        const uint32_t c=d[0]+j;
        auto v=input.coefficients[c];
        if(sources[4*c+3]>28 || v.size()!=(uint64_t(1)<<sources[4*c+3]))
          throw std::runtime_error("rolling coefficient shape");
        const auto kind=o.validateCoefficient(v,input.scope.data());
        appendCoefficientTransfer(transfers,v,count,kind,input.scope);
        source_words[4*c]=uint32_t(count); source_words[4*c+1]=uint32_t(count>>32); source_words[4*c+2]=t;
        count+=v.size();
      }
      if(transfers.size()==1 && transfers[0].source.kind==1) {
        (void)o.validateCoefficient(transfers[0].source,input.scope.data());
        coefficient_trees[t]={const_cast<uint32_t*>(transfers[0].source.data()),count,1,0};
      } else {
        coefficient_trees[t]=o.sourcePlane(count,1);
        for(const auto &v:transfers) o.uploadCoefficient({coefficient_trees[t].words+v.destination,v.source.size(),1,0},v.source,input.scope.data());
      }
      for(uint32_t g=d[2];g<d[2]+d[3];++g) {
        const auto *v=source_groups.data()+g*8;
        if(v[3]>28 || v[2]+h[5]!=v[3] || v[4]<d[0] || v[4]>d[0]+d[1] || v[5]>d[0]+d[1]-v[4]) throw std::runtime_error("rolling source groups");
        eval_count+=(uint64_t(1)<<v[3])*v[5];
        if (g + 1 < d[2] + d[3] && v[3] != source_groups[(g + 1) * 8 + 3])
          if (!prefix.addHeight(uint32_t(1) << v[3])) throw std::runtime_error("rolling prefix geometry");
      }
      max_tree_evaluations=std::max(max_tree_evaluations,eval_count);
      max_tree_nodes=std::max(max_tree_nodes,((uint64_t(2)<<d[4])-1)*8 + prefix.words());
    }
    if(next_source!=sc || next_group!=sgc) throw std::runtime_error("rolling tree coverage");
  }
  const uint64_t source_eval_base = rolling_sources ? 0 : aggregate.coefficients,
                 combined_coeff_base = rolling_sources ? 0 : source_eval_base + aggregate.evaluations,
                 combined_eval_base = combined_coeff_base + aggregate.combined_coefficients,
                 twiddle_base = combined_eval_base + aggregate.combined_evaluations,
                 descriptor_base = twiddle_base + (rolling_sources ? 0 : h[19]);
  const uint64_t arena_words = descriptor_base + uint64_t(sc + 8 * gc) * 6;
  const auto arena = o.plane(arena_words, 1);
  std::vector<CoefficientTransfer> coefficient_transfers;
  coefficient_transfers.reserve(sc);
  uint32_t device_columns=0;
  for (uint32_t c = 0; c < sc; ++c) {
    const uint64_t offset =
        uint64_t(sources[4 * c]) | (uint64_t(sources[4 * c + 1]) << 32);
    const auto coefficients = input.coefficients[c];
    if (sources[4*c+3]>28 ||
        coefficients.size() != (uint64_t(1) << sources[4 * c + 3]) ||
        offset > aggregate.coefficients || coefficients.size() > aggregate.coefficients - offset)
      throw std::runtime_error("coefficient span geometry");
    const uint32_t lease_kind=o.validateCoefficient(coefficients,input.scope.data());
    device_columns += coefficients.kind==1;
    appendCoefficientTransfer(coefficient_transfers,coefficients,offset,lease_kind,input.scope);
  }
  // uploadCoefficient revalidates the COMPLETE merged range against the same
  // live lease; adjacency alone never establishes ownership of the gap/span.
  if (!rolling_sources) for (const auto &transfer:coefficient_transfers)
    o.uploadCoefficient({arena.words+transfer.destination,transfer.source.size(),1,0},
                        transfer.source,transfer.scope.data());
  if (!rolling_sources) o.uploadBorrowed({arena.words + twiddle_base, h[19], 1, 0}, twiddles.data(),
                                        twiddles.size());
  StwoRv64Plane rolling_evaluations{}, rolling_tree{}, stream_scratch{};
  const uint64_t stream_budget = rolling_sources ? pcsStreamBudget() : 0;
  uint64_t stream_scratch_words = 0;
  std::vector<stwo::cuda::rv64::stream::Plan> stream_plans;
  const auto source_tw = rolling_sources ? upload(twiddles) : StwoRv64Plane{};
  const auto trace_roots = rolling_sources ? o.plane(nt*8,1) : StwoRv64Plane{};
  std::vector<StwoRv64Plane> source_descriptors, combined_descriptors, combined_logs;
  std::vector<uint32_t> group_trees(sgc), group_logs;
  if(rolling_sources) for(uint32_t t=0;t<nt;++t) for(uint32_t g=tree_info[t*6+2];g<tree_info[t*6+2]+tree_info[t*6+3];++g) group_trees[g]=t;
  std::vector<b::MixedSegment> trace_segments;
  std::vector<uint64_t> trace_evaluation_offsets;
  uint64_t descriptor_offset = descriptor_base;
  auto descriptor = [&](uint64_t source, uint64_t destination,
                        uint32_t coefficient_log, std::vector<uint32_t> &v) {
    v.insert(v.end(),
             {uint32_t(source), uint32_t(source >> 32), uint32_t(destination),
              uint32_t(destination >> 32), coefficient_log, 0});
  };
  uint64_t sample_scratch_words = 0;
  uint32_t max_group_terms = 0;
  uint64_t local_eval_offset=0;
  for (uint32_t g = 0; g < sgc; ++g) {
    const auto *s = source_groups.data() + g * 8;
    if (rolling_sources && (!g || group_trees[g]!=group_trees[g-1])) local_eval_offset=0;
    const uint64_t eval_offset = rolling_sources ? local_eval_offset : uint64_t(s[0]) | (uint64_t(s[1]) << 32);
    if (rolling_sources && s[4] != group_logs.size()) throw std::runtime_error("rolling source group coverage");
    const uint32_t m = 1u << s[3];
    if (s[4] + s[5] > sc || s[3] != s[2] + h[5] ||
        (rolling_sources && (s[6]>h[19] || s[7]>h[19]-s[6])))
      throw std::runtime_error("source group geometry");
    std::vector<uint32_t> packets;
    for (uint32_t j = 0; j < s[5]; ++j) {
      const auto *c = (rolling_sources ? source_words.data() : sources.data()) + (s[4] + j) * 4;
      if (rolling_sources && c[3]!=s[2]) throw std::runtime_error("rolling column degree mismatch");
      descriptor(uint64_t(c[0]) | (uint64_t(c[1]) << 32),
                 source_eval_base + eval_offset + uint64_t(j) * m, s[2],
                 packets);
    }
    StwoRv64Plane p{arena.words + descriptor_offset, packets.size(), 1, 0};
    o.upload(p, packets);
    source_descriptors.push_back(p);
    descriptor_offset += packets.size();
    trace_evaluation_offsets.push_back(eval_offset);
    trace_segments.push_back({rolling_sources ? nullptr : arena.words+source_eval_base+eval_offset, m,
                              uint64_t(m) * s[5], m, 0});
    local_eval_offset+=uint64_t(m)*s[5];
    group_logs.insert(group_logs.end(),s[5],s[2]);
  }
  if (rolling_sources && group_logs.size()!=sc) throw std::runtime_error("rolling source group coverage");
  for (uint32_t g = 0; g < gc; ++g) {
    const auto *d = groups.data() + g * 8;
    if(d[2]>28||d[3]>28||(rolling_sources&&d[3]!=d[2]+h[5]))
      throw std::runtime_error("combined extension geometry");
    const uint32_t n = 1u << d[2], m = 1u << d[3], count = d[1] - d[0];
    const uint64_t coefficient_offset=uint64_t(d[4])|(uint64_t(d[5])<<32);
    const uint64_t evaluation_offset=uint64_t(d[6])|(uint64_t(d[7])<<32);
    if (!count || d[0]>=d[1] || d[1] > tc ||
        (rolling_sources &&
         (coefficient_offset>aggregate.combined_coefficients || uint64_t(n)*8>aggregate.combined_coefficients-coefficient_offset ||
          evaluation_offset>aggregate.combined_evaluations || uint64_t(m)*8>aggregate.combined_evaluations-evaluation_offset ||
          deep_tw[g*2]>h[19] || deep_tw[g*2+1]>h[19]-deep_tw[g*2])))
      throw std::runtime_error("DEEP group geometry");
    std::vector<uint32_t> packets;
    if (rolling_sources) {
      // Compact columns N2B accepts the separate forward-twiddle plane.
      // Keep the existing arena reservation; only the first eight log words
      // are consumed on this rolling path.
      packets.assign(8,d[2]);
      packets.resize(8*6,0);
    } else for (uint32_t c = 0; c < 8; ++c)
      descriptor(
          combined_coeff_base + (uint64_t(d[4]) | (uint64_t(d[5]) << 32)) +
              uint64_t(c) * n,
          combined_eval_base + (uint64_t(d[6]) | (uint64_t(d[7]) << 32)) +
              uint64_t(c) * m,
          d[2], packets);
    StwoRv64Plane p{arena.words + descriptor_offset, packets.size(), 1, 0};
    o.upload(p, packets);
    combined_descriptors.push_back(p);
    combined_logs.push_back(rolling_sources ? StwoRv64Plane{p.words,8,1,0} : StwoRv64Plane{});
    descriptor_offset += packets.size();
    sample_scratch_words =
        std::max(sample_scratch_words, uint64_t((n + 1023) / 1024) * count * 8);
    max_group_terms = std::max(max_group_terms, count);
  }
  if (descriptor_offset != arena_words)
    throw std::runtime_error("PCS arena plan mismatch");
  const auto permutation = upload(sample_map),
             ordered_values = o.plane(sample_count * 8, 1);
  const auto coefficient_logs=uploadOwned(group_logs);
  const auto seed = o.io.seed ? o.borrow(o.io.seed, 9) : upload(initial_seed), src = rolling_sources ? uploadOwned(source_words) : upload(sources),
             term = upload(terms), grp = upload(groups),
             recipe = upload(recipes),
             xy = o.domain(log, input.domain, input.sections[16]),
             fri_tw = upload(fri_twiddles);
  const auto state = o.plane(16, 1), boundary = o.plane(16, 1),
             parameter = h[21] ? (o.io.point ? o.borrow(o.io.point, 16) : upload(imported_point)) : o.plane(8, 1),
             point_arena = o.plane((gc + 1) * 16, 1),
             factors = o.plane(gc * 28 * 8, 1),
             point_ready = o.plane(gc + 1, 1),
             sample_scratch_a = o.plane(sample_scratch_words, 1),
             sample_scratch_b = o.plane(sample_scratch_words, 1),
             sample_valid = o.plane(max_group_terms, 1),
             values = o.plane(tc * 8, 1), alpha = o.plane(8, 1),
             weights = o.plane(tc * 8, 1), linear = o.plane(gc * 16, 1),
             deep_valid = o.plane(2, 1), deep = o.plane(rows, 8),
             terminal = o.plane(8, 1), raw = o.plane(queries, 1),
             nonce = uploadOwned({0, 0}), status = uploadOwned({0}),
             pow_prefix = o.plane(8, 1), pow_best = o.plane(2, 1),
             pow_blocks = o.plane(1, 1);
  struct TraceStorage {
    StwoRv64Plane tree, values, paths;
    uint32_t first, columns, group, groups, log;
    uint64_t tree_words, tree_capacity;
  };
  std::vector<TraceStorage> traces;
  for (uint32_t t = 0; t < nt; ++t) {
    const auto *d = tree_info.data() + t * 6;
    if (d[5] || d[0] + d[1] > sc || d[2] + d[3] > sgc || d[4] > log)
      throw std::runtime_error("tree geometry");
    TraceStorage v{};
    v.first = d[0];
    v.columns = d[1];
    v.group = d[2];
    v.groups = d[3];
    v.log = d[4];
    v.tree_words = ((uint64_t(2) << v.log) - 1) * 8;
    stwo::cuda::rv64::PrefixBanks prefix;
    for (uint32_t i = 0; i + 1 < v.groups; ++i) {
      const auto &segment = trace_segments[v.group + i];
      if (segment.source_size != trace_segments[v.group + i + 1].source_size)
        if (!prefix.addHeight(segment.source_size)) throw std::runtime_error("trace prefix geometry");
    }
    // The shared rolling allocation includes both prefix-state banks. Logical
    // Merkle offsets exclude this admitted tail, exactly as in the legacy path.
    v.tree_capacity = v.tree_words + prefix.words();
    v.tree = rolling_sources ? StwoRv64Plane{} : o.plane(v.tree_capacity, 1);
    v.values = o.plane(uint64_t(v.columns) * queries, 1);
    v.paths = o.plane(uint64_t(queries) * v.log * 8, 1);
    traces.push_back(v);
  }
  const auto last = o.plane(1u << h[5], 8);
  const auto fri_roots = rolling_sources && layers ? o.plane(uint64_t(layers)*8,1) : StwoRv64Plane{};
  std::vector<FriStorage> storage;
  for (uint32_t i = 0; i < layers; ++i) {
    const auto *d = descriptions.data() + i * 8;
    FriStorage s{};
    s.count = d[0];
    s.steps = d[1];
    s.leaf = d[2];
    s.shift = d[3];
    s.column = i == 0 ? deep : o.plane(s.count, 8);
    s.tree_words = (2ull * (s.count >> s.leaf) - 1) * 8;
    s.value_words = (uint64_t(queries) << s.steps) * 8;
    s.path_words = (uint64_t(queries) << (s.steps - s.leaf)) *
                   (uint32_t(__builtin_ctz(s.count)) - s.leaf) * 8;
    s.tree = o.plane(s.tree_words, 1);
    s.alpha = o.plane(8, 1);
    s.values = o.plane(s.value_words, 1);
    s.paths = o.plane(s.path_words, 1);
    storage.push_back(s);
  }
  // run() joined here before compute on lane 1; ingress is on this stream.
  void *stream_raw = o.stream;
  auto stream = o.stream;
  auto phase_mark = [](size_t) {};
  // Preserve the qualified beta1 call verbatim. Beta2 coefficients have
  // stride=2^degree < half-domain, requiring the bounded compact ABI even
  // though the arithmetic kernels and zero extension are the same.
  auto extend_columns = [&](const uint32_t *coefficients, size_t stride,
      const uint32_t *logs, uint32_t *evaluations, size_t output_stride,
      uint32_t log_n, uint32_t count, const uint32_t *twiddles,
      uint32_t twiddle_words, uint32_t domain, void *stream, uint32_t *launches) {
    if (h[5] == 2)
      return stwo_lde_n2b_columns_compact_on(coefficients, stride, logs,
          evaluations, output_stride, log_n, count, twiddles, twiddle_words,
          domain, stride, stream, launches);
    return stwo_lde_n2b_columns_on(coefficients, stride, logs, evaluations,
        output_stride, log_n, count, twiddles, twiddle_words, domain, stream, launches);
  };
  auto extend_source = [&](uint32_t g) {
    const auto *d = source_groups.data() + g * 8;
    uint32_t launches = 0;
    if(rolling_sources) {
      const uint32_t t=group_trees[g];
      const auto *source=source_words.data()+4*d[4];
      const uint64_t offset=uint64_t(source[0])|(uint64_t(source[1])<<32);
      CHECK(extend_columns(coefficient_trees[t].words+offset, uint64_t(1)<<d[2],
        coefficient_logs.words+d[4], const_cast<uint32_t*>(trace_segments[g].columns), uint64_t(1)<<d[3], d[3], d[5],
        source_tw.words+d[6],d[7],1u<<(d[3]-1),stream_raw,&launches));
      return;
    }
    CHECK(stwo_lde_n2b_addressed_on(
        arena.words, arena_words, source_descriptors[g].words, d[5],
        source_eval_base + (uint64_t(d[0]) | (uint64_t(d[1]) << 32)), d[3],
        arena.words + twiddle_base + d[6], d[7], 1u << (d[3] - 1), stream_raw,
        1, &launches));
  };
  auto extend_combined = [&](uint32_t g) {
    const auto *d = groups.data() + g * 8;
    uint32_t launches = 0;
    if (rolling_sources) {
      CHECK(extend_columns(
          arena.words+combined_coeff_base+(uint64_t(d[4])|(uint64_t(d[5])<<32)),uint64_t(1)<<d[2],combined_logs[g].words,
          arena.words+combined_eval_base+(uint64_t(d[6])|(uint64_t(d[7])<<32)),uint64_t(1)<<d[3],d[3],8,
          source_tw.words+deep_tw[g*2],deep_tw[g*2+1],1u<<(d[3]-1),stream_raw,&launches));
    } else CHECK(stwo_lde_n2b_addressed_on(
        arena.words, arena_words, combined_descriptors[g].words, 8,
        combined_eval_base + (uint64_t(d[6]) | (uint64_t(d[7]) << 32)), d[3],
        arena.words + twiddle_base + deep_tw[g * 2], deep_tw[g * 2 + 1],
        1u << (d[3] - 1), stream_raw, 1, &launches));
  };
  if(!rolling_sources) for (uint32_t g = 0; g < sgc; ++g)
    extend_source(g);
  phase_mark(1);
  if(!rolling_sources) for (auto &t : traces)
    CHECK(stwo_rv64_trace_tree_on(o.ctx, o.lane, trace_segments.data() + t.group,
                                  t.groups, t.log, t.tree.words, t.tree_capacity));
  phase_mark(2);
  CHECK(stwo_rv64_channel_init_on(o.ctx, o.lane, state.words, seed.words, 17));
  uint32_t step = 0;
  auto mix = [&](const uint32_t *p, uint32_t count, uint32_t field) {
    CHECK(stwo_rv64_channel_mix_on(o.ctx, o.lane, state.words, step, 17 + step,
                                   18 + step, p, count, field, boundary.words));
    ++step;
  };
  auto draw = [&](uint32_t *p) {
    CHECK(stwo_rv64_channel_draw_on(o.ctx, o.lane, state.words, step, 17 + step,
                                    18 + step, 1, p, boundary.words));
    ++step;
  };
  if (!h[21]) {
    for (const auto &t : traces)
      mix(t.tree.words + t.tree_words - 8, 8, 0);
    draw(parameter.words);
  }
  StwoRv64SamplePoints point_job{
      parameter.words,
      reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words),
      point_arena.words,
      factors.words,
      point_ready.words,
      status.words,
      gc,
      0};
  CHECK(h[21] ? stwo_rv64_sample_points_from_point_on(o.ctx, o.lane, &point_job)
              : stwo_rv64_sample_points_on(o.ctx, o.lane, &point_job));
  for (uint32_t g = 0; g < gc; ++g) {
    const auto *d = groups.data() + g * 8;
    StwoRv64SampleEvaluation sample{};
    if(rolling_sources) for(uint32_t t=0;t<nt;++t) { sample.trees[t]=coefficient_trees[t].words; sample.tree_words[t]=coefficient_trees[t].stride; }
    else { sample.trees[0] = arena.words; sample.tree_words[0] = aggregate.coefficients; }
    sample.sources = reinterpret_cast<const StwoRv64DeepSource *>(src.words);
    sample.terms = reinterpret_cast<const StwoRv64DeepTerm *>(term.words);
    sample.recipes =
        reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words);
    sample.factors = factors.words;
    sample.point_ready = point_ready.words;
    sample.scratch_a = sample_scratch_a.words;
    sample.scratch_b = sample_scratch_b.words;
    sample.values = values.words;
    sample.valid = sample_valid.words;
    sample.status = status.words;
    sample.scratch_words = sample_scratch_words;
    sample.value_words = tc * 8;
    sample.source_count = sc;
    sample.term_capacity = tc;
    sample.group_count = gc;
    sample.first = d[0];
    sample.count = d[1] - d[0];
    sample.coefficient_log = d[2];
    CHECK(stwo_rv64_sample_evaluate_on(o.ctx, o.lane, &sample));
  }
  CHECK(stwo_rv64_sample_order_on(o.ctx, o.lane, values.words, tc, permutation.words,
                                  sample_count, ordered_values.words,
                                  status.words));
  mix(ordered_values.words, sample_count * 8, 1);
  draw(alpha.words);
  phase_mark(3);
  StwoRv64DeepPrepare prepare{};
  if(rolling_sources) for(uint32_t t=0;t<nt;++t) { prepare.trees[t]=coefficient_trees[t].words; prepare.tree_words[t]=coefficient_trees[t].stride; }
  else { prepare.trees[0] = arena.words; prepare.tree_words[0] = aggregate.coefficients; }
  prepare.sources = reinterpret_cast<const StwoRv64DeepSource *>(src.words);
  prepare.terms = reinterpret_cast<const StwoRv64DeepTerm *>(term.words);
  prepare.groups = reinterpret_cast<const StwoRv64DeepGroup *>(grp.words);
  prepare.points = point_arena.words + 16;
  prepare.values = values.words;
  prepare.alpha = alpha.words;
  prepare.weights = weights.words;
  prepare.linear = linear.words;
  prepare.coefficients = arena.words + combined_coeff_base;
  prepare.valid = deep_valid.words;
  prepare.status = status.words;
  prepare.coefficient_words = aggregate.combined_coefficients;
  prepare.source_count = sc;
  prepare.term_count = tc;
  prepare.group_count = gc;
  CHECK(stwo_rv64_deep_prepare_on(o.ctx, o.lane, &prepare));
  for (uint32_t g = 0; g < gc; ++g)
    extend_combined(g);
  StwoRv64DeepCombine combine{};
  combine.groups = reinterpret_cast<const StwoRv64DeepGroup *>(grp.words);
  combine.points = point_arena.words + 16;
  combine.linear = linear.words;
  combine.evaluations = arena.words + combined_eval_base;
  combine.domain_xy = xy.words;
  combine.valid = deep_valid.words;
  combine.output = deep;
  combine.status = status.words;
  combine.evaluation_words = aggregate.combined_evaluations;
  combine.group_count = gc;
  combine.output_log = log;
  CHECK(stwo_rv64_deep_combine_on(o.ctx, o.lane, &combine));
  phase_mark(4);
  if (rolling_sources) {
    // Source opening uses only original coefficients, compact logs and fresh
    // immutable forward twiddles. None of the combined DEEP arena survives.
    o.retirePlanes({arena, sample_scratch_a, sample_scratch_b, sample_valid,
                    values, weights, linear, deep_valid, factors, point_ready,
                    point_arena, parameter, alpha, src, term, grp, recipe,
                    permutation, seed});
  }
  for (uint32_t i = 0; i < layers; ++i) {
    auto &s = storage[i];
    CHECK(stwo_rv64_fri_tree_on(o.ctx, o.lane, s.column, s.count, s.leaf,
                                s.tree.words, s.tree_words));
    if (rolling_sources) CHECK(cudaMemcpyAsync(fri_roots.words+uint64_t(i)*8,s.tree.words+s.tree_words-8,8*sizeof(uint32_t),cudaMemcpyDeviceToDevice,stream));
    mix(s.tree.words + s.tree_words - 8, 8, 0);
    draw(s.alpha.words);
    StwoRv64FriFold fold{};
    fold.input = s.column;
    fold.output = i + 1 < layers ? storage[i + 1].column : last;
    fold.twiddles = fri_tw.words;
    fold.twiddle_words = fri_twiddles.size();
    fold.alpha = s.alpha.words;
    for (uint32_t k = 0; k < 4; ++k)
      fold.offsets[k] = descriptions[i * 8 + 4 + k];
    fold.count = s.count;
    fold.steps = s.steps;
    fold.first_is_circle = i == 0;
    CHECK(stwo_rv64_fri_fold_on(o.ctx, o.lane, &fold));
  }
  CHECK(stwo_rv64_fri_terminal_on(o.ctx, o.lane, last, 1u << h[5], terminal.words,
                                  status.words));
  mix(terminal.words, 8, 1);
  if (rolling_sources) {
    std::vector<StwoRv64Plane> finished{fri_tw,last};
    for (const auto &s : storage) finished.push_back(s.alpha);
    o.retirePlanes(finished);
  }
  phase_mark(5);
  if (h[22]) {
    CHECK(stwo_blake2s_pow_persistent_on(
        state.words, h[22], 1ull << 40, pow_prefix.words,
        reinterpret_cast<unsigned long long *>(pow_best.words),
        pow_blocks.words, nonce.words, stream_raw));
  }
  phase_mark(6);
  mix(nonce.words, 2, 0);
  CHECK(stwo_rv64_channel_queries_on(o.ctx, o.lane, state.words, step, 17 + step,
                                     18 + step, log, queries, raw.words,
                                     boundary.words));
  ++step;
  for (auto &s : storage) {
    StwoRv64FriOpen open{s.column,       s.tree.words,  raw.words,
                         s.values.words, s.paths.words, status.words,
                         s.tree_words,   s.value_words, s.path_words,
                         s.count,        queries,       s.steps,
                         s.leaf,         s.shift,       0};
    CHECK(stwo_rv64_fri_open_on(o.ctx, o.lane, &open));
  }
  if (rolling_sources) {
    // FRI openings have now consumed every full column and tree. Only their
    // tiny roots and queried values/paths remain part of the proof output.
    std::vector<StwoRv64Plane> finished;
    for (const auto &s : storage) { finished.push_back(s.column);finished.push_back(s.tree); }
    if (storage.empty()) finished.push_back(deep);
    o.retirePlanes(finished);
    if (stream_budget) {
      for (const auto &t : traces) {
        std::vector<uint32_t> rows;
        for (uint32_t g = t.group; g < t.group + t.groups; ++g)
          rows.insert(rows.end(), source_groups[g * 8 + 5], 1u << source_groups[g * 8 + 3]);
        stwo::cuda::rv64::stream::Plan p;
        if (!stwo::cuda::rv64::stream::plan(rows, stream_budget, &p, 1u << t.log, pcsCompactEager()))
          throw std::runtime_error("streamed source geometry");
        stream_scratch_words = std::max(stream_scratch_words, p.scratchWords());
        stream_plans.push_back(std::move(p));
      }
      stream_scratch = o.plane(stream_scratch_words, 1);
    } else {
      rolling_evaluations = o.plane(max_tree_evaluations,1);
      rolling_tree = o.plane(max_tree_nodes,1);
      for (uint32_t g=0;g<sgc;++g)
        trace_segments[g].columns = rolling_evaluations.words+trace_evaluation_offsets[g];
      for (auto &t : traces) t.tree = {rolling_tree.words,t.tree_capacity,1,0};
    }
    // run() joined here; job arena allocations are stream-ordered.
  }
  for (auto &t : traces) {
    if (rolling_sources && stream_budget) {
      // Chunked rebuild: LDE a bounded column chunk, read its queried values,
      // absorb it into the progressive leaf state, then reuse the chunk. The
      // tree is built in the bank that is dead after the final absorption.
      const size_t ti = size_t(&t - traces.data());
      const auto &p = stream_plans[ti];
      uint32_t *base = stream_scratch.words, *chunk = base;
      uint32_t *banks[2] = {base + p.bankOffset(0), base + p.bankOffset(1)};
      uint32_t *hashes = banks[0];
      for (const auto &c : p.calls) {
        b::MixedSegment segments[stwo::cuda::rv64::stream::kMaxSegments];
        uint32_t count = 0, column = 0, g = t.group;
        uint64_t cursor = 0;
        for (uint32_t k = c.first; k < c.end;) {
          while (column + source_groups[g * 8 + 5] <= k) column += source_groups[g++ * 8 + 5];
          const auto *d = source_groups.data() + g * 8;
          const uint32_t j = k - column, run = std::min(c.end, column + d[5]) - k;
          const uint64_t n = uint64_t(1) << d[2], m = uint64_t(1) << d[3];
          const auto *source = source_words.data() + 4 * d[4];
          const uint64_t offset = (uint64_t(source[0]) | (uint64_t(source[1]) << 32)) + uint64_t(j) * n;
          if (count == stwo::cuda::rv64::stream::kMaxSegments)
            throw std::runtime_error("streamed segment overflow");
          uint32_t launches = 0;
          CHECK(extend_columns(coefficient_trees[ti].words + offset, n,
            coefficient_logs.words + d[4] + j, chunk + cursor, m, d[3], run,
            source_tw.words + d[6], d[7], uint32_t(m / 2), stream_raw, &launches));
          segments[count++] = {chunk + cursor, m, m * run, uint32_t(m), 0};
          cursor += m * run;
          k += run;
        }
        StwoRv64TraceOpen values{nullptr, raw.words,
                                 t.values.words + uint64_t(c.first) * queries,
                                 nullptr, status.words, 0,
                                 uint64_t(c.end - c.first) * queries, 0,
                                 t.log, log, queries, 0};
        CHECK(stwo_rv64_trace_open_values_on(o.ctx, o.lane, segments, count, &values));
        const void *seed = c.seed_bank < 0 ? nullptr : banks[c.seed_bank];
        auto *out = banks[c.out_bank];
        if (pcsCompactEager()) {
          if (!&stwo_blake2s_mixed_seeded_eager_compact_on)
            throw std::runtime_error("base image lacks compact eager Blake2s");
          CHECK(stwo_blake2s_mixed_seeded_eager_compact_on(c.size,count,segments,c.absorbed,c.seed_size,
              reinterpret_cast<const uint32_t*>(seed),c.seed_bank<0?0:p.bank_words[c.seed_bank],
              c.final?nullptr:out,c.final?0:p.bank_words[c.out_bank],
              c.final?out:nullptr,c.final?p.bank_words[c.out_bank]:0,stream_raw));
        } else {
        CHECK(stwo_blake2s_mixed_seeded_eager_on(c.size, count, segments, c.absorbed,
            c.seed_size, seed, c.final ? nullptr : out, c.final ? out : nullptr,
            stream_raw));
        }
        if (c.final) hashes = out;
      }
      CHECK(pcsMerkleLayers(hashes, p.leaves, stream_raw));
      CHECK(cudaMemcpyAsync(trace_roots.words + ti * 8, hashes + p.tree_words - 8,
                            8 * sizeof(uint32_t), cudaMemcpyDeviceToDevice, stream));
      StwoRv64TraceOpen paths{hashes, raw.words, nullptr, t.paths.words,
                              status.words, p.tree_words, 0,
                              uint64_t(queries) * t.log * 8, t.log, log,
                              queries, 0};
      CHECK(stwo_rv64_trace_open_paths_on(o.ctx, o.lane, &paths));
      continue;
    }
    if(rolling_sources) {
      for(uint32_t g=t.group;g<t.group+t.groups;++g) extend_source(g);
      CHECK(stwo_rv64_trace_tree_on(o.ctx, o.lane,trace_segments.data()+t.group,t.groups,t.log,t.tree.words,t.tree_capacity));
      CHECK(cudaMemcpyAsync(trace_roots.words+(&t-traces.data())*8,t.tree.words+t.tree_words-8,8*sizeof(uint32_t),cudaMemcpyDeviceToDevice,stream));
    }
    StwoRv64TraceOpen open{t.tree.words,
                           raw.words,
                           t.values.words,
                           t.paths.words,
                           status.words,
                           t.tree_words,
                           uint64_t(t.columns) * queries,
                           uint64_t(queries) * t.log * 8,
                           t.log,
                           log,
                           queries,
                           0};
    CHECK(stwo_rv64_trace_open_on(o.ctx, o.lane, trace_segments.data() + t.group,
                                  t.groups, &open));
  }
  // run() joined and read back here. The job writes the identical words into
  // its slab span instead: D2D slices in Result.words order, header last.
  std::vector<StwoRv64Plane> readbacks{status, state};
  for (const auto &t : traces)
    readbacks.push_back({rolling_sources ? trace_roots.words+(&t-traces.data())*8 : t.tree.words+t.tree_words-8,8,1,0});
  readbacks.push_back(ordered_values);
  readbacks.push_back(nonce);
  readbacks.push_back(terminal);
  readbacks.push_back(raw);
  for (const auto &s : storage) {
    readbacks.push_back({rolling_sources ? fri_roots.words+uint64_t(&s-storage.data())*8 : s.tree.words + s.tree_words - 8, 8, 1, 0});
    readbacks.push_back(s.values);
    readbacks.push_back(s.paths);
  }
  for (const auto &t : traces) {
    readbacks.push_back(t.values);
    readbacks.push_back(t.paths);
  }
  if (step != job_plan.steps)
    throw std::runtime_error("PCS job transcript step plan mismatch");
  uint64_t cursor = 14;
  for (const auto &p : readbacks) {
    const uint64_t count = p.stride * p.coordinates;
    if (count > o.io.output_words - cursor)
      throw std::runtime_error("PCS job output layout overflow");
    CHECK(cudaMemcpyAsync(o.io.output + cursor, p.words, count * 4,
                          cudaMemcpyDeviceToDevice, stream));
    cursor += count;
  }
  if (cursor != o.io.output_words)
    throw std::runtime_error("PCS job output layout mismatch");
  const uint32_t out_header[] = {
      0x52564d4f,   2,      0,   sc,      tc,     gc,  sgc, nt,
      sample_count, layers, log, queries, degree, step};
  CHECK(cudaMemcpyAsync(o.io.output, o.stage(out_header, 14), sizeof(out_header),
                        cudaMemcpyHostToDevice, stream));
}
} // namespace

extern "C" int stwo_rv64_pcs_job_plan_v1(const StwoRv64PcsNativeRequest *request,
                                         StwoRv64PcsJobPlan *out) {
  try {
    if (!out) throw std::runtime_error("missing PCS job plan output");
    *out = planOf(inputFrom(request));
    last_error.clear();
    return 0;
  } catch (const std::exception &e) {
    last_error = e.what();
    return int(cudaErrorInvalidValue);
  }
}

extern "C" int stwo_rv64_pcs_job_enqueue_v1(void *ctx, uint32_t lane,
                                            const StwoRv64PcsNativeRequest *request,
                                            const StwoRv64PcsJobMemory *memory,
                                            const StwoRv64PcsJobIo *io) {
  try {
    if (!ctx || !memory || !io || !memory->alloc || !memory->release || !io->output)
      throw std::runtime_error("PCS job arguments");
    const auto input = inputFrom(request);
    const auto plan = planOf(input);
    if (io->output_words != plan.output_words)
      throw std::runtime_error("PCS job output span");
    if (memory->pinned_words < plan.ingress_words)
      throw std::runtime_error("PCS job pinned span");
    if (io->point && !input.sections[0][21])
      throw std::runtime_error("device OODS point requires an imported-point request");
    if (stwo_exec_context_validate_allocation(ctx, io->output, io->output_words * 4))
      throw std::runtime_error("PCS job output is not context storage");
    JobOwner owner(ctx, lane, *memory, *io);
    enqueueBody(owner, input, plan);
    last_error.clear();
    return 0;
  } catch (const std::exception &e) {
    last_error = e.what();
    return int(cudaErrorUnknown);
  }
}

extern "C" const char *stwo_rv64_pcs_job_error_v1(void) { return last_error.c_str(); }
