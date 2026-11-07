// Device global seal of a native request (M8 GPU-native, design
// rv64-m8-gpu-native.md §3.2 "Device seal" / §3.6, inventory H8; stream
// native, piece n-stage2). Replaces the host barrier's
//
//   chi    = manifest.chainDigestFor(.m6_v2_gkr, execution, entries)
//   shared = manifest.drawShared(chi)
//
// over the roster, reading every MAIN root from the request's peer-exchange
// replica on the seal device (no host ever reads a root). Under native-GKR
// (m6_v2_gkr) every entry's rho is the MAIN-only rho:
//
//   rho_k = H(rho, main_k || 0 || 0^8 || 0)
//   m_0   = H(iv, version_identity)                 (host constant)
//   m_k+1 = H(seg, m_k || k, family, rung || vkhash || stmt || s_in || s_out || rho_k)
//   chi   = H(chi, execution || m_n)
//   H(tag, words) = Blake2s(Blake2s(tag) || LE32 words)   (canon_native.zig)
//
// and then the shared challenges on a fresh Om31Channel (state digest =
// Om31Channel.init() digest, host constant):
//   mix {0x53474d31, 1, 8}; mix chi; mix {0x52414d31, 14}; draw 15 (RAM);
//   mix {0x4b494f31, kio_header}; draw 1 + kio_arity; mix {0x53574952,
//   wire_header}; draw 1 + wire_arity.
// Outputs: the 16-word seal checkpoint slot (chi[8], then 0) that every
// Stage-2 transcript mixes (mixManifestAndClaims) and the request's
// Check.global_seal verdict (every root slot this seal read carries this
// request's exchange flag tag). The shared felts are drawn by
// `stwo_rv64_native_seal_shared_v1_on` on each GPU from its replica of the
// slot (a few dozen hashes: cheaper than another exchange slot).
// One thread (the chain is sequential; ~3 Blake2s per entry), enqueue only.
#include "rv64/custody.cuh"
#include "transcript/state.cuh"
#include <stdint.h>

struct StwoRv64SealEntry {
  uint32_t k, family, rung;
  uint32_t root_offset;  // word offset of the MAIN root in `exchange`; UINT32_MAX: main_const
  uint32_t flag_offset;  // word offset of its exchange flag; UINT32_MAX: none (constant root)
  uint32_t reserved[3];
  uint32_t vkhash[8], stmt[8], s_in[8], s_out[8], main_const[8];
};
static_assert(sizeof(StwoRv64SealEntry) == 48 * 4, "seal entry ABI");

struct StwoRv64SealConstants {
  uint32_t rho_tag[8], seg_tag[8], chi_tag[8];  // Blake2s(tag name)
  uint32_t m0[8];                               // chainIv(version identity)
  uint32_t execution[8];                        // statement digest (chi input)
  uint32_t channel_init[8];                     // Om31Channel.init() digest
  uint32_t ram_header, kio_header, wire_header;  // 14, 11, 35 (manifest.drawShared)
  uint32_t ram_draws, kio_draws, wire_draws;     // 15, 1 + IO_ARITY, 1 + WIRE_ARITY
  uint32_t entries, tag;                         // roster size; request flag tag
};
static_assert(sizeof(StwoRv64SealConstants) == 56 * 4, "seal constants ABI");

namespace stwo::cuda::rv64::seal {
namespace t = stwo::cuda::transcript;
namespace {
constexpr uint32_t kGlobalSeal = 0x0103u;
enum Detail : uint32_t { kRootNotLanded = 1, kShape = 2 };

__device__ __forceinline__ void hash_into(uint32_t out[8], const uint32_t tag[8], const uint32_t *words, uint32_t n) {
  const t::Hash h = t::hash_digest_and_words(tag, words, n);
  for (uint32_t i = 0; i < 8; ++i) out[i] = h.words[i];
}

__device__ __forceinline__ void mix(uint32_t digest[8], uint32_t &draws, const uint32_t *words, uint32_t n) {
  const t::Hash h = t::hash_digest_and_words(digest, words, n);
  for (uint32_t i = 0; i < 8; ++i) digest[i] = h.words[i];
  draws = 0;
}

__device__ __forceinline__ void draw(const uint32_t digest[8], uint32_t &draws, uint32_t *out) {
  const t::Hash h = t::hash_draw(digest, draws);
  ++draws;
  for (uint32_t i = 0; i < 8; ++i) out[i] = t::reduce_m31_word(h.words[i]);
}

__global__ void seal_kernel(const StwoRv64SealEntry *entries, const uint32_t *exchange, StwoRv64SealConstants c,
                            uint32_t *slot, uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  uint32_t m[8];
  for (uint32_t i = 0; i < 8; ++i) m[i] = c.m0[i];
  for (uint32_t k = 0; k < c.entries; ++k) {
    const StwoRv64SealEntry &e = entries[k];
    if (e.k != k) detail = kShape;
    const uint32_t *main = e.root_offset == UINT32_MAX ? e.main_const : exchange + e.root_offset;
    if (e.flag_offset != UINT32_MAX && exchange[e.flag_offset] != c.tag && !detail) detail = kRootNotLanded;
    uint32_t pre[18] = {0};
    for (uint32_t i = 0; i < 8; ++i) pre[i] = main[i];
    uint32_t rho[8];
    hash_into(rho, c.rho_tag, pre, 18);
    uint32_t step[51];
    for (uint32_t i = 0; i < 8; ++i) step[i] = m[i];
    step[8] = e.k;
    step[9] = e.family;
    step[10] = e.rung;
    for (uint32_t i = 0; i < 8; ++i) {
      step[11 + i] = e.vkhash[i];
      step[19 + i] = e.stmt[i];
      step[27 + i] = e.s_in[i];
      step[35 + i] = e.s_out[i];
      step[43 + i] = rho[i];
    }
    hash_into(m, c.seg_tag, step, 51);
  }
  uint32_t fin[16], chi[8];
  for (uint32_t i = 0; i < 8; ++i) {
    fin[i] = c.execution[i];
    fin[8 + i] = m[i];
  }
  hash_into(chi, c.chi_tag, fin, 16);
  for (uint32_t i = 0; i < 8; ++i) {
    slot[i] = chi[i];
    slot[8 + i] = 0;
  }
  *verdict = detail ? ((kGlobalSeal << 16) | detail) : 0u;
}

// manifest.drawShared(chi) on a fresh Om31Channel; `chi` is the seal slot.
__global__ void shared_kernel(const uint32_t *chi_words, StwoRv64SealConstants c, uint32_t *shared) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t chi[8], digest[8], draws = 0;
  for (uint32_t i = 0; i < 8; ++i) {
    chi[i] = chi_words[i];
    digest[i] = c.channel_init[i];
  }
  const uint32_t h0[3] = {0x53474d31u, 1u, 8u};
  mix(digest, draws, h0, 3);
  mix(digest, draws, chi, 8);
  uint32_t at = 0;
  const uint32_t heads[3][2] = {{0x52414d31u, c.ram_header}, {0x4b494f31u, c.kio_header}, {0x53574952u, c.wire_header}};
  const uint32_t counts[3] = {c.ram_draws, c.kio_draws, c.wire_draws};
  for (uint32_t r = 0; r < 3; ++r) {
    mix(digest, draws, heads[r], 2);
    for (uint32_t i = 0; i < counts[r]; ++i, ++at) draw(digest, draws, shared + 8 * at);
  }
}
}  // namespace
}  // namespace stwo::cuda::rv64::seal

// entries: constants->entries records (device); exchange: the seal device's
// replica of the request exchange region (exchange_words); slot: the seal
// slot (16 words, inside the replica: published to the other GPUs by the
// caller); shared: (ram_draws + kio_draws + wire_draws) x 8 words; verdict: the
// request pseudo-proof's global_seal word.
extern "C" int stwo_rv64_native_seal_chi_v1_on(void *context, uint32_t lane, const StwoRv64SealEntry *entries,
                                              const uint32_t *exchange, uint64_t exchange_words,
                                              const StwoRv64SealConstants *constants, uint32_t *slot,
                                              uint32_t *verdict, const StwoRv64SealEntry *entries_host) {
  using stwo::cuda::rv64::RangeCustody;
  if (!constants || !entries_host || constants->entries == 0 || constants->entries > 4096)
    return int(cudaErrorInvalidValue);
  // Root/flag offsets are validated against the replica on the host copy.
  for (uint32_t k = 0; k < constants->entries; ++k) {
    const auto &e = entries_host[k];
    if ((e.root_offset != UINT32_MAX && uint64_t(e.root_offset) + 8 > exchange_words) ||
        (e.flag_offset != UINT32_MAX && e.flag_offset >= exchange_words))
      return int(cudaErrorInvalidValue);
  }
  RangeCustody<4> custody(context, lane);
  // `slot` lies inside the exchange replica; the replica is read-only here
  // except for that slot, so the replica range is declared up to the slot.
  const uintptr_t xb = reinterpret_cast<uintptr_t>(exchange), sb = reinterpret_cast<uintptr_t>(slot);
  if (sb < xb || sb + 64 > xb + exchange_words * 4) return int(cudaErrorInvalidValue);
  const uint64_t before = (sb - xb) / 4;
  if (!custody.range(reinterpret_cast<const uint32_t *>(entries), 48ull * constants->entries, false) ||
      (before && !custody.range(exchange, before, false)) || !custody.range(slot, 16, true))
    return custody.status;
  // The verdict is in the request slab (status region), outside the replica.
  RangeCustody<1> out(context, lane);
  if (!out.range(verdict, 1, true)) return out.status;
  for (uint32_t k = 0; k < constants->entries; ++k) {
    const auto &e = entries_host[k];
    if (e.root_offset != UINT32_MAX && uint64_t(e.root_offset) + 8 > before) return int(cudaErrorInvalidValue);
    if (e.flag_offset != UINT32_MAX && e.flag_offset >= before) return int(cudaErrorInvalidValue);
  }
  stwo::cuda::rv64::seal::seal_kernel<<<1, 1, 0, custody.stream>>>(entries, exchange, *constants, slot, verdict);
  return int(cudaPeekAtLastError());
}

// chi: the 8 digest words of a seal slot (any GPU's replica, after its
// await); shared: (ram_draws + kio_draws + wire_draws) x 8 words, draw order
// (RAM offset + 14 coefficients, KIO offset + arity, Wire offset + arity).
extern "C" int stwo_rv64_native_seal_shared_v1_on(void *context, uint32_t lane, const uint32_t *chi,
                                                 const StwoRv64SealConstants *constants, uint32_t *shared,
                                                 uint64_t shared_words) {
  using stwo::cuda::rv64::RangeCustody;
  if (!constants || constants->ram_draws + constants->kio_draws + constants->wire_draws == 0 ||
      shared_words < 8ull * (constants->ram_draws + constants->kio_draws + constants->wire_draws))
    return int(cudaErrorInvalidValue);
  RangeCustody<2> custody(context, lane);
  if (!custody.range(chi, 8, false) || !custody.range(shared, shared_words, true)) return custody.status;
  stwo::cuda::rv64::seal::shared_kernel<<<1, 1, 0, custody.stream>>>(chi, *constants, shared);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_native_seal_version(void) {
  return 1;
}
