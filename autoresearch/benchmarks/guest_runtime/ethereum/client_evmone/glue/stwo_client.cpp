// stwo RV64IM entry and input adapter for the ziskethone/evmone client (our code).
//
// Input: the canonical schema-prefixed SSZ StatelessInput the Rust guest reads
// (u32 length prefix at __input_start). Output: the 43-byte
// StatelessValidationResult (request root | success | chain id LE | schema id LE),
// identical to ethereum/rv64/src/main.rs.
//
// ziskethone consumes a pre-processed ZEG0 container. Its non-state sections
// (consensus info, transactions, contracts, ancestor headers) are synthesized
// here from the SSZ input; the state is not: the SSZ witness has no key
// preimages, so the account/storage tables are filled lazily by walking the
// witness trie from the parent state root (stwo_lazy_load_*), and the new state
// root is computed by applying the block's writes to that trie.
//
// The public output is the SSZ hash_tree_root of the input NewPayloadRequest,
// computed from the input bytes. It is only emitted if the re-executed block's
// hash equals the payload's block_hash and the payload's remaining fields
// (versioned hashes, execution requests via requests_hash, withdrawals via the
// header) agree with the re-execution.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/accounts.hpp"
#include "zeg/binary_format.hpp"
#include "zeg/block_header.hpp"
#include "zeg/consensus_info.hpp"
#include "zeg/fork_schedule.hpp"
#include "zeg/previous_blocks.hpp"
#include "zeg/rlp.hpp"
#include "zeg/run.hpp"
#include "zeg/sha256.hpp"
#include "zeg/ssz.hpp"
#include "zeg/storages.hpp"
#include "zeg/stwo_hooks.hpp"
#include "zeg/transactions.hpp"
#include "zeg/trie_node.hpp"

#include "witness_trie.hpp"

extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept;
extern "C" size_t stwo_heap_used() noexcept;
extern "C" bool stwo_secp_hint_sender(const uint8_t z_be[32], const uint8_t r_be[32], const uint8_t s_be[32],
                                      unsigned recid, const uint8_t pubkey65[65], uint8_t addr_out[20]);
extern "C" void stwo_secp_verify_pending();
extern "C" [[noreturn]] void stwo_fatal(const char* why) noexcept { stwo_guest_abort(why); }

namespace {

using stwo::ByteView;
using stwo::H256;

[[noreturn]] void fail(const char* why) { stwo_guest_abort(why); }

inline uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint64_t le64(const uint8_t* p) { return uint64_t(le32(p)) | uint64_t(le32(p + 4)) << 32; }

// ------------------------------------------------------------------ SSZ ----
struct Span {
    const uint8_t* p;
    size_t n;
};

// Field `i` of a variable-size field set: offsets are u32 at fixed positions.
Span var_field(Span c, size_t off_pos, size_t next_off_pos, bool last) {
    const uint32_t a = le32(c.p + off_pos);
    const uint32_t b = last ? uint32_t(c.n) : le32(c.p + next_off_pos);
    if (a > b || b > c.n) fail("ssz: bad offset");
    return Span{c.p + a, size_t(b - a)};
}

// A list of variable-size items: offsets table then data.
struct VarList {
    Span s;
    size_t count = 0;
    void init(Span x) {
        s = x;
        if (x.n == 0) { count = 0; return; }
        if (x.n < 4) fail("ssz: short list");
        const uint32_t first = le32(x.p);
        if (first % 4 != 0 || first > x.n || first == 0) fail("ssz: bad list offset");
        count = first / 4;
    }
    Span at(size_t i) const {
        const uint32_t a = le32(s.p + 4 * i);
        const uint32_t b = (i + 1 == count) ? uint32_t(s.n) : le32(s.p + 4 * (i + 1));
        if (a > b || b > s.n) fail("ssz: bad item offset");
        return Span{s.p + a, size_t(b - a)};
    }
};

struct Input {
    uint16_t schema_id;
    uint8_t fork_index;
    Span npr;  // NewPayloadRequestElectraFulu bytes
    Span payload;
    Span versioned_hashes;
    const uint8_t* parent_beacon_block_root;
    Span requests;
    Span req_lists[3];
    Span extra_data;
    VarList txs;
    Span withdrawals;
    VarList state_nodes, codes, headers;
    Span public_keys;  // 65-byte uncompressed keys, one per transaction
    uint64_t chain_id;
};

Input parse_input(const uint8_t* bytes, size_t len) {
    Input in{};
    if (len < 2 + 20) fail("ssz: input too short");
    in.schema_id = uint16_t(bytes[0]) << 8 | bytes[1];
    if ((in.schema_id & 0xff) != 0x01) fail("ssz: unsupported schema revision");
    in.fork_index = uint8_t(in.schema_id >> 8);
    // Prague, Osaka, BPO1, BPO2 share the ElectraFulu request shape.
    if (in.fork_index < 0x11 || in.fork_index > 0x14) fail("ssz: unsupported fork");
    const Span body{bytes + 2, len - 2};
    if (le32(body.p) != 20) fail("ssz: bad StatelessInput offsets");
    in.npr = var_field(body, 0, 4, false);
    const Span witness = var_field(body, 4, 16, false);
    in.chain_id = le64(body.p + 8);
    const Span pks = var_field(body, 16, 0, true);
    if (pks.n % 65 != 0) fail("ssz: public keys");
    in.public_keys = pks;

    const Span r = in.npr;
    if (r.n < 44 || le32(r.p) != 44) fail("ssz: bad request offsets");
    in.payload = var_field(r, 0, 4, false);
    in.versioned_hashes = var_field(r, 4, 40, false);
    in.parent_beacon_block_root = r.p + 8;
    in.requests = var_field(r, 40, 0, true);
    if (in.versioned_hashes.n % 32 != 0) fail("ssz: versioned hashes");
    if (in.requests.n < 12 || le32(in.requests.p) != 12) fail("ssz: bad requests offsets");
    in.req_lists[0] = var_field(in.requests, 0, 4, false);
    in.req_lists[1] = var_field(in.requests, 4, 8, false);
    in.req_lists[2] = var_field(in.requests, 8, 0, true);
    if (in.req_lists[0].n % 192 || in.req_lists[1].n % 76 || in.req_lists[2].n % 116)
        fail("ssz: request sizes");

    const Span p = in.payload;
    if (p.n < 528 || le32(p.p + 436) != 528) fail("ssz: bad payload offsets");
    in.extra_data = var_field(p, 436, 504, false);
    if (in.extra_data.n > 32) fail("ssz: extra data too long");
    in.txs.init(var_field(p, 504, 508, false));
    in.withdrawals = var_field(p, 508, 0, true);
    if (in.withdrawals.n % 44 != 0) fail("ssz: withdrawals");

    if (witness.n < 12 || le32(witness.p) != 12) fail("ssz: bad witness offsets");
    in.state_nodes.init(var_field(witness, 0, 4, false));
    in.codes.init(var_field(witness, 4, 8, false));
    in.headers.init(var_field(witness, 8, 0, true));
    return in;
}

// Payload field accessors (ExecutionPayloadV3 fixed part).
const uint8_t* pl_parent_hash(const Input& in) { return in.payload.p + 0; }
const uint8_t* pl_fee_recipient(const Input& in) { return in.payload.p + 32; }
const uint8_t* pl_state_root(const Input& in) { return in.payload.p + 52; }
const uint8_t* pl_receipts_root(const Input& in) { return in.payload.p + 84; }
const uint8_t* pl_logs_bloom(const Input& in) { return in.payload.p + 116; }
const uint8_t* pl_prev_randao(const Input& in) { return in.payload.p + 372; }
uint64_t pl_number(const Input& in) { return le64(in.payload.p + 404); }
uint64_t pl_gas_limit(const Input& in) { return le64(in.payload.p + 412); }
uint64_t pl_gas_used(const Input& in) { return le64(in.payload.p + 420); }
uint64_t pl_timestamp(const Input& in) { return le64(in.payload.p + 428); }
const uint8_t* pl_base_fee_le(const Input& in) { return in.payload.p + 440; }
const uint8_t* pl_block_hash(const Input& in) { return in.payload.p + 472; }
uint64_t pl_blob_gas_used(const Input& in) { return le64(in.payload.p + 512); }
uint64_t pl_excess_blob_gas(const Input& in) { return le64(in.payload.p + 520); }

// --------------------------------------------------------- SSZ roots ----
using zeg::ssz::Chunk;

Chunk chunk_of(const uint8_t* p, size_t n) {
    Chunk c{};
    std::memcpy(c.bytes, p, n);
    return c;
}

Chunk progressive_list_root(const std::vector<Chunk>& v) {
    return zeg::ssz::mix_in_length(zeg::ssz::merkleize_progressive({v.data(), v.size()}), v.size());
}

Chunk request_list_root(Span s, const size_t* fields, size_t nfields, size_t item) {
    std::vector<Chunk> roots;
    for (size_t off = 0; off < s.n; off += item) {
        Chunk f[5];
        size_t o = off;
        for (size_t i = 0; i < nfields; ++i) {
            f[i] = zeg::ssz::byte_vector_root({s.p + o, fields[i]});
            o += fields[i];
        }
        roots.push_back(zeg::ssz::merkleize({f, nfields}, nfields));
    }
    return progressive_list_root(roots);
}

// hash_tree_root(NewPayloadRequestElectraFulu) per the stateless crate pinned
// by the Rust guest (progressive payload / requests containers, progressive lists).
H256 request_root(const Input& in) {
    // ExecutionPayloadV3 (progressive container, 17 active fields).
    std::vector<Chunk> txr;
    txr.reserve(in.txs.count);
    for (size_t i = 0; i < in.txs.count; ++i) {
        const Span t = in.txs.at(i);
        txr.push_back(zeg::ssz::progressive_byte_list_root({t.p, t.n}));
    }
    std::vector<Chunk> wdr;
    for (size_t off = 0; off < in.withdrawals.n; off += 44) {
        const uint8_t* w = in.withdrawals.p + off;
        const Chunk f[4] = {chunk_of(w, 8), chunk_of(w + 8, 8), chunk_of(w + 16, 20), chunk_of(w + 36, 8)};
        wdr.push_back(zeg::ssz::merkleize({f, 4}, 4));
    }
    const Chunk pf[17] = {
        chunk_of(pl_parent_hash(in), 32),
        chunk_of(pl_fee_recipient(in), 20),
        chunk_of(pl_state_root(in), 32),
        chunk_of(pl_receipts_root(in), 32),
        zeg::ssz::byte_vector_root({pl_logs_bloom(in), 256}),
        chunk_of(pl_prev_randao(in), 32),
        zeg::ssz::uint64_root(pl_number(in)),
        zeg::ssz::uint64_root(pl_gas_limit(in)),
        zeg::ssz::uint64_root(pl_gas_used(in)),
        zeg::ssz::uint64_root(pl_timestamp(in)),
        zeg::ssz::byte_list_root({in.extra_data.p, in.extra_data.n}, 32),
        chunk_of(pl_base_fee_le(in), 32),
        chunk_of(pl_block_hash(in), 32),
        progressive_list_root(txr),
        progressive_list_root(wdr),
        zeg::ssz::uint64_root(pl_blob_gas_used(in)),
        zeg::ssz::uint64_root(pl_excess_blob_gas(in)),
    };
    const Chunk payload_root =
        zeg::ssz::mix_in_active_fields(zeg::ssz::merkleize_progressive({pf, 17}), 17);
    std::vector<Chunk> vh;
    for (size_t off = 0; off < in.versioned_hashes.n; off += 32)
        vh.push_back(chunk_of(in.versioned_hashes.p + off, 32));
    static constexpr size_t kDep[] = {48, 32, 8, 96, 8};
    static constexpr size_t kWr[] = {20, 48, 8};
    static constexpr size_t kCons[] = {20, 48, 48};
    const Chunk rl[3] = {
        request_list_root(in.req_lists[0], kDep, 5, 192),
        request_list_root(in.req_lists[1], kWr, 3, 76),
        request_list_root(in.req_lists[2], kCons, 3, 116),
    };
    const Chunk requests_root = zeg::ssz::mix_in_active_fields(zeg::ssz::merkleize_progressive({rl, 3}), 3);
    const Chunk top[4] = {payload_root, progressive_list_root(vh), chunk_of(in.parent_beacon_block_root, 32),
                          requests_root};
    const Chunk root = zeg::ssz::merkleize({top, 4}, 4);
    H256 out;
    std::memcpy(out.b, root.bytes, 32);
    return out;
}

// EIP-7685 requests_hash over the typed request lists.
evmc::bytes32 requests_hash(const Input& in) {
    std::vector<uint8_t> acc;
    for (uint8_t t = 0; t < 3; ++t) {
        const Span s = in.req_lists[t];
        if (s.n == 0) continue;
        std::vector<uint8_t> buf(1 + s.n);
        buf[0] = t;
        std::memcpy(buf.data() + 1, s.p, s.n);
        const evmc::bytes32 h = zeg::sha256_bytes32(buf.data(), buf.size());
        acc.insert(acc.end(), h.bytes, h.bytes + 32);
    }
    return zeg::sha256_bytes32(acc.data(), acc.size());
}

// ------------------------------------------------------- ZEG0 synthesis ----
struct Writer {
    std::vector<uint64_t> words;  // 8-byte aligned backing
    size_t n = 0;
    void reserve(size_t bytes) { words.assign((bytes + 7) / 8 + 1, 0); }
    uint8_t* at(size_t off) { return reinterpret_cast<uint8_t*>(words.data()) + off; }
    void need(size_t k) {
        if (n + k > words.size() * 8) fail("zeg0 writer overflow");
    }
    void u64(uint64_t v) { need(8); std::memcpy(at(n), &v, 8); n += 8; }
    void bytes(const uint8_t* p, size_t k) {
        need(k + 8);
        std::memcpy(at(n), p, k);
        n += k;
        n = (n + 7) & ~size_t(7);  // zero pad (buffer is zero-filled)
    }
    uint8_t* zeros(size_t k) { need(k); uint8_t* p = at(n); n += k; return p; }
};

// Big-endian minimal integer from an RLP string into a right-aligned field.
void rlp_uint_be(const zeg::rlp::Item& it, uint8_t* out, size_t width) {
    if (it.kind != zeg::rlp::ItemKind::String || it.payload.size() > width) fail("header: bad integer");
    std::memset(out, 0, width);
    std::memcpy(out + width - it.payload.size(), it.payload.data(), it.payload.size());
}
uint64_t rlp_u64(const zeg::rlp::Item& it) {
    uint8_t b[8];
    rlp_uint_be(it, b, 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[i];
    return v;
}
void rlp_fixed(const zeg::rlp::Item& it, uint8_t* out, size_t width) {
    if (it.kind != zeg::rlp::ItemKind::String || it.payload.size() != width) fail("header: bad fixed field");
    std::memcpy(out, it.payload.data(), width);
}

// Decode one RLP header into a 768-byte PreviousBlocks record.
uint64_t header_record(Span h, uint8_t* rec) {
    using namespace zeg::rlp;
    const Item outer = decode_item({h.p, h.n});
    if (outer.kind != ItemKind::List || outer.raw.size() != h.n) fail("header: not a list");
    Item f[24];
    size_t n = 0;
    ListIter it{outer.payload};
    while (it.has_next()) {
        if (n == 24) fail("header: too many fields");
        f[n++] = it.next();
    }
    if (n != 15 && n != 16 && n != 17 && n != 20 && n != 21 && n != 23) fail("header: field count");
    rlp_fixed(f[0], rec + 0, 32);     // parent_hash
    rlp_fixed(f[1], rec + 32, 32);    // ommers_hash
    rlp_fixed(f[2], rec + 64, 20);    // coinbase
    const uint32_t fc = uint32_t(n);
    std::memcpy(rec + 84, &fc, 4);
    rlp_fixed(f[3], rec + 88, 32);    // state_root
    rlp_fixed(f[4], rec + 120, 32);   // transactions_root
    rlp_fixed(f[5], rec + 152, 32);   // receipts_root
    rlp_fixed(f[6], rec + 184, 256);  // logs_bloom
    rlp_uint_be(f[7], rec + 440, 32); // difficulty
    const uint64_t number = rlp_u64(f[8]);
    std::memcpy(rec + 472, &number, 8);
    const uint64_t gl = rlp_u64(f[9]), gu = rlp_u64(f[10]), ts = rlp_u64(f[11]);
    std::memcpy(rec + 480, &gl, 8);
    std::memcpy(rec + 488, &gu, 8);
    std::memcpy(rec + 496, &ts, 8);
    if (f[12].kind != ItemKind::String || f[12].payload.size() > 32) fail("header: extra data");
    const uint64_t el = f[12].payload.size();
    std::memcpy(rec + 504, &el, 8);
    std::memcpy(rec + 512, f[12].payload.data(), el);
    rlp_fixed(f[13], rec + 544, 32);  // prev_randao / mix_hash
    rlp_fixed(f[14], rec + 576, 8);   // nonce
    if (n > 15) rlp_uint_be(f[15], rec + 584, 32);  // base_fee_per_gas
    if (n > 16) rlp_fixed(f[16], rec + 616, 32);    // withdrawals_root
    if (n > 17) {
        const uint64_t bgu = rlp_u64(f[17]), ebg = rlp_u64(f[18]);
        std::memcpy(rec + 648, &bgu, 8);
        std::memcpy(rec + 656, &ebg, 8);
        rlp_fixed(f[19], rec + 664, 32);  // parent_beacon_block_root
    }
    if (n > 20) rlp_fixed(f[20], rec + 696, 32);  // requests_hash
    if (n > 21) {
        rlp_fixed(f[21], rec + 728, 32);
        const uint64_t slot = rlp_u64(f[22]);
        std::memcpy(rec + 760, &slot, 8);
    }
    return number;
}

uint8_t fork_index_for_timestamp(uint64_t ts) {
    // Mainnet schedule (ProtocolFork discriminants of the stateless schema).
    if (ts >= 1767747671) return 0x14;  // BPO2
    if (ts >= 1765290071) return 0x13;  // BPO1
    if (ts >= 1764798551) return 0x12;  // Osaka
    if (ts >= 1746612311) return 0x11;  // Prague
    return 0;
}

// ---------------------------------------------------------- state glue ----
struct State {
    const Input* in = nullptr;
    stwo::NodeStore store;
    H256 parent_state_root;
    zeg::Accounts* accounts = nullptr;
    zeg::Storages* storages = nullptr;
    std::vector<H256> acct_key;       // keccak(address) per account row
    std::vector<H256> acct_sroot;     // block-start storage root per account row
    std::vector<H256> slot_key;       // keccak(position) per storage row
    bool loading = false;
} g;

uint64_t be_uint(const uint8_t* p, size_t n, size_t max) {
    if (n > max) fail("account: integer too long");
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

}  // namespace

namespace zeg {

bool stwo_lazy_load_account(Accounts& accounts, const evmc::address& addr) noexcept {
    if (g.accounts != &accounts) fail("lazy account load before state_begin");
    const H256 key = stwo::keccak(addr.bytes, 20);
    ByteView v;
    const stwo::Lookup r = stwo::trie_get(g.store, g.parent_state_root, key.b, v);
    if (r == stwo::Lookup::Missing) return false;
    uint64_t nonce = 0;
    evmc::uint256be balance{};
    evmc::bytes32 code_hash = kEmptyCodeHash;
    H256 sroot = stwo::kEmptyTrieRoot;
    if (r == stwo::Lookup::Found) {
        const rlp::Item acc = rlp::decode_item({v.p, v.n});
        if (acc.kind != rlp::ItemKind::List || acc.raw.size() != v.n) fail("account: not a list");
        rlp::ListIter it{acc.payload};
        rlp::Item f[4];
        for (int i = 0; i < 4; ++i) {
            if (!it.has_next()) fail("account: short");
            f[i] = it.next();
            if (f[i].kind != rlp::ItemKind::String) fail("account: field kind");
        }
        if (it.has_next()) fail("account: long");
        nonce = be_uint(f[0].payload.data(), f[0].payload.size(), 8);
        if (f[1].payload.size() > 32) fail("account: balance");
        std::memcpy(balance.bytes + 32 - f[1].payload.size(), f[1].payload.data(), f[1].payload.size());
        if (f[2].payload.size() != 32 || f[3].payload.size() != 32) fail("account: hash fields");
        std::memcpy(sroot.b, f[2].payload.data(), 32);
        std::memcpy(code_hash.bytes, f[3].payload.data(), 32);
    }
    const size_t idx = accounts.append(addr, nonce, balance, code_hash);
    accounts.set_storage_empty_at(idx, sroot == stwo::kEmptyTrieRoot);
    if (idx != g.acct_key.size()) fail("account row index drift");
    g.acct_key.push_back(key);
    g.acct_sroot.push_back(sroot);
    return true;
}

bool stwo_lazy_load_storage(Storages& storages, const evmc::address& addr,
                            const evmc::bytes32& position) noexcept {
    if (g.storages != &storages) fail("lazy storage load before state_begin");
    if (!g.accounts->contains(addr)) return false;
    const size_t a = g.accounts->index_of(addr);
    const H256 key = stwo::keccak(position.bytes, 32);
    ByteView v;
    const stwo::Lookup r = stwo::trie_get(g.store, g.acct_sroot[a], key.b, v);
    if (r == stwo::Lookup::Missing) return false;
    evmc::bytes32 value{};
    if (r == stwo::Lookup::Found) {
        const rlp::Item s = rlp::decode_item({v.p, v.n});
        if (s.kind != rlp::ItemKind::String || s.raw.size() != v.n || s.payload.size() > 32 ||
            s.payload.empty())
            fail("storage: bad value");
        std::memcpy(value.bytes + 32 - s.payload.size(), s.payload.data(), s.payload.size());
    }
    const size_t idx = storages.append(addr, position, value);
    if (idx != g.slot_key.size()) fail("storage row index drift");
    g.slot_key.push_back(key);
    return true;
}

void stwo_state_begin(Accounts& accounts, Storages& storages, const ConsensusInfo& consensus,
                      const PreviousBlocks& previous_blocks) {
    g.accounts = &accounts;
    g.storages = &storages;
    // The parent header is authenticated by the payload's parent_hash (checked
    // on the computed block hash); its state root anchors every lookup.
    std::memcpy(g.parent_state_root.b, previous_blocks.at(0).state_root().bytes, 32);
    // Row capacities only pre-size the vectors; rows beyond them still append.
    const uint64_t cap_a = consensus.gas_limit() / 2400 + 1024;
    const uint64_t cap_s = consensus.gas_limit() / 1900 + 1024;
    accounts.reserve(cap_a);
    storages.reserve(cap_s);
    g.acct_key.reserve(cap_a);
    g.acct_sroot.reserve(cap_a);
    g.slot_key.reserve(cap_s);
}

namespace {
size_t put_rlp_uint(uint8_t* out, const uint8_t* be, size_t width) {
    size_t i = 0;
    while (i < width && be[i] == 0) ++i;
    const size_t n = width - i;
    if (n == 0) { out[0] = 0x80; return 1; }
    if (n == 1 && be[i] < 0x80) { out[0] = be[i]; return 1; }
    out[0] = uint8_t(0x80 + n);
    std::memcpy(out + 1, be + i, n);
    return 1 + n;
}
}  // namespace

evmc::bytes32 stwo_state_new_root(Accounts& accounts, Storages& storages) {
    const size_t na = accounts.size();
    const size_t ns = storages.size();
    // Changed slots grouped by account row.
    std::vector<std::vector<size_t>> changed(na);
    for (size_t i = 0; i < ns; ++i) {
        if (storages.value_unchanged_at(i)) continue;
        changed[accounts.index_of(storages.address_at(i))].push_back(i);
    }
    stwo::MutableTrie state(g.store, g.parent_state_root);
    for (size_t a = 0; a < na; ++a) {
        H256 sroot = g.acct_sroot[a];
        bool storage_changed = false;
        if (!changed[a].empty()) {
            stwo::MutableTrie st(g.store, sroot);
            for (size_t s : changed[a]) {
                const evmc::bytes32 v = storages.value_at(s);
                uint8_t enc[33];
                const size_t n = put_rlp_uint(enc, v.bytes, 32);
                if (n == 1 && enc[0] == 0x80) st.remove(g.slot_key[s].b);
                else st.put(g.slot_key[s].b, enc, n);
            }
            const H256 nr = st.root_hash();
            storage_changed = nr != sroot;
            sroot = nr;
        }
        if (!storage_changed && accounts.fields_unchanged_at(a)) continue;
        const evmc::uint256be bal = accounts.balance_at(a);
        const uint64_t nonce = accounts.nonce_at(a);
        const evmc::bytes32 ch = accounts.code_hash_at(a);
        if (is_empty_account(nonce, bal, ch) && sroot == stwo::kEmptyTrieRoot) {
            state.remove(g.acct_key[a].b);
            continue;
        }
        uint8_t nb[8];
        for (int i = 0; i < 8; ++i) nb[i] = uint8_t(nonce >> (56 - 8 * i));
        uint8_t body[120];
        size_t k = 0;
        k += put_rlp_uint(body + k, nb, 8);
        k += put_rlp_uint(body + k, bal.bytes, 32);
        body[k++] = 0xa0;
        std::memcpy(body + k, sroot.b, 32); k += 32;
        body[k++] = 0xa0;
        std::memcpy(body + k, ch.bytes, 32); k += 32;
        uint8_t enc[124];
        size_t e = 0;
        if (k <= 55) enc[e++] = uint8_t(0xc0 + k);
        else { enc[e++] = 0xf8; enc[e++] = uint8_t(k); }
        std::memcpy(enc + e, body, k);
        state.put(g.acct_key[a].b, enc, e + k);
    }
    const H256 r = state.root_hash();
    evmc::bytes32 out;
    std::memcpy(out.bytes, r.b, 32);
    return out;
}

bool stwo_tx_sender(uint64_t index, const evmc::bytes32& hash, const evmc::uint256be& r,
                    const evmc::uint256be& s, unsigned recid, evmc::address& out) noexcept {
    const Input& in = *g.in;
    if (index >= in.public_keys.n / 65) return false;
    return stwo_secp_hint_sender(hash.bytes, r.bytes, s.bytes, recid, in.public_keys.p + 65 * index, out.bytes);
}

void stwo_after_block(const Transactions& transactions, const BlockHeader& h,
                      const evmc::bytes32& block_hash) {
    const Input& in = *g.in;
    // Every ExecutionPayloadV3 field must equal the re-executed header: the
    // execution results (state/receipts root, bloom, gas, blob gas) are taken
    // from the computation, so the payload's claims must be compared here.
    auto eq = [](const uint8_t* a, const uint8_t* b, size_t n) { return std::memcmp(a, b, n) == 0; };
    if (!eq(h.parent_hash.bytes, pl_parent_hash(in), 32)) fail("payload parent_hash mismatch");
    if (!eq(h.coinbase.bytes, pl_fee_recipient(in), 20)) fail("payload fee_recipient mismatch");
    if (!eq(h.state_root.bytes, pl_state_root(in), 32)) fail("payload state_root mismatch");
    if (!eq(h.receipts_root.bytes, pl_receipts_root(in), 32)) fail("payload receipts_root mismatch");
    if (!eq(h.logs_bloom.data(), pl_logs_bloom(in), 256)) fail("payload logs_bloom mismatch");
    if (!eq(h.prev_randao.bytes, pl_prev_randao(in), 32)) fail("payload prev_randao mismatch");
    if (h.number != pl_number(in) || h.gas_limit != pl_gas_limit(in) || h.gas_used != pl_gas_used(in) ||
        h.timestamp != pl_timestamp(in) || h.blob_gas_used != pl_blob_gas_used(in) ||
        h.excess_blob_gas != pl_excess_blob_gas(in))
        fail("payload integer field mismatch");
    if (h.extra_data.size() != in.extra_data.n || !eq(h.extra_data.data(), in.extra_data.p, in.extra_data.n))
        fail("payload extra_data mismatch");
    for (int i = 0; i < 32; ++i)
        if (h.base_fee_per_gas.bytes[i] != pl_base_fee_le(in)[31 - i]) fail("payload base_fee mismatch");
    if (!eq(h.parent_beacon_block_root.bytes, in.parent_beacon_block_root, 32)) fail("parent beacon root mismatch");
    if (!eq(h.requests_hash.bytes, requests_hash(in).bytes, 32)) fail("requests hash mismatch");
    // Every hinted sender's signature must verify (batch), else no output.
    stwo_secp_verify_pending();
    if (in.public_keys.n / 65 != transactions.size()) fail("public key count != transaction count");
    if (std::memcmp(block_hash.bytes, pl_block_hash(in), 32) != 0) fail("block hash mismatch");
    // Versioned hashes: the payload's list must equal the blob txs' hashes in order.
    size_t off = 0;
    for (size_t i = 0; i < transactions.size(); ++i) {
        const auto& tx = transactions.at(i);
        if (tx.type() != Transactions::Type::Blob) continue;
        const auto outer = rlp::decode_item(tx.blob_versioned_hashes_rlp());
        if (outer.kind != rlp::ItemKind::List) fail("blob hashes not a list");
        rlp::ListIter it{outer.payload};
        while (it.has_next()) {
            const auto item = it.next();
            if (item.kind != rlp::ItemKind::String || item.payload.size() != 32) fail("blob hash size");
            if (off + 32 > in.versioned_hashes.n ||
                std::memcmp(in.versioned_hashes.p + off, item.payload.data(), 32) != 0)
                fail("versioned hashes mismatch");
            off += 32;
        }
    }
    if (off != in.versioned_hashes.n) fail("versioned hashes count mismatch");
}

}  // namespace zeg

// -------------------------------------------------------------- entry ----
extern "C" {
extern uint8_t __input_start[];
extern uint8_t __input_end[];
extern uint8_t __halt_flag[];
extern uint8_t __output_len[];
extern uint8_t __output_data[];
}

namespace {

// Build ZEG0 sections 0-6 (everything except the StateRoot hints).
std::vector<uint64_t> build_zeg0(const Input& in, size_t& out_len) {
    // Size: magic+seed, consensus, txs, codes, headers.
    size_t total = 24 + 376 + 48 * (in.withdrawals.n / 44) + 8 + 8 + 8 + 64;
    for (size_t i = 0; i < in.txs.count; ++i) total += 16 + in.txs.at(i).n;
    for (size_t i = 0; i < in.codes.count; ++i) total += 16 + in.codes.at(i).n;
    total += 768 * in.headers.count;
    Writer w;
    w.reserve(total);
    // Section 0: magic, version, hash seed. The seed only places hash-map
    // buckets (never the output); derive it from the payload's block hash.
    w.u64(uint64_t(zeg::kMagic) | uint64_t(zeg::kVersion) << 32);
    {
        uint8_t* seed = w.zeros(16);
        std::memcpy(seed, pl_block_hash(in), 16);
    }
    // Section 1: ConsensusInfo.
    uint8_t* ci = w.zeros(376);
    // parent_hash := parent state root (ziskethone convention); filled below.
    std::memcpy(ci + 32, pl_fee_recipient(in), 20);
    const uint64_t number = pl_number(in), gas_limit = pl_gas_limit(in), ts = pl_timestamp(in);
    std::memcpy(ci + 56, &number, 8);
    std::memcpy(ci + 64, &gas_limit, 8);
    std::memcpy(ci + 72, &ts, 8);
    const uint64_t el = in.extra_data.n;
    std::memcpy(ci + 80, &el, 8);
    std::memcpy(ci + 88, in.extra_data.p, el);
    std::memcpy(ci + 120, pl_prev_randao(in), 32);
    std::memcpy(ci + 152, in.parent_beacon_block_root, 32);
    for (int i = 0; i < 32; ++i) ci[184 + i] = pl_base_fee_le(in)[31 - i];
    const uint64_t nw = in.withdrawals.n / 44;
    std::memcpy(ci + 216, &nw, 8);
    const uint64_t ebg = pl_excess_blob_gas(in);
    std::memcpy(ci + 224, &ebg, 8);
    const evmc::bytes32 rh = requests_hash(in);
    std::memcpy(ci + 232, rh.bytes, 32);
    // difficulty 0, nonce 0 (zero-filled); ommers hash = keccak(rlp([])).
    static constexpr uint8_t kEmptyOmmers[32] = {
        0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
        0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47};
    std::memcpy(ci + 304, kEmptyOmmers, 32);
    const uint64_t fork = static_cast<uint64_t>(zeg::fork_params_at(ts).fork);
    std::memcpy(ci + 336, &fork, 8);
    for (uint64_t i = 0; i < nw; ++i) {
        const uint8_t* s = in.withdrawals.p + 44 * i;
        uint8_t* d = w.zeros(48);
        std::memcpy(d, s, 16);
        std::memcpy(d + 16, s + 16, 20);
        std::memcpy(d + 40, s + 36, 8);
    }
    // Section 2: transactions (canonical envelopes, as in the payload).
    w.u64(in.txs.count);
    for (size_t i = 0; i < in.txs.count; ++i) {
        const Span t = in.txs.at(i);
        w.u64(t.n);
        w.bytes(t.p, t.n);
    }
    // Section 4: contracts.
    w.u64(in.codes.count);
    for (size_t i = 0; i < in.codes.count; ++i) {
        const Span c = in.codes.at(i);
        w.u64(c.n);
        w.bytes(c.p, c.n);
    }
    // Section 6: previous blocks, index 0 = parent (highest number first).
    const size_t nh = in.headers.count;
    if (nh == 0) fail("witness: no parent header");
    w.u64(nh);
    uint8_t* recs = w.zeros(768 * nh);
    std::vector<uint8_t> tmp(768);
    std::vector<uint64_t> numbers(nh);
    std::vector<std::vector<uint8_t>> decoded(nh);
    for (size_t i = 0; i < nh; ++i) {
        decoded[i].assign(768, 0);
        numbers[i] = header_record(in.headers.at(i), decoded[i].data());
    }
    // Order by number descending (witness order is not relied upon).
    std::vector<size_t> order(nh);
    for (size_t i = 0; i < nh; ++i) order[i] = i;
    for (size_t i = 1; i < nh; ++i)
        for (size_t j = i; j > 0 && numbers[order[j]] > numbers[order[j - 1]]; --j) {
            const size_t t = order[j]; order[j] = order[j - 1]; order[j - 1] = t;
        }
    for (size_t i = 0; i < nh; ++i) std::memcpy(recs + 768 * i, decoded[order[i]].data(), 768);
    if (numbers[order[0]] + 1 != number) fail("witness: parent header number");
    // The parent header must hash to the payload's parent_hash.
    {
        const Span ph = in.headers.at(order[0]);
        const H256 h = stwo::keccak(ph.p, ph.n);
        if (std::memcmp(h.b, pl_parent_hash(in), 32) != 0) fail("witness: parent header hash");
    }
    std::memcpy(ci + 0, recs + 88, 32);  // parent state root
    out_len = w.n;
    return std::move(w.words);
}

void write_output(const H256& root, uint64_t chain_id, uint16_t schema_id) {
    uint8_t* o = __output_data;
    std::memcpy(o, root.b, 32);
    o[32] = 1;
    for (int i = 0; i < 8; ++i) o[33 + i] = uint8_t(chain_id >> (8 * i));
    o[41] = uint8_t(schema_id);
    o[42] = uint8_t(schema_id >> 8);
    *reinterpret_cast<volatile uint32_t*>(__output_len) = 43;
    *reinterpret_cast<volatile uint32_t*>(__halt_flag) = 1;
}

}  // namespace

// Runs the whole validation on a canonical SSZ input; returns the output root.
extern "C" void stwo_validate(const uint8_t* ssz, size_t len, uint8_t out_root[32], uint64_t* chain_id,
                              uint16_t* schema_id) {
    static Input in;
    in = parse_input(ssz, len);
    g.in = &in;
    if (in.chain_id != 1) fail("chain id: only mainnet is configured");
    if (fork_index_for_timestamp(pl_timestamp(in)) != in.fork_index) fail("schema fork mismatch");
    // Index the witness trie nodes by hash.
    g.store.init(in.state_nodes.count);
    for (size_t i = 0; i < in.state_nodes.count; ++i) {
        const Span s = in.state_nodes.at(i);
        g.store.add(s.p, s.n);
    }
    size_t zlen = 0;
    std::vector<uint64_t> zeg0 = build_zeg0(in, zlen);
    uint8_t block_hash[32];
    uint8_t unused[32];
    const int rc = zeg::run(reinterpret_cast<const uint8_t*>(zeg0.data()), zlen, unused, block_hash);
    if (rc != 0) fail("run: partial stage");
    // Execution, header, block hash and payload binding all passed.
    const H256 root = request_root(in);
    std::memcpy(out_root, root.b, 32);
    *chain_id = in.chain_id;
    *schema_id = in.schema_id;
}

#if !defined(STWO_HOST)
extern "C" [[noreturn]] void stwo_guest_main() {
    const uint32_t length = *reinterpret_cast<const uint32_t*>(__input_start);
    if (length > size_t(__input_end - __input_start) - 4) fail("input length");
    uint8_t root[32];
    uint64_t chain_id = 0;
    uint16_t schema_id = 0;
    stwo_validate(__input_start + 4, length, root, &chain_id, &schema_id);
    H256 r;
    std::memcpy(r.b, root, 32);
    write_output(r, chain_id, schema_id);
    // Diagnostic only: leave the heap high-water mark in t6 (final registers).
    const size_t heap_used = stwo_heap_used();
    asm volatile("mv t6, %0\n1: j 1b" : : "r"(heap_used) : "memory");
    __builtin_unreachable();
}
#endif
