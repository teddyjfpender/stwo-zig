// Merkle-Patricia trie over the stateless witness (our code). See header.
//
// RV64IM layout notes (the guest traps on misaligned accesses and has no
// byte-swap or rotate instructions):
//   * Each witness node is hashed once (NodeStore::add) and decoded at most
//     once. A decoded branch keeps the offset of each child item inside the
//     witness bytes, found by a byte-class scan (0x80 empty, 0xa0 digest,
//     0xc0-0xf7 embedded node), and a per-child cache of the resolved node.
//   * Child digests are read in place: probes assemble the four little-endian
//     words of an unaligned digest with funnel shifts, never byte loops.
//   * Unmodified children of a mutable node are tagged pointers to their RLP
//     item in the witness bytes. A branch materialized from the witness
//     re-encodes by copying the runs of unchanged child items straight from
//     the original node encoding; only modified positions are rebuilt.
//   * Decoded and mutable nodes come from a bump arena (never freed).
#include "witness_trie.hpp"

#include <cstdlib>
#include <new>

#include <evmone_precompiles/keccak.h>

extern "C" [[noreturn]] void stwo_fatal(const char* why) noexcept;

namespace stwo {

H256 keccak(const uint8_t* data, size_t len) noexcept {
    const auto h = ethash_keccak256(data, len);
    H256 out;
    uint64_t* o = reinterpret_cast<uint64_t*>(out.b);
    o[0] = h.word64s[0];
    o[1] = h.word64s[1];
    o[2] = h.word64s[2];
    o[3] = h.word64s[3];
    return out;
}

const H256 kEmptyTrieRoot = {{0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45,
                              0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c,
                              0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21}};

namespace {

// ------------------------------------------------------------ arena ----
// Nodes live until the guest halts; a bump arena avoids per-node malloc
// headers and size-class work. Blocks are 16-byte aligned.
uint8_t* g_arena = nullptr;
size_t g_arena_left = 0;

inline void* arena_alloc(size_t n) {
    n = (n + 15) & ~size_t(15);
    if (n > g_arena_left) {
        const size_t chunk = n > (size_t(1) << 16) ? n : (size_t(1) << 16);
        g_arena = static_cast<uint8_t*>(std::malloc(chunk));
        if (!g_arena) stwo_fatal("trie arena: out of memory");
        g_arena_left = chunk;
    }
    void* p = g_arena;
    g_arena += n;
    g_arena_left -= n;
    return p;
}

// ------------------------------------------------- unaligned digests ----
inline uint64_t ldw(const uint8_t* p) { return *reinterpret_cast<const uint64_t*>(p); }

// The four little-endian words of the 32 bytes at `p` (any alignment). Reads
// only aligned words that hold at least one of those bytes.
struct W4 { uint64_t w[4]; };
inline W4 load32(const uint8_t* p) {
    W4 r;
    const unsigned off = reinterpret_cast<uintptr_t>(p) & 7;
    const uint8_t* a = p - off;
    if (off == 0) {
        r.w[0] = ldw(a); r.w[1] = ldw(a + 8); r.w[2] = ldw(a + 16); r.w[3] = ldw(a + 24);
        return r;
    }
    const unsigned sh = off * 8, rs = 64 - sh;
    const uint64_t a0 = ldw(a), a1 = ldw(a + 8), a2 = ldw(a + 16), a3 = ldw(a + 24), a4 = ldw(a + 32);
    r.w[0] = (a0 >> sh) | (a1 << rs);
    r.w[1] = (a1 >> sh) | (a2 << rs);
    r.w[2] = (a2 >> sh) | (a3 << rs);
    r.w[3] = (a3 >> sh) | (a4 << rs);
    return r;
}
inline void store_h256(H256& dst, const W4& v) {
    uint64_t* d = reinterpret_cast<uint64_t*>(dst.b);
    d[0] = v.w[0]; d[1] = v.w[1]; d[2] = v.w[2]; d[3] = v.w[3];
}

// ---------------------------------------------------------------- RLP ----
struct Item {
    bool list;
    const uint8_t* payload;
    size_t len;
    size_t raw_len;
};

inline Item decode(const uint8_t* p, const uint8_t* end) {
    if (p >= end) stwo_fatal("rlp: empty");
    const uint8_t b = p[0];
    Item it;
    size_t hdr, len;
    if (b < 0x80) {
        it.list = false; it.payload = p; it.len = 1; it.raw_len = 1;
        return it;
    } else if (b <= 0xb7) {
        it.list = false; hdr = 1; len = b - 0x80;
    } else if (b <= 0xbf) {
        it.list = false;
        const size_t ll = b - 0xb7;
        if (ll > 8 || ll > static_cast<size_t>(end - p) - 1) stwo_fatal("rlp: truncated length");
        len = 0;
        for (size_t i = 0; i < ll; ++i) len = (len << 8) | p[1 + i];
        hdr = 1 + ll;
    } else if (b <= 0xf7) {
        it.list = true; hdr = 1; len = b - 0xc0;
    } else {
        it.list = true;
        const size_t ll = b - 0xf7;
        if (ll > 8 || ll > static_cast<size_t>(end - p) - 1) stwo_fatal("rlp: truncated length");
        len = 0;
        for (size_t i = 0; i < ll; ++i) len = (len << 8) | p[1 + i];
        hdr = 1 + ll;
    }
    if (len > static_cast<size_t>(end - p) - hdr) stwo_fatal("rlp: truncated payload");
    it.payload = p + hdr;
    it.len = len;
    it.raw_len = hdr + len;
    return it;
}

inline uint8_t nibble(const uint8_t* key, size_t i) {
    return (i & 1) ? (key[i >> 1] & 0x0f) : (key[i >> 1] >> 4);
}

// Length of the child-reference item starting with byte `b`: 0x80 empty,
// 0xa0 a 32-byte digest, 0xc0-0xf7 an embedded node (short list). Any other
// form is not a valid child reference (0 = invalid).
struct ChildLenTable {
    uint8_t len[256];
    constexpr ChildLenTable() : len{} {
        len[0x80] = 1;
        len[0xa0] = 33;
        for (int b = 0xc0; b <= 0xf7; ++b) len[b] = static_cast<uint8_t>(b - 0xbf);
    }
};
constexpr ChildLenTable kChildLen{};
inline size_t child_item_len(uint8_t b) { return kChildLen.len[b]; }

}  // namespace

// --------------------------------------------------------- decoded node ----
// raw[off[i]] is the RLP item of child i (branch: i < 16, off[16] = the
// empty value item; extension: off[0]). res[i] caches the resolved child:
// nullptr = not yet resolved, kMissing = digest not in the witness.
// Leaf/extension paths stay hex-prefix encoded in the witness: `hp` points
// at the flag byte, nibble i of the path is hp_nibble(hp, i + skip) with
// skip = 1 for odd lengths and 2 for even ones.
struct DNode {
    const uint8_t* raw;
    uint32_t raw_len;
    uint8_t kind;  // 0 leaf, 1 extension, 2 branch
    uint8_t plen;
    uint16_t off[17];
    const uint8_t* hp;
    const uint8_t* value;  // leaf payload
    uint32_t vlen;
    mutable const DNode* res[16];
};

namespace {

const DNode* const kMissing = reinterpret_cast<const DNode*>(uintptr_t(8));

// Validate a hex-prefix path item; returns its nibble count.
size_t hp_check(const Item& it, bool& leaf) {
    if (it.list || it.len == 0) stwo_fatal("trie: bad path item");
    const uint8_t f = it.payload[0] >> 4;
    if (f > 3) stwo_fatal("trie: bad path flag");
    leaf = f >= 2;
    if (!(f & 1) && (it.payload[0] & 0x0f) != 0) stwo_fatal("trie: bad path padding");
    const size_t n = (it.len - 1) * 2 + (f & 1);
    if (n > 64) stwo_fatal("trie: path too long");
    return n;
}
inline uint8_t hp_nibble(const uint8_t* hp, size_t j) {
    return (j & 1) ? (hp[j >> 1] & 0x0f) : (hp[j >> 1] >> 4);
}
inline size_t hp_skip(size_t plen) { return (plen & 1) ? 1 : 2; }
void hp_unpack(const DNode* d, uint8_t* nib) {
    const size_t skip = hp_skip(d->plen);
    for (size_t i = 0; i < d->plen; ++i) nib[i] = hp_nibble(d->hp, i + skip);
}

DNode* decode_dnode(const uint8_t* p, size_t n) {
    const Item node = decode(p, p + n);
    if (!node.list || node.raw_len != n) stwo_fatal("trie: node is not a list");
    const uint8_t* q = node.payload;
    const uint8_t* end = q + node.len;
    if (q >= end) stwo_fatal("trie: empty node");
    // A branch starts with a child reference (0x80, 0xa0 or a short list), a
    // leaf/extension with a hex-prefix path string (< 0x80 or 0x81-0xa0).
    // Only 0xa0 is ambiguous (a 32-byte path): a leaf/extension then ends
    // after its second item.
    const uint8_t b0 = q[0];
    bool branch = b0 == 0x80 || b0 >= 0xc0;
    if (b0 == 0xa0) {
        if (end - q <= 33) stwo_fatal("trie: truncated node");
        const Item second = decode(q + 33, end);
        branch = q + 33 + second.raw_len != end;
    }
    DNode* d;
    if (branch) {
        d = static_cast<DNode*>(arena_alloc(sizeof(DNode)));
        d->raw = p;
        d->raw_len = static_cast<uint32_t>(n);
        d->kind = 2;
        d->plen = 0;
        for (int i = 0; i < 16; ++i) {
            if (q >= end) stwo_fatal("trie: bad node arity");
            const size_t l = child_item_len(*q);
            if (l == 0) stwo_fatal("trie: bad child reference");
            d->off[i] = static_cast<uint16_t>(q - p);
            d->res[i] = nullptr;
            q += l;
        }
        // The value slot must be the empty string and close the node.
        if (q + 1 != end || *q != 0x80) stwo_fatal("trie: bad branch value");
        d->off[16] = static_cast<uint16_t>(q - p);
        return d;
    }
    const Item first = decode(q, end);
    const Item second = decode(q + first.raw_len, end);
    if (q + first.raw_len + second.raw_len != end) stwo_fatal("trie: bad node arity");
    bool leaf;
    const size_t pn = hp_check(first, leaf);
    if (leaf) {
        if (second.list) stwo_fatal("trie: leaf value is a list");
        // Leaves never use the child offsets or cache.
        d = static_cast<DNode*>(arena_alloc(sizeof(DNode)));
        d->kind = 0;
        d->value = second.payload;
        d->vlen = static_cast<uint32_t>(second.len);
    } else {
        if (pn == 0) stwo_fatal("trie: empty extension");
        const uint8_t* c = q + first.raw_len;
        const size_t l = child_item_len(*c);
        if (l == 0 || l == 1 || l != second.raw_len) stwo_fatal("trie: bad child reference");
        d = static_cast<DNode*>(arena_alloc(sizeof(DNode)));
        d->kind = 1;
        d->off[0] = static_cast<uint16_t>(c - p);
        d->res[0] = nullptr;
    }
    d->raw = p;
    d->raw_len = static_cast<uint32_t>(n);
    d->plen = static_cast<uint8_t>(pn);
    d->hp = first.payload;
    return d;
}

// Resolve child item `c` (witness bytes) to a decoded node: nullptr when the
// item is empty, kMissing when its digest is not in the witness.
const DNode* resolve_item(const NodeStore& store, const uint8_t* c) {
    const uint8_t b = *c;
    if (b == 0x80) return nullptr;
    if (b == 0xa0) {
        NodeStore::Slot* s = store.find_bytes(c + 1);
        return s ? store.decoded(s) : kMissing;
    }
    return decode_dnode(c, size_t(b) - 0xbf);
}

// Child `i` of decoded node `d` (cached). nullptr = empty, kMissing = missing.
inline const DNode* follow(const NodeStore& store, const DNode* d, unsigned i) {
    const DNode* r = d->res[i];
    if (r) return r;
    r = resolve_item(store, d->raw + d->off[i]);
    if (r) d->res[i] = r;
    return r;
}

}  // namespace

// ---------------------------------------------------------- NodeStore ----
void NodeStore::init(size_t expected) {
    size_t cap = 16;
    while (cap < expected * 2 + 16) cap <<= 1;
    slots_ = static_cast<Slot*>(std::calloc(cap, sizeof(Slot)));
    mask_ = cap - 1;
    count_ = 0;
}

static inline size_t slot_index(uint64_t first_word) { return static_cast<size_t>(first_word); }

void NodeStore::add(const uint8_t* rlp, size_t len) {
    if (count_ * 2 >= mask_) stwo_fatal("node store overflow");
    const H256 h = keccak(rlp, len);
    size_t i = slot_index(*reinterpret_cast<const uint64_t*>(h.b)) & mask_;
    while (slots_[i].p != nullptr) {
        if (slots_[i].key == h) return;  // duplicate node
        i = (i + 1) & mask_;
    }
    slots_[i] = Slot{h, rlp, len, nullptr};
    ++count_;
}

NodeStore::Slot* NodeStore::find(const H256& h) const noexcept {
    size_t i = slot_index(*reinterpret_cast<const uint64_t*>(h.b)) & mask_;
    while (slots_[i].p != nullptr) {
        if (slots_[i].key == h) return &slots_[i];
        i = (i + 1) & mask_;
    }
    return nullptr;
}

NodeStore::Slot* NodeStore::find_bytes(const uint8_t* h32) const noexcept {
    const W4 k = load32(h32);
    size_t i = slot_index(k.w[0]) & mask_;
    while (slots_[i].p != nullptr) {
        const uint64_t* s = reinterpret_cast<const uint64_t*>(slots_[i].key.b);
        if (((s[0] ^ k.w[0]) | (s[1] ^ k.w[1]) | (s[2] ^ k.w[2]) | (s[3] ^ k.w[3])) == 0) return &slots_[i];
        i = (i + 1) & mask_;
    }
    return nullptr;
}

const DNode* NodeStore::decoded(Slot* s) const {
    if (!s->dec) s->dec = decode_dnode(s->p, s->n);
    return s->dec;
}

// -------------------------------------------------------------- lookup ----
Lookup trie_get(const NodeStore& store, const H256& root, const uint8_t key[32],
                ByteView& value) noexcept {
    if (root == kEmptyTrieRoot) return Lookup::Absent;
    NodeStore::Slot* rs = store.find(root);
    if (!rs) return Lookup::Missing;
    const DNode* d = store.decoded(rs);
    size_t depth = 0;
    for (;;) {
        unsigned next;
        if (d->kind == 2) {
            if (depth >= 64) stwo_fatal("trie: branch below key length");
            next = nibble(key, depth);
            ++depth;
        } else if (d->kind == 0) {
            // Leaf: its path must be exactly the rest of the key. With
            // depth + plen = 64 the hex-prefix bytes after the flag byte line
            // up with whole key bytes; an odd path adds the flag's low nibble.
            const size_t pn = d->plen;
            if (depth + pn != 64) return Lookup::Absent;
            const uint8_t* h = d->hp;
            size_t kb = depth >> 1;
            if (pn & 1) {
                if ((h[0] & 0x0f) != (key[kb] & 0x0f)) return Lookup::Absent;
                ++kb;
            }
            unsigned diff = 0;
            for (size_t i = 1; kb < 32; ++i, ++kb) diff |= h[i] ^ key[kb];
            if (diff) return Lookup::Absent;
            value = ByteView{d->value, d->vlen};
            return Lookup::Found;
        } else {
            const size_t pn = d->plen;
            if (depth + pn > 64) return Lookup::Absent;
            const size_t skip = hp_skip(pn);
            for (size_t i = 0; i < pn; ++i) {
                if (hp_nibble(d->hp, i + skip) != nibble(key, depth + i)) return Lookup::Absent;
            }
            depth += pn;
            next = 0;
        }
        d = follow(store, d, next);
        if (d == kMissing) return Lookup::Missing;
        if (!d) return Lookup::Absent;
    }
}

// --------------------------------------------------------- MutableTrie ----
// A child is the shared empty node, an owned mutable node (modified in place;
// `dirty` marks a cached hash as stale) or a tagged pointer (bit 63) to the
// child's RLP item in the witness bytes (0xa0 digest or an embedded node):
// untouched subtrees cost no allocation and re-encode as their original item.
// A branch owned from a witness node keeps `src` and a mask of the positions
// assigned since (`mod`); every other position still holds the original item.
// The root may be a Clean node (known hash).
struct MutableTrie::Node {
    enum Kind : uint8_t { Empty, Leaf, Ext, Branch, Clean } kind;
    bool dirty;
    bool has_hash;
    uint8_t plen;
    uint32_t vlen;
    uint16_t mod;
    H256 hash;
    const uint8_t* value;
    const DNode* src;
    Node* child[16];  // Ext uses child[0]
    uint8_t path[64];
};

namespace {
using Node = MutableTrie::Node;

constexpr uintptr_t kRefTag = uintptr_t(1) << 63;
inline bool is_ref(const Node* n) { return reinterpret_cast<uintptr_t>(n) & kRefTag; }
inline const uint8_t* ref_of(const Node* n) { return reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(n) & ~kRefTag); }
inline Node* tag(const uint8_t* item) { return reinterpret_cast<Node*>(reinterpret_cast<uintptr_t>(item) | kRefTag); }

inline Node* alloc_node(Node::Kind k) {
    Node* n = static_cast<Node*>(arena_alloc(sizeof(Node)));
    n->kind = k;
    n->dirty = true;
    n->has_hash = false;
    n->plen = 0;
    n->value = nullptr;
    n->vlen = 0;
    n->mod = 0;
    n->src = nullptr;
    return n;
}

Node g_empty_node = {Node::Empty, false, false, 0, 0, 0, {}, nullptr, nullptr, {}, {}};
inline Node* empty_node() { return &g_empty_node; }
inline bool is_empty(const Node* n) { return n == &g_empty_node; }

// Materialize a decoded witness node into an owned node (children tagged).
Node* own_dnode(const DNode* d) {
    Node* m;
    if (d->kind == 2) {
        m = alloc_node(Node::Branch);
        m->src = d;
        for (int i = 0; i < 16; ++i) {
            const uint8_t* c = d->raw + d->off[i];
            m->child[i] = *c == 0x80 ? empty_node() : tag(c);
        }
    } else if (d->kind == 1) {
        m = alloc_node(Node::Ext);
        m->plen = d->plen;
        hp_unpack(d, m->path);
        m->child[0] = tag(d->raw + d->off[0]);
    } else {
        m = alloc_node(Node::Leaf);
        m->plen = d->plen;
        hp_unpack(d, m->path);
        m->value = d->value;
        m->vlen = d->vlen;
    }
    return m;
}

// Owned form of any child (tagged ref, Clean root, or already owned).
Node* own(Node* n, const NodeStore& store) {
    if (is_ref(n)) {
        const uint8_t* c = ref_of(n);
        if (*c == 0xa0) {
            NodeStore::Slot* s = store.find_bytes(c + 1);
            if (!s) stwo_fatal("state key not in witness: trie node");
            Node* m = own_dnode(store.decoded(s));
            m->hash = s->key;
            m->has_hash = true;
            m->dirty = false;
            return m;
        }
        return own_dnode(decode_dnode(c, size_t(*c) - 0xbf));  // embedded
    }
    if (n->kind != Node::Clean) return n;
    NodeStore::Slot* s = store.find(n->hash);
    if (!s) stwo_fatal("state key not in witness: trie node");
    Node* m = own_dnode(store.decoded(s));
    m->hash = n->hash;
    m->has_hash = true;
    m->dirty = false;
    return m;
}

Node* make_leaf(const uint8_t* nib, size_t n, const uint8_t* value, size_t vlen) {
    Node* l = alloc_node(Node::Leaf);
    l->plen = static_cast<uint8_t>(n);
    std::memcpy(l->path, nib, n);
    l->value = value;
    l->vlen = static_cast<uint32_t>(vlen);
    return l;
}

Node* make_ext(const uint8_t* nib, size_t n, Node* child) {
    if (n == 0) return child;
    Node* e = alloc_node(Node::Ext);
    e->plen = static_cast<uint8_t>(n);
    std::memcpy(e->path, nib, n);
    e->child[0] = child;
    return e;
}

// Drop the first `k` nibbles of an owned leaf/extension in place.
Node* drop_prefix(Node* n, size_t k) {
    n->plen = static_cast<uint8_t>(n->plen - k);
    std::memmove(n->path, n->path + k, n->plen);
    n->dirty = true;
    if (n->kind == Node::Ext && n->plen == 0) return n->child[0];
    return n;
}

Node* split_into_branch(Node* n, const uint8_t* rest, size_t rlen, size_t c, const uint8_t* value,
                        size_t vlen) {
    Node* b = alloc_node(Node::Branch);
    for (auto& ch : b->child) ch = empty_node();
    Node* common = make_ext(rest, c, b);  // copies the common prefix before n is shortened
    const uint8_t old_nib = n->path[c];
    b->child[old_nib] = drop_prefix(n, c + 1);
    b->child[rest[c]] = make_leaf(rest + c + 1, rlen - c - 1, value, vlen);
    return common;
}

Node* insert(Node* n, const uint8_t* key, size_t depth, const uint8_t* value, size_t vlen,
             const NodeStore& store) {
    const uint8_t* rest = key + depth;
    const size_t rlen = 64 - depth;
    if (is_empty(n)) return make_leaf(rest, rlen, value, vlen);
    n = own(n, store);
    switch (n->kind) {
        case Node::Leaf: {
            size_t c = 0;
            while (c < n->plen && c < rlen && n->path[c] == rest[c]) ++c;
            if (c == n->plen && c == rlen) {
                n->value = value;
                n->vlen = static_cast<uint32_t>(vlen);
                n->dirty = true;
                return n;
            }
            if (c == n->plen || c == rlen) stwo_fatal("trie: key length mismatch");
            return split_into_branch(n, rest, rlen, c, value, vlen);
        }
        case Node::Ext: {
            size_t c = 0;
            while (c < n->plen && c < rlen && n->path[c] == rest[c]) ++c;
            if (c == n->plen) {
                n->child[0] = insert(n->child[0], key, depth + c, value, vlen, store);
                n->dirty = true;
                return n;
            }
            if (c == rlen) stwo_fatal("trie: key length mismatch");
            return split_into_branch(n, rest, rlen, c, value, vlen);
        }
        case Node::Branch:
            n->child[rest[0]] = insert(n->child[rest[0]], key, depth + 1, value, vlen, store);
            n->mod = static_cast<uint16_t>(n->mod | (1u << rest[0]));
            n->dirty = true;
            return n;
        default:
            stwo_fatal("trie: unreachable");
    }
}

// Merge a single remaining branch child `c` at nibble `i` into its parent slot.
Node* collapse_child(uint8_t i, Node* c, const NodeStore& store) {
    c = own(c, store);
    if (c->kind == Node::Leaf || c->kind == Node::Ext) {
        std::memmove(c->path + 1, c->path, c->plen);
        c->path[0] = i;
        c->plen = static_cast<uint8_t>(c->plen + 1);
        c->dirty = true;
        return c;
    }
    if (c->kind == Node::Branch) {
        uint8_t p[1] = {i};
        return make_ext(p, 1, c);
    }
    stwo_fatal("trie: collapse of empty child");
}

// Returns the new subtree; `changed` reports whether anything was removed.
Node* remove(Node* n, const uint8_t* key, size_t depth, const NodeStore& store, bool& changed) {
    changed = false;
    if (is_empty(n)) return n;
    const uint8_t* rest = key + depth;
    const size_t rlen = 64 - depth;
    Node* o = own(n, store);
    switch (o->kind) {
        case Node::Leaf:
            if (o->plen == rlen && std::memcmp(o->path, rest, rlen) == 0) {
                changed = true;
                return empty_node();
            }
            return n;
        case Node::Ext: {
            if (o->plen > rlen || std::memcmp(o->path, rest, o->plen) != 0) return n;
            Node* c = remove(o->child[0], key, depth + o->plen, store, changed);
            if (!changed) return n;
            if (is_empty(c)) return c;
            c = own(c, store);
            if (c->kind == Node::Leaf || c->kind == Node::Ext) {
                // Merge the extension path into the child.
                std::memmove(c->path + o->plen, c->path, c->plen);
                std::memcpy(c->path, o->path, o->plen);
                c->plen = static_cast<uint8_t>(c->plen + o->plen);
                c->dirty = true;
                return c;
            }
            o->child[0] = c;
            o->dirty = true;
            return o;
        }
        case Node::Branch: {
            const uint8_t nib = rest[0];
            Node* c = remove(o->child[nib], key, depth + 1, store, changed);
            if (!changed) return n;
            o->child[nib] = c;
            o->mod = static_cast<uint16_t>(o->mod | (1u << nib));
            o->dirty = true;
            int count = 0, last = -1;
            for (int i = 0; i < 16; ++i) {
                if (!is_empty(o->child[i])) { ++count; last = i; }
            }
            if (count >= 2) return o;
            if (count == 0) return empty_node();
            return collapse_child(static_cast<uint8_t>(last), o->child[last], store);
        }
        default:
            stwo_fatal("trie: unreachable");
    }
}

// ---- encoding ----
struct Buf {
    uint8_t* p;
    size_t n;
    void byte(uint8_t b) { p[n++] = b; }
    void bytes(const uint8_t* s, size_t k) {
        if (k > 8) std::memcpy(p + n, s, k);
        else for (size_t i = 0; i < k; ++i) p[n + i] = s[i];
        n += k;
    }
};

size_t len_of_len(size_t l) { size_t k = 0; while (l) { ++k; l >>= 8; } return k; }

void put_header(Buf& b, size_t len, uint8_t short_base, uint8_t long_base) {
    if (len <= 55) { b.byte(static_cast<uint8_t>(short_base + len)); return; }
    const size_t k = len_of_len(len);
    b.byte(static_cast<uint8_t>(long_base + k));
    for (size_t i = k; i-- > 0;) b.byte(static_cast<uint8_t>(len >> (8 * i)));
}
size_t header_size(size_t len) { return len <= 55 ? 1 : 1 + len_of_len(len); }

void put_string(Buf& b, const uint8_t* s, size_t len) {
    if (len == 1 && s[0] < 0x80) { b.byte(s[0]); return; }
    put_header(b, len, 0x80, 0xb7);
    b.bytes(s, len);
}
size_t string_size(const uint8_t* s, size_t len) {
    if (len == 1 && s[0] < 0x80) return 1;
    return header_size(len) + len;
}

size_t hp_encode(const uint8_t* nib, size_t n, bool leaf, uint8_t* out) {
    const uint8_t flag = leaf ? 2 : 0;
    size_t k = 0;
    if (n & 1) {
        out[k++] = static_cast<uint8_t>(((flag | 1) << 4) | nib[0]);
        for (size_t i = 1; i < n; i += 2) out[k++] = static_cast<uint8_t>((nib[i] << 4) | nib[i + 1]);
    } else {
        out[k++] = static_cast<uint8_t>(flag << 4);
        for (size_t i = 0; i < n; i += 2) out[k++] = static_cast<uint8_t>((nib[i] << 4) | nib[i + 1]);
    }
    return k;
}

size_t encode(Node* n, uint8_t* out, const NodeStore& store);

// The RLP item referencing child `n` (not empty): either `len` raw bytes at
// `p` (a witness item, or an embedded encoding in `emb`), or, with `len` 0,
// a digest at `p` (written as 0xa0 + 32 bytes).
struct ItemRef {
    const uint8_t* p;
    size_t len;
    size_t size() const { return len ? len : 33; }
};

ItemRef child_ref(Node* n, uint8_t emb[32], const NodeStore& store) {
    if (is_ref(n)) {
        const uint8_t* c = ref_of(n);
        return ItemRef{c, *c == 0xa0 ? size_t(33) : size_t(*c) - 0xbf};
    }
    if (n->kind == Node::Clean) n = own(n, store);
    if (!(n->has_hash && !n->dirty)) {
        alignas(8) uint8_t buf[600];
        const size_t len = encode(n, buf, store);
        if (len < 32) {
            for (size_t i = 0; i < len; ++i) emb[i] = buf[i];
            return ItemRef{emb, len};
        }
        n->hash = keccak(buf, len);
        n->has_hash = true;
        n->dirty = false;
    }
    return ItemRef{n->hash.b, 0};
}

inline void put_item(Buf& b, const ItemRef& r) {
    if (r.len) { b.bytes(r.p, r.len); return; }
    uint8_t* d = b.p + b.n;
    d[0] = 0xa0;
    std::memcpy(d + 1, r.p, 32);
    b.n += 33;
}

// Encode node `n` (Leaf/Ext/Branch) into `out` (>= 600 bytes).
size_t encode(Node* n, uint8_t* out, const NodeStore& store) {
    Buf b{out, 0};
    if (n->kind == Node::Branch) {
        uint8_t emb[16][32];
        ItemRef ref[16];
        if (const DNode* s = n->src) {
            // Positions not in `mod` still hold their original item: copy the
            // runs between modified positions from the witness encoding.
            const uint8_t* raw = s->raw;
            const unsigned mod = n->mod;
            size_t payload = s->raw_len - s->off[0];
            for (unsigned i = 0; i < 16; ++i) {
                if (!(mod >> i & 1)) continue;
                payload -= s->off[i + 1] - s->off[i];
                Node* c = n->child[i];
                if (is_empty(c)) ref[i] = ItemRef{nullptr, 1};
                else ref[i] = child_ref(c, emb[i], store);
                payload += ref[i].size();
            }
            put_header(b, payload, 0xc0, 0xf7);
            size_t run = s->off[0];
            for (unsigned i = 0; i < 16; ++i) {
                if (!(mod >> i & 1)) continue;
                if (s->off[i] > run) b.bytes(raw + run, s->off[i] - run);
                if (ref[i].p == nullptr) b.byte(0x80);
                else put_item(b, ref[i]);
                run = s->off[i + 1];
            }
            b.bytes(raw + run, s->raw_len - run);  // includes the empty value item
            return b.n;
        }
        size_t payload = 1;  // the empty value slot
        for (int i = 0; i < 16; ++i) {
            Node* c = n->child[i];
            if (is_empty(c)) { ref[i] = ItemRef{nullptr, 1}; payload += 1; continue; }
            ref[i] = child_ref(c, emb[i], store);
            payload += ref[i].size();
        }
        put_header(b, payload, 0xc0, 0xf7);
        for (int i = 0; i < 16; ++i) {
            if (ref[i].p == nullptr) b.byte(0x80);
            else put_item(b, ref[i]);
        }
        b.byte(0x80);
        return b.n;
    }
    uint8_t hpath[33];
    const size_t hpn = hp_encode(n->path, n->plen, n->kind == Node::Leaf, hpath);
    if (n->kind == Node::Leaf) {
        const size_t payload = string_size(hpath, hpn) + string_size(n->value, n->vlen);
        put_header(b, payload, 0xc0, 0xf7);
        put_string(b, hpath, hpn);
        put_string(b, n->value, n->vlen);
        return b.n;
    }
    uint8_t emb[32];
    const ItemRef r = child_ref(n->child[0], emb, store);
    const size_t payload = string_size(hpath, hpn) + r.size();
    put_header(b, payload, 0xc0, 0xf7);
    put_string(b, hpath, hpn);
    put_item(b, r);
    return b.n;
}

void unpack(const uint8_t key[32], uint8_t nib[64]) {
    for (int i = 0; i < 32; ++i) {
        nib[2 * i] = key[i] >> 4;
        nib[2 * i + 1] = key[i] & 0x0f;
    }
}

}  // namespace

MutableTrie::MutableTrie(const NodeStore& store, const H256& root) noexcept : store_(store) {
    if (root == kEmptyTrieRoot) {
        root_ = empty_node();
    } else {
        root_ = alloc_node(Node::Clean);
        root_->hash = root;
        root_->has_hash = true;
        root_->dirty = false;
    }
}

void MutableTrie::put(const uint8_t key[32], const uint8_t* value, size_t len) {
    uint8_t* v = static_cast<uint8_t*>(arena_alloc(len ? len : 1));
    for (size_t i = 0; i < len; ++i) v[i] = value[i];
    uint8_t nib[64];
    unpack(key, nib);
    root_ = insert(root_, nib, 0, v, len, store_);
}

void MutableTrie::remove(const uint8_t key[32]) {
    uint8_t nib[64];
    unpack(key, nib);
    bool changed;
    root_ = stwo::remove(root_, nib, 0, store_, changed);
}

H256 MutableTrie::root_hash() {
    if (is_empty(root_)) return kEmptyTrieRoot;
    if (is_ref(root_)) {
        // A collapse can leave a witness child as the root.
        root_ = own(root_, store_);
    }
    if (root_->has_hash && !root_->dirty) return root_->hash;
    Node* r = own(root_, store_);
    alignas(8) uint8_t buf[600];
    const size_t len = encode(r, buf, store_);
    return keccak(buf, len);
}

}  // namespace stwo
