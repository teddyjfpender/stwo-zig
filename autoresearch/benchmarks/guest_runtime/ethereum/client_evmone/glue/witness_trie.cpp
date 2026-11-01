// Merkle-Patricia trie over the stateless witness (our code). See header.
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

inline uint64_t ld8_unaligned(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
inline void copy32_from_bytes(H256& dst, const uint8_t* src) {
    uint64_t* d = reinterpret_cast<uint64_t*>(dst.b);
    if ((reinterpret_cast<uintptr_t>(src) & 7) == 0) {
        const uint64_t* s = reinterpret_cast<const uint64_t*>(src);
        d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3];
    } else {
        d[0] = ld8_unaligned(src); d[1] = ld8_unaligned(src + 8);
        d[2] = ld8_unaligned(src + 16); d[3] = ld8_unaligned(src + 24);
    }
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
        if (p + 1 + ll > end) stwo_fatal("rlp: truncated length");
        len = 0;
        for (size_t i = 0; i < ll; ++i) len = (len << 8) | p[1 + i];
        hdr = 1 + ll;
    } else if (b <= 0xf7) {
        it.list = true; hdr = 1; len = b - 0xc0;
    } else {
        it.list = true;
        const size_t ll = b - 0xf7;
        if (p + 1 + ll > end) stwo_fatal("rlp: truncated length");
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

}  // namespace

// --------------------------------------------------------- decoded node ----
// A child reference of a witness node: empty, a 32-byte hash (slot resolved
// lazily) or an embedded node (< 32 bytes, decoded lazily).
struct CRef {
    uint8_t type;  // 0 empty, 1 hash, 2 embedded
    mutable bool missing;  // type 1: lookup failed
    uint32_t len;
    const uint8_t* p;
    // type 1: resolved slot (nullptr until looked up); type 2: decoded node.
    mutable union {
        NodeStore::Slot* slot;
        const DNode* emb;
    } u;
};

struct DNode {
    uint8_t kind;  // 0 leaf, 1 extension, 2 branch
    uint8_t plen;
    uint8_t path[64];
    const uint8_t* value;  // leaf payload
    uint32_t vlen;
    CRef child[16];  // ext uses child[0]
};

namespace {

void hp_decode(const Item& it, uint8_t* nib, size_t& n, bool& leaf) {
    if (it.list || it.len == 0) stwo_fatal("trie: bad path item");
    const uint8_t f = it.payload[0] >> 4;
    if (f > 3) stwo_fatal("trie: bad path flag");
    leaf = f >= 2;
    n = 0;
    if (f & 1) nib[n++] = it.payload[0] & 0x0f;
    else if ((it.payload[0] & 0x0f) != 0) stwo_fatal("trie: bad path padding");
    if ((it.len - 1) * 2 + n > 64) stwo_fatal("trie: path too long");
    for (size_t i = 1; i < it.len; ++i) {
        nib[n++] = it.payload[i] >> 4;
        nib[n++] = it.payload[i] & 0x0f;
    }
}

CRef make_cref(const Item& it) {
    CRef r{};
    if (it.list) {
        r.type = 2;
        r.p = it.payload - (it.raw_len - it.len);
        r.len = static_cast<uint32_t>(it.raw_len);
    } else if (it.len == 0) {
        r.type = 0;
    } else if (it.len == 32) {
        r.type = 1;
        r.p = it.payload;
        r.len = 32;
    } else {
        stwo_fatal("trie: bad child reference");
    }
    return r;
}

DNode* decode_dnode(const uint8_t* p, size_t n) {
    const Item node = decode(p, p + n);
    if (!node.list || node.raw_len != n) stwo_fatal("trie: node is not a list");
    DNode* d = static_cast<DNode*>(std::malloc(sizeof(DNode)));
    const uint8_t* q = node.payload;
    const uint8_t* end = q + node.len;
    Item parts[3];
    size_t count = 0;
    // Peek: a branch has 17 items, leaf/extension 2.
    Item first = decode(q, end);
    Item second = decode(q + first.raw_len, end);
    const uint8_t* after2 = q + first.raw_len + second.raw_len;
    if (after2 == end) {
        parts[0] = first;
        parts[1] = second;
        count = 2;
        size_t pn;
        bool leaf;
        hp_decode(parts[0], d->path, pn, leaf);
        d->plen = static_cast<uint8_t>(pn);
        if (leaf) {
            if (parts[1].list) stwo_fatal("trie: leaf value is a list");
            d->kind = 0;
            d->value = parts[1].payload;
            d->vlen = static_cast<uint32_t>(parts[1].len);
        } else {
            if (pn == 0) stwo_fatal("trie: empty extension");
            d->kind = 1;
            d->child[0] = make_cref(parts[1]);
        }
        return d;
    }
    d->kind = 2;
    d->plen = 0;
    d->child[0] = make_cref(first);
    d->child[1] = make_cref(second);
    q = after2;
    for (int i = 2; i < 16; ++i) {
        const Item it = decode(q, end);
        d->child[i] = make_cref(it);
        q += it.raw_len;
    }
    const Item v = decode(q, end);
    if (v.list || v.len != 0) stwo_fatal("trie: branch with value");
    if (q + v.raw_len != end) stwo_fatal("trie: bad node arity");
    (void)count;
    return d;
}

// Resolve a child reference to a decoded node; nullptr = empty; *missing set
// when the hash is not in the witness.
const DNode* follow(const NodeStore& store, const CRef& c, bool& missing) {
    missing = false;
    if (c.type == 0) return nullptr;
    if (c.type == 2) {
        if (!c.u.emb) c.u.emb = decode_dnode(c.p, c.len);
        return c.u.emb;
    }
    if (!c.u.slot) {
        if (c.missing) { missing = true; return nullptr; }
        c.u.slot = store.find_bytes(c.p);
        if (!c.u.slot) { c.missing = true; missing = true; return nullptr; }
    }
    return store.decoded(c.u.slot);
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
    H256 h;
    copy32_from_bytes(h, h32);
    return find(h);
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
        const CRef* next;
        if (d->kind == 2) {
            if (depth >= 64) stwo_fatal("trie: branch below key length");
            next = &d->child[nibble(key, depth)];
            ++depth;
        } else {
            const size_t pn = d->plen;
            if (depth + pn > 64) return Lookup::Absent;
            for (size_t i = 0; i < pn; ++i) {
                if (d->path[i] != nibble(key, depth + i)) return Lookup::Absent;
            }
            depth += pn;
            if (d->kind == 0) {
                if (depth != 64) return Lookup::Absent;
                value = ByteView{d->value, d->vlen};
                return Lookup::Found;
            }
            next = &d->child[0];
        }
        bool missing;
        d = follow(store, *next, missing);
        if (missing) return Lookup::Missing;
        if (!d) return Lookup::Absent;
    }
}

// --------------------------------------------------------- MutableTrie ----
// Children are either owned mutable nodes (modified in place; `dirty` marks a
// cached hash as stale) or tagged pointers to a witness node's raw child
// reference (low bit set): untouched subtrees cost no allocation and encode as
// their original RLP reference. The root may be a Clean node (known hash).
struct MutableTrie::Node {
    enum Kind : uint8_t { Empty, Leaf, Ext, Branch, Clean } kind;
    bool dirty;
    bool has_hash;
    uint8_t plen;
    uint32_t vlen;
    H256 hash;
    const uint8_t* value;
    Node* child[16];  // Ext uses child[0]
    uint8_t path[64];
};

namespace {
using Node = MutableTrie::Node;

inline bool is_cref(const Node* n) { return reinterpret_cast<uintptr_t>(n) & 1; }
inline const CRef* cref_of(const Node* n) { return reinterpret_cast<const CRef*>(reinterpret_cast<uintptr_t>(n) & ~uintptr_t(1)); }
inline Node* tag(const CRef* c) { return reinterpret_cast<Node*>(reinterpret_cast<uintptr_t>(c) | 1); }

inline Node* alloc_node(Node::Kind k) {
    Node* n = static_cast<Node*>(std::malloc(sizeof(Node)));
    n->kind = k;
    n->dirty = true;
    n->has_hash = false;
    n->plen = 0;
    n->value = nullptr;
    n->vlen = 0;
    return n;
}

Node g_empty_node = {Node::Empty, false, false, 0, 0, {}, nullptr, {}, {}};
inline Node* empty_node() { return &g_empty_node; }
inline bool is_empty(const Node* n) { return !is_cref(n) && n->kind == Node::Empty; }

inline Node* child_of(const CRef& c) { return c.type == 0 ? empty_node() : tag(&c); }

// Materialize a decoded witness node into an owned node (children tagged).
Node* own_dnode(const DNode* d) {
    Node* m;
    if (d->kind == 2) {
        m = alloc_node(Node::Branch);
        for (int i = 0; i < 16; ++i) m->child[i] = child_of(d->child[i]);
    } else if (d->kind == 1) {
        m = alloc_node(Node::Ext);
        m->plen = d->plen;
        std::memcpy(m->path, d->path, d->plen);
        m->child[0] = child_of(d->child[0]);
    } else {
        m = alloc_node(Node::Leaf);
        m->plen = d->plen;
        std::memcpy(m->path, d->path, d->plen);
        m->value = d->value;
        m->vlen = d->vlen;
    }
    return m;
}

// Owned form of any child (tagged ref, Clean root, or already owned).
Node* own(Node* n, const NodeStore& store) {
    if (is_cref(n)) {
        const CRef* c = cref_of(n);
        bool missing;
        const DNode* d = follow(store, *c, missing);
        if (missing || !d) stwo_fatal("state key not in witness: trie node");
        Node* m = own_dnode(d);
        if (c->type == 1) {
            copy32_from_bytes(m->hash, c->p);
            m->has_hash = true;
            m->dirty = false;
        }
        return m;
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

// Child reference: returns 0 when the child is referenced by hash (`hash`
// receives a pointer to the 32 bytes) or the embedded encoding length.
size_t child_ref(Node* n, uint8_t emb[32], const uint8_t*& hash, const NodeStore& store) {
    if (is_cref(n)) {
        const CRef* c = cref_of(n);
        if (c->type == 1) { hash = c->p; return 0; }
        for (uint32_t i = 0; i < c->len; ++i) emb[i] = c->p[i];  // embedded: raw RLP
        return c->len;
    }
    if (n->kind == Node::Clean) n = own(n, store);
    if (!(n->has_hash && !n->dirty)) {
        uint8_t buf[600];
        const size_t len = encode(n, buf, store);
        if (len < 32) {
            for (size_t i = 0; i < len; ++i) emb[i] = buf[i];
            return len;
        }
        n->hash = keccak(buf, len);
        n->has_hash = true;
        n->dirty = false;
    }
    hash = n->hash.b;
    return 0;
}

inline void put_hash(Buf& b, const uint8_t* h) {
    uint8_t* d = b.p + b.n;
    d[0] = 0xa0;
    std::memcpy(d + 1, h, 32);
    b.n += 33;
}

// Encode node `n` (Leaf/Ext/Branch) into `out` (>= 600 bytes).
size_t encode(Node* n, uint8_t* out, const NodeStore& store) {
    Buf b{out, 0};
    if (n->kind == Node::Branch) {
        uint8_t emb[16][32];
        uint8_t elen[16];
        const uint8_t* hp[16];
        size_t payload = 1;  // the empty value slot
        for (int i = 0; i < 16; ++i) {
            Node* c = n->child[i];
            if (is_empty(c)) { elen[i] = 255; payload += 1; continue; }
            const size_t e = child_ref(c, emb[i], hp[i], store);
            elen[i] = static_cast<uint8_t>(e);
            payload += e ? e : 33;
        }
        put_header(b, payload, 0xc0, 0xf7);
        for (int i = 0; i < 16; ++i) {
            if (elen[i] == 255) b.byte(0x80);
            else if (elen[i]) b.bytes(emb[i], elen[i]);
            else put_hash(b, hp[i]);
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
    const uint8_t* h = nullptr;
    const size_t e = child_ref(n->child[0], emb, h, store);
    const size_t payload = string_size(hpath, hpn) + (e ? e : 33);
    put_header(b, payload, 0xc0, 0xf7);
    put_string(b, hpath, hpn);
    if (e) b.bytes(emb, e);
    else put_hash(b, h);
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
    uint8_t* v = static_cast<uint8_t*>(std::malloc(len ? len : 1));
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
    if (is_cref(root_)) {
        // A collapse can leave a witness child as the root.
        root_ = own(root_, store_);
    }
    if (root_->has_hash && !root_->dirty) return root_->hash;
    Node* r = own(root_, store_);
    uint8_t buf[600];
    const size_t len = encode(r, buf, store_);
    return keccak(buf, len);
}

}  // namespace stwo
