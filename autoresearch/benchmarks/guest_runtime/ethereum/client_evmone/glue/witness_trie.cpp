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
    std::memcpy(out.b, h.bytes, 32);
    return out;
}

const H256 kEmptyTrieRoot = {{0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45,
                              0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c,
                              0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21}};

// ---------------------------------------------------------------- RLP ----
namespace {

struct Item {
    bool list;
    const uint8_t* payload;
    size_t len;
    const uint8_t* raw;
    size_t raw_len;
};

// Decode one item at p (bounded by end). Fatal on malformed input.
Item decode(const uint8_t* p, const uint8_t* end) {
    if (p >= end) stwo_fatal("rlp: empty");
    const uint8_t b = p[0];
    Item it{};
    it.raw = p;
    size_t hdr, len;
    if (b < 0x80) {
        it.list = false;
        it.payload = p;
        it.len = 1;
        it.raw_len = 1;
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

// Split a list payload into up to `max` items; returns the count.
size_t items(const Item& list, Item* out, size_t max) {
    const uint8_t* p = list.payload;
    const uint8_t* end = p + list.len;
    size_t n = 0;
    while (p < end) {
        if (n == max) stwo_fatal("rlp: too many list items");
        out[n] = decode(p, end);
        p += out[n].raw_len;
        ++n;
    }
    return n;
}

inline uint8_t nibble(const uint8_t* key, size_t i) {
    return (i & 1) ? (key[i >> 1] & 0x0f) : (key[i >> 1] >> 4);
}

// Hex-prefix decode: returns is_leaf, writes nibbles.
bool hp_decode(const Item& it, uint8_t* nib, size_t& n) {
    if (it.list || it.len == 0) stwo_fatal("trie: bad path item");
    const uint8_t f = it.payload[0] >> 4;
    if (f > 3) stwo_fatal("trie: bad path flag");
    const bool leaf = f >= 2;
    n = 0;
    if (f & 1) nib[n++] = it.payload[0] & 0x0f;
    else if ((it.payload[0] & 0x0f) != 0) stwo_fatal("trie: bad path padding");
    if ((it.len - 1) * 2 + n > 64) stwo_fatal("trie: path too long");
    for (size_t i = 1; i < it.len; ++i) {
        nib[n++] = it.payload[i] >> 4;
        nib[n++] = it.payload[i] & 0x0f;
    }
    return leaf;
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

static inline size_t slot_hash(const H256& h) {
    uint64_t v;
    std::memcpy(&v, h.b, 8);
    return static_cast<size_t>(v);
}

void NodeStore::add(const uint8_t* rlp, size_t len) {
    if (count_ * 2 >= mask_) stwo_fatal("node store overflow");
    const H256 h = keccak(rlp, len);
    size_t i = slot_hash(h) & mask_;
    while (slots_[i].p != nullptr) {
        if (slots_[i].key == h) return;  // duplicate node
        i = (i + 1) & mask_;
    }
    slots_[i] = Slot{h, rlp, len};
    ++count_;
}

bool NodeStore::find(const H256& h, ByteView& out) const noexcept {
    size_t i = slot_hash(h) & mask_;
    while (slots_[i].p != nullptr) {
        if (slots_[i].key == h) {
            out = ByteView{slots_[i].p, slots_[i].n};
            return true;
        }
        i = (i + 1) & mask_;
    }
    return false;
}

// -------------------------------------------------------------- lookup ----
Lookup trie_get(const NodeStore& store, const H256& root, const uint8_t key[32],
                ByteView& value) noexcept {
    if (root == kEmptyTrieRoot) return Lookup::Absent;
    ByteView raw;
    if (!store.find(root, raw)) return Lookup::Missing;
    Item node = decode(raw.p, raw.p + raw.n);
    size_t depth = 0;
    Item parts[17];
    uint8_t nib[64];
    for (;;) {
        if (!node.list) stwo_fatal("trie: node is not a list");
        const size_t n = items(node, parts, 17);
        Item child;
        if (n == 17) {
            if (depth >= 64) stwo_fatal("trie: branch below key length");
            child = parts[nibble(key, depth)];
            ++depth;
        } else if (n == 2) {
            size_t pn;
            const bool leaf = hp_decode(parts[0], nib, pn);
            if (depth + pn > 64) return Lookup::Absent;
            for (size_t i = 0; i < pn; ++i) {
                if (nib[i] != nibble(key, depth + i)) return Lookup::Absent;
            }
            depth += pn;
            if (leaf) {
                if (depth != 64) return Lookup::Absent;
                if (parts[1].list) stwo_fatal("trie: leaf value is a list");
                value = ByteView{parts[1].payload, parts[1].len};
                return Lookup::Found;
            }
            child = parts[1];
        } else {
            stwo_fatal("trie: bad node arity");
        }
        // Follow the child reference.
        if (child.list) {
            node = child;  // embedded node
        } else if (child.len == 0) {
            return Lookup::Absent;
        } else if (child.len == 32) {
            H256 h;
            std::memcpy(h.b, child.payload, 32);
            if (!store.find(h, raw)) return Lookup::Missing;
            node = decode(raw.p, raw.p + raw.n);
        } else {
            stwo_fatal("trie: bad child reference");
        }
    }
}

// --------------------------------------------------------- MutableTrie ----
struct MutableTrie::Node {
    enum Kind : uint8_t { Empty, Leaf, Ext, Branch, HashRef } kind;
    bool dirty;       // modified since resolution (hash must be recomputed)
    bool has_hash;    // `hash` is the keccak of this node's encoding
    uint8_t plen;
    uint8_t path[64];
    H256 hash;
    const uint8_t* value;  // Leaf payload
    size_t vlen;
    Node* child[16];       // Ext uses child[0]
};

namespace {
using Node = MutableTrie::Node;

Node* new_node(Node::Kind k) {
    Node* n = static_cast<Node*>(std::malloc(sizeof(Node)));
    n->kind = k;
    n->dirty = true;
    n->has_hash = false;
    n->plen = 0;
    n->value = nullptr;
    n->vlen = 0;
    for (auto& c : n->child) c = nullptr;
    return n;
}

Node* g_empty = nullptr;
Node* empty_node() {
    if (!g_empty) {
        g_empty = new_node(Node::Empty);
        g_empty->dirty = false;
    }
    return g_empty;
}

Node* from_item(const Item& it, const NodeStore& store);

// Decode a node's RLP list into a Node whose children are HashRef / embedded.
Node* decode_node(const Item& node, const NodeStore& store) {
    if (!node.list) stwo_fatal("trie: node is not a list");
    Item parts[17];
    const size_t n = items(node, parts, 17);
    if (n == 17) {
        Node* b = new_node(Node::Branch);
        for (int i = 0; i < 16; ++i) b->child[i] = from_item(parts[i], store);
        if (parts[16].list || parts[16].len != 0) stwo_fatal("trie: branch with value");
        return b;
    }
    if (n != 2) stwo_fatal("trie: bad node arity");
    size_t pn;
    uint8_t nib[64];
    const bool leaf = hp_decode(parts[0], nib, pn);
    Node* x = new_node(leaf ? Node::Leaf : Node::Ext);
    x->plen = static_cast<uint8_t>(pn);
    std::memcpy(x->path, nib, pn);
    if (leaf) {
        if (parts[1].list) stwo_fatal("trie: leaf value is a list");
        x->value = parts[1].payload;
        x->vlen = parts[1].len;
    } else {
        if (pn == 0) stwo_fatal("trie: empty extension");
        x->child[0] = from_item(parts[1], store);
    }
    return x;
}

Node* from_item(const Item& it, const NodeStore& store) {
    if (it.list) {
        Node* e = decode_node(it, store);
        e->dirty = false;
        return e;
    }
    if (it.len == 0) return empty_node();
    if (it.len != 32) stwo_fatal("trie: bad child reference");
    Node* h = new_node(Node::HashRef);
    std::memcpy(h->hash.b, it.payload, 32);
    h->has_hash = true;
    h->dirty = false;
    return h;
}

// Resolve a HashRef in place (keeps the pointer identity of the parent slot).
Node* resolve(Node* n, const NodeStore& store) {
    if (n->kind != Node::HashRef) return n;
    ByteView raw;
    if (!store.find(n->hash, raw)) stwo_fatal("state key not in witness: trie node");
    Item it = decode(raw.p, raw.p + raw.n);
    Node* r = decode_node(it, store);
    r->dirty = false;
    r->has_hash = true;
    r->hash = n->hash;
    return r;
}

Node* make_leaf(const uint8_t* nib, size_t n, const uint8_t* value, size_t vlen) {
    Node* l = new_node(Node::Leaf);
    l->plen = static_cast<uint8_t>(n);
    std::memcpy(l->path, nib, n);
    l->value = value;
    l->vlen = vlen;
    return l;
}

Node* make_ext(const uint8_t* nib, size_t n, Node* child) {
    if (n == 0) return child;
    Node* e = new_node(Node::Ext);
    e->plen = static_cast<uint8_t>(n);
    std::memcpy(e->path, nib, n);
    e->child[0] = child;
    return e;
}

// Shorten a leaf/ext's path by dropping its first `k` nibbles (copy-on-write).
Node* drop_prefix(Node* n, size_t k) {
    Node* c = new_node(n->kind);
    *c = *n;
    c->dirty = true;
    c->has_hash = false;
    c->plen = static_cast<uint8_t>(n->plen - k);
    std::memmove(c->path, n->path + k, c->plen);
    if (c->kind == Node::Ext && c->plen == 0) return c->child[0];
    return c;
}

Node* insert(Node* n, const uint8_t* key, size_t depth, const uint8_t* value, size_t vlen,
             const NodeStore& store) {
    n = resolve(n, store);
    const uint8_t* rest = key + depth;
    const size_t rlen = 64 - depth;
    switch (n->kind) {
        case Node::Empty:
            return make_leaf(rest, rlen, value, vlen);
        case Node::Leaf: {
            size_t c = 0;
            while (c < n->plen && c < rlen && n->path[c] == rest[c]) ++c;
            if (c == n->plen && c == rlen) {
                Node* l = make_leaf(n->path, n->plen, value, vlen);
                return l;
            }
            if (c == n->plen || c == rlen) stwo_fatal("trie: key length mismatch");
            Node* b = new_node(Node::Branch);
            for (auto& ch : b->child) ch = empty_node();
            b->child[n->path[c]] = drop_prefix(n, c + 1);
            b->child[rest[c]] = make_leaf(rest + c + 1, rlen - c - 1, value, vlen);
            return make_ext(rest, c, b);
        }
        case Node::Ext: {
            size_t c = 0;
            while (c < n->plen && c < rlen && n->path[c] == rest[c]) ++c;
            if (c == n->plen) {
                Node* e = new_node(Node::Ext);
                *e = *n;
                e->dirty = true;
                e->has_hash = false;
                e->child[0] = insert(n->child[0], key, depth + c, value, vlen, store);
                return e;
            }
            if (c == rlen) stwo_fatal("trie: key length mismatch");
            Node* b = new_node(Node::Branch);
            for (auto& ch : b->child) ch = empty_node();
            b->child[n->path[c]] = drop_prefix(n, c + 1);
            b->child[rest[c]] = make_leaf(rest + c + 1, rlen - c - 1, value, vlen);
            return make_ext(rest, c, b);
        }
        case Node::Branch: {
            Node* b = new_node(Node::Branch);
            *b = *n;
            b->dirty = true;
            b->has_hash = false;
            b->child[rest[0]] = insert(n->child[rest[0]], key, depth + 1, value, vlen, store);
            return b;
        }
        default:
            stwo_fatal("trie: unreachable");
    }
}

// Merge a single remaining branch child `c` at nibble `i` into its parent slot.
Node* collapse_child(uint8_t i, Node* c, const NodeStore& store) {
    c = resolve(c, store);
    if (c->kind == Node::Leaf || c->kind == Node::Ext) {
        Node* m = new_node(c->kind);
        *m = *c;
        m->dirty = true;
        m->has_hash = false;
        m->plen = static_cast<uint8_t>(c->plen + 1);
        m->path[0] = i;
        std::memcpy(m->path + 1, c->path, c->plen);
        return m;
    }
    if (c->kind == Node::Branch) {
        uint8_t p[1] = {i};
        return make_ext(p, 1, c);
    }
    stwo_fatal("trie: collapse of empty child");
}

Node* remove(Node* n, const uint8_t* key, size_t depth, const NodeStore& store) {
    if (n->kind == Node::Empty) return n;
    n = resolve(n, store);
    const uint8_t* rest = key + depth;
    const size_t rlen = 64 - depth;
    switch (n->kind) {
        case Node::Leaf:
            if (n->plen == rlen && std::memcmp(n->path, rest, rlen) == 0) return empty_node();
            return n;  // absent
        case Node::Ext: {
            if (n->plen > rlen || std::memcmp(n->path, rest, n->plen) != 0) return n;
            Node* c = remove(n->child[0], key, depth + n->plen, store);
            if (c == n->child[0]) return n;
            if (c->kind == Node::Empty) return c;
            c = resolve(c, store);
            if (c->kind == Node::Leaf || c->kind == Node::Ext) {
                Node* m = new_node(c->kind);
                *m = *c;
                m->dirty = true;
                m->has_hash = false;
                m->plen = static_cast<uint8_t>(n->plen + c->plen);
                std::memcpy(m->path, n->path, n->plen);
                std::memcpy(m->path + n->plen, c->path, c->plen);
                return m;
            }
            Node* e = new_node(Node::Ext);
            *e = *n;
            e->dirty = true;
            e->has_hash = false;
            e->child[0] = c;
            return e;
        }
        case Node::Branch: {
            Node* old = n->child[rest[0]];
            Node* c = remove(old, key, depth + 1, store);
            if (c == old) return n;
            Node* b = new_node(Node::Branch);
            *b = *n;
            b->dirty = true;
            b->has_hash = false;
            b->child[rest[0]] = c;
            int count = 0, last = -1;
            for (int i = 0; i < 16; ++i) {
                if (b->child[i]->kind != Node::Empty) { ++count; last = i; }
            }
            if (count >= 2) return b;
            if (count == 0) return empty_node();
            return collapse_child(static_cast<uint8_t>(last), b->child[last], store);
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
    void bytes(const uint8_t* s, size_t k) { std::memcpy(p + n, s, k); n += k; }
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

// A child reference: either a 32-byte hash or an embedded encoding (< 32 B).
struct Ref {
    bool embedded;
    uint8_t len;
    uint8_t data[32];
};

Ref ref_of(Node* n, const NodeStore& store);

// Encode node `n` (not Empty/HashRef) into `out` (>= 1100 bytes).
size_t encode(Node* n, uint8_t* out, const NodeStore& store) {
    Buf b{out, 0};
    if (n->kind == Node::Branch) {
        Ref refs[16];
        size_t payload = 1;  // the empty value slot
        for (int i = 0; i < 16; ++i) {
            if (n->child[i]->kind == Node::Empty) { refs[i].embedded = true; refs[i].len = 0; payload += 1; continue; }
            refs[i] = ref_of(n->child[i], store);
            payload += refs[i].embedded ? refs[i].len : 33;
        }
        put_header(b, payload, 0xc0, 0xf7);
        for (int i = 0; i < 16; ++i) {
            if (refs[i].embedded) {
                if (refs[i].len == 0) b.byte(0x80);
                else b.bytes(refs[i].data, refs[i].len);
            } else {
                b.byte(0xa0);
                b.bytes(refs[i].data, 32);
            }
        }
        b.byte(0x80);
        return b.n;
    }
    uint8_t hp[33];
    const size_t hpn = hp_encode(n->path, n->plen, n->kind == Node::Leaf, hp);
    if (n->kind == Node::Leaf) {
        const size_t payload = string_size(hp, hpn) + string_size(n->value, n->vlen);
        put_header(b, payload, 0xc0, 0xf7);
        put_string(b, hp, hpn);
        put_string(b, n->value, n->vlen);
        return b.n;
    }
    Ref r = ref_of(n->child[0], store);
    const size_t payload = string_size(hp, hpn) + (r.embedded ? r.len : 33);
    put_header(b, payload, 0xc0, 0xf7);
    put_string(b, hp, hpn);
    if (r.embedded) b.bytes(r.data, r.len);
    else { b.byte(0xa0); b.bytes(r.data, 32); }
    return b.n;
}

Ref ref_of(Node* n, const NodeStore& store) {
    Ref r;
    if (n->has_hash && !n->dirty) {
        r.embedded = false;
        std::memcpy(r.data, n->hash.b, 32);
        return r;
    }
    uint8_t buf[1100];
    const size_t len = encode(n, buf, store);
    if (len < 32) {
        r.embedded = true;
        r.len = static_cast<uint8_t>(len);
        std::memcpy(r.data, buf, len);
        return r;
    }
    n->hash = keccak(buf, len);
    n->has_hash = true;
    n->dirty = false;
    r.embedded = false;
    std::memcpy(r.data, n->hash.b, 32);
    return r;
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
        root_ = new_node(Node::HashRef);
        root_->hash = root;
        root_->has_hash = true;
        root_->dirty = false;
    }
}

void MutableTrie::put(const uint8_t key[32], const uint8_t* value, size_t len) {
    uint8_t* v = static_cast<uint8_t*>(std::malloc(len ? len : 1));
    std::memcpy(v, value, len);
    uint8_t nib[64];
    unpack(key, nib);
    root_ = insert(root_, nib, 0, v, len, store_);
}

void MutableTrie::remove(const uint8_t key[32]) {
    uint8_t nib[64];
    unpack(key, nib);
    root_ = stwo::remove(root_, nib, 0, store_);
}

H256 MutableTrie::root_hash() {
    if (root_->kind == Node::Empty) return kEmptyTrieRoot;
    if (root_->has_hash && !root_->dirty) return root_->hash;
    uint8_t buf[1100];
    const size_t len = encode(root_, buf, store_);
    return keccak(buf, len);
}

}  // namespace stwo
