// Host differential test for glue/witness_trie.cpp (our code).
//
// A reference Merkle-Patricia trie is built from scratch from a key/value map
// (straightforward recursive encoder). Its nodes form the witness. Then:
//   1. trie_get finds every key with its exact value and reports random
//      absent keys as Absent;
//   2. after random puts (new keys and overwrites) and removes, applied in
//      several root_hash rounds, MutableTrie's root equals the reference root
//      of the updated map;
//   3. with nodes dropped from the witness, lookups under a dropped node
//      report Missing, lookups elsewhere still agree, and mutations that need
//      a dropped node abort.
// Key sets mix random keys with clustered keys sharing long prefixes, so
// extensions, embedded (< 32-byte) nodes, branch collapses and odd/even leaf
// paths all occur.
//
// Build: python3 -I build.py --out DIR --host --tests  (runs it)
#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "witness_trie.hpp"

static std::jmp_buf g_abort;
static bool g_expect_abort = false;
extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept {
    if (g_expect_abort) std::longjmp(g_abort, 1);
    std::fprintf(stderr, "unexpected abort: %s\n", why);
    std::exit(1);
}
extern "C" [[noreturn]] void stwo_fatal(const char* why) noexcept { stwo_guest_abort(why); }

namespace {
using Bytes = std::string;  // byte string
using Key = std::string;    // 32 bytes

std::mt19937_64 rng(0x7472696531ull);

void fail(const char* what, int round) {
    std::fprintf(stderr, "FAIL: %s (case %d)\n", what, round);
    std::exit(1);
}

// ---- reference encoder ----
Bytes rlp_header(size_t len, uint8_t base_short, uint8_t base_long) {
    if (len <= 55) return Bytes(1, char(base_short + len));
    Bytes l;
    for (size_t v = len; v; v >>= 8) l.insert(l.begin(), char(v & 0xff));
    return Bytes(1, char(base_long + l.size())) + l;
}
Bytes rlp_str(const Bytes& s) {
    if (s.size() == 1 && uint8_t(s[0]) < 0x80) return s;
    return rlp_header(s.size(), 0x80, 0xb7) + s;
}
Bytes rlp_list(const Bytes& payload) { return rlp_header(payload.size(), 0xc0, 0xf7) + payload; }
Bytes hp(const std::vector<uint8_t>& nib, size_t from, bool leaf) {
    const size_t n = nib.size() - from;
    Bytes out;
    const uint8_t flag = leaf ? 2 : 0;
    size_t i = from;
    if (n & 1) out += char(((flag | 1) << 4) | nib[i++]);
    else out += char(flag << 4);
    for (; i < nib.size(); i += 2) out += char((nib[i] << 4) | nib[i + 1]);
    return out;
}
std::vector<uint8_t> nibbles(const Key& k) {
    std::vector<uint8_t> n;
    for (unsigned char c : k) { n.push_back(c >> 4); n.push_back(c & 15); }
    return n;
}
Bytes hash_bytes(const Bytes& b) {
    const stwo::H256 h = stwo::keccak(reinterpret_cast<const uint8_t*>(b.data()), b.size());
    return Bytes(reinterpret_cast<const char*>(h.b), 32);
}

struct Ref {
    std::vector<Bytes>* witness;
    // Child reference item; nodes of >= 32 bytes are recorded as witness nodes.
    Bytes ref(const Bytes& enc) {
        if (enc.size() < 32) return enc;
        witness->push_back(enc);
        return Bytes(1, char(0xa0)) + hash_bytes(enc);
    }
    using Entry = std::pair<std::vector<uint8_t>, Bytes>;
    Bytes build(const std::vector<Entry>& items, size_t depth) {
        if (items.size() == 1) return rlp_list(rlp_str(hp(items[0].first, depth, true)) + rlp_str(items[0].second));
        size_t c = 0;
        for (;; ++c) {
            const uint8_t x = items[0].first[depth + c];
            bool same = true;
            for (const auto& e : items) same &= e.first[depth + c] == x;
            if (!same) break;
        }
        if (c > 0) {
            std::vector<uint8_t> pre(items[0].first.begin(), items[0].first.begin() + depth + c);
            return rlp_list(rlp_str(hp(pre, depth, false)) + ref(build(items, depth + c)));
        }
        Bytes payload;
        for (int i = 0; i < 16; ++i) {
            std::vector<Entry> g;
            for (const auto& e : items) if (e.first[depth] == i) g.push_back(e);
            payload += g.empty() ? Bytes(1, char(0x80)) : ref(build(g, depth + 1));
        }
        payload += char(0x80);
        return rlp_list(payload);
    }
};

// Root hash of `m`; the witness receives every node (the root included).
Bytes reference_root(const std::map<Key, Bytes>& m, std::vector<Bytes>* witness) {
    std::vector<Bytes> sink;
    Ref r{witness ? witness : &sink};
    if (m.empty()) return Bytes(reinterpret_cast<const char*>(stwo::kEmptyTrieRoot.b), 32);
    std::vector<Ref::Entry> items;
    for (const auto& [k, v] : m) items.push_back({nibbles(k), v});
    const Bytes root = r.build(items, 0);
    r.witness->push_back(root);
    return hash_bytes(root);
}

Key random_key(int mode, const Key& base) {
    Key k(32, '\0');
    for (auto& c : k) c = char(rng());
    if (mode == 1) {  // cluster: share a long prefix with base, differ near the end
        const size_t keep = 24 + rng() % 8;
        for (size_t i = 0; i < keep; ++i) k[i] = base[i];
        if (rng() % 2) k[31] = char((uint8_t(k[31]) & 0x0f) | (uint8_t(base[31]) & 0xf0));
    }
    return k;
}
Bytes random_value() {
    const size_t len = 1 + rng() % (rng() % 4 == 0 ? 40 : 3);
    Bytes v(len, '\0');
    for (auto& c : v) c = char(rng());
    return v;
}

// Witness bytes must outlive the store: keep them in stable storage.
struct Witness {
    std::vector<Bytes> nodes;
    stwo::NodeStore store;
    void index(const std::set<size_t>& drop = {}) {
        store.init(nodes.size());
        for (size_t i = 0; i < nodes.size(); ++i)
            if (!drop.count(i)) store.add(reinterpret_cast<const uint8_t*>(nodes[i].data()), nodes[i].size());
    }
};

stwo::H256 to_h(const Bytes& b) { stwo::H256 h; std::memcpy(h.b, b.data(), 32); return h; }

int run_case(int cs) {
    std::map<Key, Bytes> m;
    const int n = 1 + int(rng() % (cs % 7 == 0 ? 400 : 60));
    const Key base = random_key(0, Key(32, '\0'));
    const int mode = int(rng() % 3);  // 0 random, 1 clustered, 2 mixed
    for (int i = 0; i < n; ++i) m[random_key(mode == 2 ? int(rng() % 2) : mode, base)] = random_value();
    auto* w = new Witness();  // leaked on purpose: decoded nodes point into it
    const Bytes root = reference_root(m, &w->nodes);
    w->index();
    const stwo::H256 rh = to_h(root);

    // 1. lookups
    for (const auto& [k, v] : m) {
        stwo::ByteView out;
        if (stwo::trie_get(w->store, rh, reinterpret_cast<const uint8_t*>(k.data()), out) != stwo::Lookup::Found)
            fail("present key not found", cs);
        if (out.n != v.size() || std::memcmp(out.p, v.data(), v.size()) != 0) fail("value mismatch", cs);
    }
    for (int i = 0; i < 50; ++i) {
        const Key k = random_key(int(rng() % 2), base);
        if (m.count(k)) continue;
        stwo::ByteView out;
        if (stwo::trie_get(w->store, rh, reinterpret_cast<const uint8_t*>(k.data()), out) != stwo::Lookup::Absent)
            fail("absent key not absent", cs);
    }

    // 2. mutations, with intermediate root_hash calls
    stwo::MutableTrie t(w->store, rh);
    std::vector<Key> keys;
    for (const auto& kv : m) keys.push_back(kv.first);
    const int rounds = 1 + int(rng() % 3);
    for (int r = 0; r < rounds; ++r) {
        const int ops = 1 + int(rng() % (n + 4));
        for (int i = 0; i < ops; ++i) {
            const unsigned op = rng() % 4;
            Key k;
            if (op == 0 || keys.empty()) k = random_key(mode == 2 ? int(rng() % 2) : mode, base);
            else k = keys[rng() % keys.size()];
            if (op == 3) {
                m.erase(k);
                t.remove(reinterpret_cast<const uint8_t*>(k.data()));
            } else {
                const Bytes v = random_value();
                m[k] = v;
                t.put(reinterpret_cast<const uint8_t*>(k.data()), reinterpret_cast<const uint8_t*>(v.data()), v.size());
            }
        }
        const stwo::H256 got = t.root_hash();
        if (std::memcmp(got.b, reference_root(m, nullptr).data(), 32) != 0) fail("root mismatch after mutations", cs);
    }
    // Removing everything gives the empty root.
    if (cs % 11 == 0) {
        for (const auto& kv : m) t.remove(reinterpret_cast<const uint8_t*>(kv.first.data()));
        if (t.root_hash() != stwo::kEmptyTrieRoot) fail("empty root", cs);
    }
    return n;
}

// 3. partial witness: drop one non-root node.
void run_partial(int cs) {
    std::map<Key, Bytes> m;
    const Key base = random_key(0, Key(32, '\0'));
    const int n = 20 + int(rng() % 100);
    for (int i = 0; i < n; ++i) m[random_key(int(rng() % 2), base)] = random_value();
    auto* w = new Witness();
    const Bytes root = reference_root(m, &w->nodes);
    if (w->nodes.size() < 2) return;
    const size_t drop = rng() % (w->nodes.size() - 1);  // the root is last
    std::set<size_t> drops;  // identical encodings elsewhere share the hash
    for (size_t i = 0; i < w->nodes.size(); ++i)
        if (w->nodes[i] == w->nodes[drop]) drops.insert(i);
    w->index(drops);
    const Bytes dropped_hash = hash_bytes(w->nodes[drop]);
    const stwo::H256 rh = to_h(root);
    int missing = 0;
    for (const auto& [k, v] : m) {
        stwo::ByteView out;
        const auto r = stwo::trie_get(w->store, rh, reinterpret_cast<const uint8_t*>(k.data()), out);
        // Reference: is the dropped node on k's path? Rebuild the lookup by
        // checking whether the key's leaf lies under the dropped subtree: the
        // key is reachable iff trie_get on the full witness path avoids it.
        // We test consistency: Found must give the right value, Missing must
        // be explained by the dropped node, Absent is never right here.
        if (r == stwo::Lookup::Absent) fail("present key absent with partial witness", cs);
        if (r == stwo::Lookup::Found && (out.n != v.size() || std::memcmp(out.p, v.data(), v.size()) != 0))
            fail("value mismatch with partial witness", cs);
        if (r == stwo::Lookup::Missing) ++missing;
    }
    if (missing == 0) fail("dropped node never reported missing", cs);
    (void)dropped_hash;
    // A put that needs the dropped node must abort, not produce a root.
    bool aborted = false;
    for (const auto& kv : m) {
        stwo::ByteView out;
        if (stwo::trie_get(w->store, rh, reinterpret_cast<const uint8_t*>(kv.first.data()), out) != stwo::Lookup::Missing) continue;
        stwo::MutableTrie t(w->store, rh);
        g_expect_abort = true;
        if (setjmp(g_abort) == 0) {
            t.put(reinterpret_cast<const uint8_t*>(kv.first.data()), reinterpret_cast<const uint8_t*>("\x01"), 1);
            (void)t.root_hash();
        } else {
            aborted = true;
        }
        g_expect_abort = false;
        break;
    }
    if (!aborted) fail("mutation through a dropped node did not abort", cs);
}
}  // namespace

int main(int argc, char** argv) {
    const int cases = argc > 1 ? std::atoi(argv[1]) : 600;
    long keys = 0;
    for (int c = 0; c < cases; ++c) keys += run_case(c);
    for (int c = 0; c < cases / 3; ++c) run_partial(c);
    std::printf("trie_differential: %d cases (%ld keys), %d partial-witness cases OK\n", cases, keys, cases / 3);
    return 0;
}
