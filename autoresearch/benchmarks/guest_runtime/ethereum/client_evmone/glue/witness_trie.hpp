// Merkle-Patricia trie over the stateless witness (our code).
//
// The canonical SSZ StatelessInput carries the execution witness as a list of
// RLP trie nodes (by hash), contract codes and ancestor headers -- no key
// preimages and no pre-indexed tables. ziskethone's own input (ZEG0) instead
// ships a pre-walked trie with plaintext keys. This module bridges the two:
//
//   * NodeStore indexes every witness node by keccak256(rlp) and decodes each
//     node at most once (child references are resolved to store slots lazily).
//   * trie_get() walks a trie from an authenticated root to read one key
//     (account or storage slot), proving presence or absence.
//   * MutableTrie applies the block's writes (insert/update/delete with branch
//     collapse) on top of the witness, in place, and recomputes the root.
//
// A key whose path leaves the witness is "unresolvable": lookups report it so
// warming-only accesses can proceed, and any load or write of it fails.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace stwo {

struct alignas(8) H256 {
    uint8_t b[32];
    bool operator==(const H256& o) const noexcept {
        const uint64_t* x = reinterpret_cast<const uint64_t*>(b);
        const uint64_t* y = reinterpret_cast<const uint64_t*>(o.b);
        return ((x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]) | (x[3] ^ y[3])) == 0;
    }
    bool operator!=(const H256& o) const noexcept { return !(*this == o); }
};

H256 keccak(const uint8_t* data, size_t len) noexcept;
extern const H256 kEmptyTrieRoot;  // keccak(rlp(""))

struct ByteView {
    const uint8_t* p = nullptr;
    size_t n = 0;
};

struct DNode;  // decoded witness node

class NodeStore {
public:
    struct Slot {
        H256 key;
        const uint8_t* p;
        size_t n;
        DNode* dec;  // decoded lazily
    };
    void init(size_t expected_nodes);
    void add(const uint8_t* rlp, size_t len);
    Slot* find(const H256& h) const noexcept;
    Slot* find_bytes(const uint8_t* h32) const noexcept;  // unaligned 32-byte key
    const DNode* decoded(Slot* s) const;
    size_t size() const noexcept { return count_; }

private:
    Slot* slots_ = nullptr;
    size_t mask_ = 0;
    size_t count_ = 0;
};

enum class Lookup { Found, Absent, Missing };

// Read the value stored under the 32-byte trie key `key` (already hashed)
// in the trie rooted at `root`. Found: `value` is the leaf payload bytes.
Lookup trie_get(const NodeStore& store, const H256& root, const uint8_t key[32],
                ByteView& value) noexcept;

// Mutable trie: lazily materializes witness nodes, applies updates in place, hashes.
class MutableTrie {
public:
    MutableTrie(const NodeStore& store, const H256& root) noexcept;
    // `value` is the leaf payload (the RLP item stored in the leaf, e.g. the
    // account RLP list or the RLP string of a storage value). Copied.
    void put(const uint8_t key[32], const uint8_t* value, size_t len);
    void remove(const uint8_t key[32]);
    H256 root_hash();

    struct Node;

private:
    const NodeStore& store_;
    Node* root_;
};

}  // namespace stwo
