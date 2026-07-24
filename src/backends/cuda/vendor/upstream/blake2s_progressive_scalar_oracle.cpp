// Host-only arithmetic oracle:
// c++ -std=c++20 -O2 -I cuda cuda/blake2s_progressive_scalar_oracle.cpp -o /tmp/p && /tmp/p

#include "blake2s_progressive_scalar.cuh"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>

namespace {

struct State {
    std::array<uint32_t, 8> h;
    std::array<uint32_t, 16> pending;
};

constexpr uint8_t SIGMA[10][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
    {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
    {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
    {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
    {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
};
constexpr uint32_t IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

uint32_t rotr(uint32_t value, uint32_t shift) {
    return (value >> shift) | (value << (32 - shift));
}

void reference_compress(State &state, uint64_t counter, uint32_t lastblock) {
    uint32_t v[16];
    for (int i = 0; i < 8; ++i) {
        v[i] = state.h[i];
        v[i + 8] = IV[i];
    }
    v[12] ^= static_cast<uint32_t>(counter);
    v[13] ^= static_cast<uint32_t>(counter >> 32);
    v[14] ^= lastblock;
    for (int round = 0; round < 10; ++round) {
        auto g = [&](int a, int b, int c, int d, int index) {
            v[a] += v[b] + state.pending[SIGMA[round][2 * index]];
            v[d] = rotr(v[d] ^ v[a], 16);
            v[c] += v[d];
            v[b] = rotr(v[b] ^ v[c], 12);
            v[a] += v[b] + state.pending[SIGMA[round][2 * index + 1]];
            v[d] = rotr(v[d] ^ v[a], 8);
            v[c] += v[d];
            v[b] = rotr(v[b] ^ v[c], 7);
        };
        g(0,4,8,12,0); g(1,5,9,13,1); g(2,6,10,14,2); g(3,7,11,15,3);
        g(0,5,10,15,4); g(1,6,11,12,5); g(2,7,8,13,6); g(3,4,9,14,7);
    }
    for (int i = 0; i < 8; ++i) state.h[i] ^= v[i] ^ v[i + 8];
}

void scalar_compress(State &state, uint64_t counter, uint32_t lastblock) {
    auto [h0,h1,h2,h3,h4,h5,h6,h7] = state.h;
    const auto &m = state.pending;
    progressive_blake2s_compress_scalar(
        h0,h1,h2,h3,h4,h5,h6,h7,
        m[0],m[1],m[2],m[3],m[4],m[5],m[6],m[7],
        m[8],m[9],m[10],m[11],m[12],m[13],m[14],m[15],counter,lastblock);
    state.h = {h0,h1,h2,h3,h4,h5,h6,h7};
}

uint32_t pending_words(uint32_t columns) {
    return columns == 0 ? 0 : ((columns - 1) & 15u) + 1;
}

template <void (*Compress)(State &, uint64_t, uint32_t)>
void absorb(State &state, uint32_t before, const std::array<uint32_t, 65> &words,
            uint32_t count) {
    uint32_t pending = pending_words(before);
    uint64_t compressed = static_cast<uint64_t>(before - pending) * 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (pending == 16) {
            compressed += 64;
            Compress(state, compressed, 0);
            pending = 0;
        }
        switch (pending++) {
            case 0: state.pending[0] = words[i]; break;
            case 1: state.pending[1] = words[i]; break;
            case 2: state.pending[2] = words[i]; break;
            case 3: state.pending[3] = words[i]; break;
            case 4: state.pending[4] = words[i]; break;
            case 5: state.pending[5] = words[i]; break;
            case 6: state.pending[6] = words[i]; break;
            case 7: state.pending[7] = words[i]; break;
            case 8: state.pending[8] = words[i]; break;
            case 9: state.pending[9] = words[i]; break;
            case 10: state.pending[10] = words[i]; break;
            case 11: state.pending[11] = words[i]; break;
            case 12: state.pending[12] = words[i]; break;
            case 13: state.pending[13] = words[i]; break;
            case 14: state.pending[14] = words[i]; break;
            default: state.pending[15] = words[i]; break;
        }
    }
}

template <void (*Compress)(State &, uint64_t, uint32_t)>
std::array<uint32_t, 8> finalize(State state, uint32_t columns) {
    uint32_t pending = pending_words(columns);
    for (uint32_t i = pending; i < 16; ++i) state.pending[i] = 0;
    Compress(state, static_cast<uint64_t>(columns) * 4, 0xffffffffu);
    return state.h;
}

uint64_t next(uint64_t &state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

State initial_state() {
    State state{};
    state.h = {IV[0] ^ 0x01010020u, IV[1], IV[2], IV[3],
               IV[4], IV[5], IV[6], IV[7]};
    return state;
}

} // namespace

int main() {
    const std::array<uint32_t, 8> empty_digest = {
        0x307a2169u, 0x94809079u, 0xd02111e1u, 0x7c4a3542u,
        0x48b6551fu, 0x1ea5a12cu, 0xfd0d251bu, 0xf9eed01eu,
    };
    assert(finalize<scalar_compress>(initial_state(), 0) == empty_digest);
    assert(finalize<reference_compress>(initial_state(), 0) == empty_digest);

    constexpr std::array<uint32_t, 9> batch_lengths = {0,1,2,15,16,17,31,32,65};
    for (uint64_t seed = 1; seed <= 257; ++seed) {
        uint64_t random = seed * 0x9e3779b97f4a7c15ull;
        for (uint32_t pending = 0; pending <= 16; ++pending) {
            uint32_t before = pending == 0 ? 0 : pending + 16 * (seed & 3);
            State source;
            for (auto &word : source.h) word = static_cast<uint32_t>(next(random));
            for (auto &word : source.pending) word = static_cast<uint32_t>(next(random));
            std::array<uint32_t, 65> words;
            for (auto &word : words) word = static_cast<uint32_t>(next(random));
            for (uint32_t count : batch_lengths) {
                State reference = source;
                State scalar = source;
                absorb<reference_compress>(reference, before, words, count);
                absorb<scalar_compress>(scalar, before, words, count);
                assert(reference.h == scalar.h);
                assert(reference.pending == scalar.pending);
                assert(finalize<reference_compress>(reference, before + count) ==
                       finalize<scalar_compress>(scalar, before + count));
            }
        }
    }

    State maximum{};
    uint64_t random = 0xfeedfacecafebeefull;
    for (auto &word : maximum.h) word = static_cast<uint32_t>(next(random));
    for (auto &word : maximum.pending) word = static_cast<uint32_t>(next(random));
    assert(finalize<reference_compress>(maximum, UINT32_MAX) ==
           finalize<scalar_compress>(maximum, UINT32_MAX));
    std::puts("progressive scalar oracle: 257 seeds, pending 0..16, 9 batches PASS");
}
