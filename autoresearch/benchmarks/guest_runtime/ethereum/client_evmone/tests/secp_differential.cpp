// Host differential test for glue/secp256k1_stwo.cpp (our code).
//
// 1. Recovery: for random and edge-case (z, r, s, recid) the stwo recover
//    (emulated secp services) must agree with evmone's reference
//    secp256k1_ecdsa_recover: same failure/success and the same public key.
// 2. Hinted verification (transaction senders): for every successful
//    recovery, the deferred batch verifier must accept the true key and reject
//    the negated key, the key with the other parity, and a wrong recid.
//
// Build: python3 -I build.py --out DIR --host --tests  (runs it)
#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

#include <evmone_precompiles/secp256k1.hpp>

extern "C" int secp256k1_ecdsa_recover(const uint64_t* z, const uint64_t* r, const uint64_t* s, unsigned recid,
                                       uint64_t* pubkey);
extern "C" bool stwo_secp_hint_sender(const uint8_t z_be[32], const uint8_t r_be[32], const uint8_t s_be[32],
                                      unsigned recid, const uint8_t pubkey65[65], uint8_t addr_out[20]);
extern "C" void stwo_secp_verify_pending();
extern "C" void stwo_secp_reset_pending();

static std::jmp_buf g_abort;
static const char* g_why = nullptr;
extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept {
    g_why = why;
    std::longjmp(g_abort, 1);
}

static void be_to_limbs(const uint8_t* be, uint64_t* l) {
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | be[i * 8 + j];
        l[3 - i] = w;
    }
}
static void limbs_to_be(const uint64_t* l, uint8_t* be) {
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 8; ++j) be[i * 8 + j] = uint8_t(l[3 - i] >> (8 * (7 - j)));
}

// Returns true if the batch verifier accepted.
static bool verify_one(const uint8_t z[32], const uint8_t r[32], const uint8_t s[32], unsigned recid,
                       const uint8_t pk[65]) {
    uint8_t addr[20];
    stwo_secp_reset_pending();
    if (setjmp(g_abort) != 0) return false;
    if (!stwo_secp_hint_sender(z, r, s, recid, pk, addr)) return false;  // invalid hint point
    stwo_secp_verify_pending();
    return true;
}

int main(int argc, char** argv) {
    const int iters = argc > 1 ? std::atoi(argv[1]) : 2000;
    std::mt19937_64 rng(20261101);
    static const uint8_t N[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
                                  0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
    int agree_ok = 0, agree_fail = 0, mismatches = 0, hint_ok = 0, hint_bad = 0;
    for (int it = 0; it < iters; ++it) {
        uint8_t z[32], r[32], s[32];
        for (auto* b : {z, r, s})
            for (int i = 0; i < 32; ++i) b[i] = uint8_t(rng());
        // Edge cases: r/s at 0, 1, N-1, N, small values; z = 0 and z >= N.
        switch (it % 16) {
            case 0: std::memset(r, 0, 32); break;
            case 1: std::memcpy(s, N, 32); break;
            case 2: std::memcpy(r, N, 32); r[31] -= 1; break;
            case 3: std::memset(s, 0, 32); s[31] = 1; break;
            case 4: std::memset(z, 0, 32); break;
            case 5: std::memset(z, 0xff, 32); break;
            case 6: std::memset(r, 0, 31); break;  // tiny r
            default: break;
        }
        const unsigned recid = unsigned(rng() & 1);
        const auto ref = evmone::crypto::secp256k1::secp256k1_ecdsa_recover(
            std::span<const uint8_t, 32>{z, 32}, std::span<const uint8_t, 32>{r, 32},
            std::span<const uint8_t, 32>{s, 32}, recid != 0, evmone::crypto::secp256k1::RecoveryMode::malleable);
        uint64_t zl[4], rl[4], sl[4], pk[8];
        be_to_limbs(z, zl); be_to_limbs(r, rl); be_to_limbs(s, sl);
        g_why = nullptr;
        int rc;
        if (setjmp(g_abort) != 0) { std::printf("recover aborted: %s\n", g_why); return 1; }
        rc = secp256k1_ecdsa_recover(zl, rl, sl, recid, pk);
        if (!ref.has_value()) {
            if (rc == 0) { ++mismatches; std::printf("it %d: stwo recovered, reference failed\n", it); }
            else ++agree_fail;
            continue;
        }
        uint8_t refpk[64];
        ref->to_bytes(refpk);
        uint8_t mine[64];
        limbs_to_be(pk, mine); limbs_to_be(pk + 4, mine + 32);
        if (rc != 0 || std::memcmp(refpk, mine, 64) != 0) {
            ++mismatches;
            std::printf("it %d: key mismatch (rc %d)\n", it, rc);
            continue;
        }
        ++agree_ok;
        // Hinted verification: the true key passes, wrong ones fail.
        uint8_t pk65[65];
        pk65[0] = 0x04;
        std::memcpy(pk65 + 1, refpk, 64);
        if (verify_one(z, r, s, recid, pk65)) ++hint_ok;
        else { ++mismatches; std::printf("it %d: true key rejected (%s)\n", it, g_why); }
        // Negated key (other y): a valid curve point, wrong key.
        uint8_t neg[65];
        std::memcpy(neg, pk65, 65);
        {
            uint64_t y[4];
            be_to_limbs(neg + 33, y);
            static const uint64_t P[4] = {0xFFFFFFFEFFFFFC2FULL, ~0ULL, ~0ULL, ~0ULL};
            unsigned __int128 borrow = 0;
            uint64_t ny[4];
            for (int i = 0; i < 4; ++i) {
                const unsigned __int128 d = (unsigned __int128)P[i] - y[i] - borrow;
                ny[i] = uint64_t(d);
                borrow = (d >> 64) & 1;
            }
            limbs_to_be(ny, neg + 33);
        }
        if (verify_one(z, r, s, recid, neg)) { ++mismatches; std::printf("it %d: negated key accepted\n", it); }
        else ++hint_bad;
        if (verify_one(z, r, s, recid ^ 1, pk65)) { ++mismatches; std::printf("it %d: wrong recid accepted\n", it); }
        else ++hint_bad;
        uint8_t z2[32];
        std::memcpy(z2, z, 32);
        z2[7] ^= 0x40;
        if (verify_one(z2, r, s, recid, pk65)) { ++mismatches; std::printf("it %d: wrong hash accepted\n", it); }
        else ++hint_bad;
    }
    std::printf("recover agree ok=%d agree-fail=%d; hinted accept=%d reject=%d; mismatches=%d\n", agree_ok,
                agree_fail, hint_ok, hint_bad, mismatches);
    return mismatches == 0 ? 0 : 1;
}
