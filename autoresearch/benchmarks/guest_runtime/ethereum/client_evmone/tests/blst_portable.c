// blst differential: the guest's portable-C configuration vs the host assembly.
//
// The RV64 guest compiles blst with -D__BLST_NO_ASM__ and patch 0002 (64-bit
// limbs, __int128 double limb); the host build links blst's assembly. build.py
// --tests compiles this file twice (portable C with the patched sources, and
// assembly) and requires byte-identical output. On the 64-bit host the
// portable build takes the same 64-bit-limb no_asm.h path as the guest, so a
// defect in it (e.g. the quot_rem_64 limb-count assumption that crashed G2
// scalar multiplication on RV64) shows up natively, and trips UBSan traps.
//
// Covers every blst entry point evmone's EIP-2537 / EIP-4844 code uses: G1/G2
// scalar multiplication (short and 256-bit scalars, GLV/GLS paths), Pippenger
// MSM for 1..5 points (1 point is evmone's fallback to mult), subgroup checks,
// map-to-curve, Miller loop + final exponentiation. Prints one line per result.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "blst.h"

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}
static void rand_bytes(byte* out, size_t n) {
    for (size_t i = 0; i < n; ++i) out[i] = (byte)next();
}
static void hex(const char* tag, const byte* p, size_t n) {
    printf("%s ", tag);
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}
static void out_p1(const char* tag, const blst_p1* p) { byte b[48]; blst_p1_compress(b, p); hex(tag, b, 48); }
static void out_p2(const char* tag, const blst_p2* p) { byte b[96]; blst_p2_compress(b, p); hex(tag, b, 96); }

// Edge scalars: 0, 1, 2, r-1, r, 2^256-1, and the BLS parameter |z|.
static void edge_scalar(int k, byte s[32]) {
    static const byte r_le[32] = {0x01,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xfe,0x5b,0xfe,0xff,0x02,0xa4,0xbd,0x53,
                                  0x05,0xd8,0xa1,0x09,0x08,0xd8,0x39,0x33,0x48,0x7d,0x9d,0x29,0x53,0xa7,0xed,0x73};
    memset(s, 0, 32);
    switch (k) {
        case 0: break;
        case 1: s[0] = 1; break;
        case 2: s[0] = 2; break;
        case 3: memcpy(s, r_le, 32); s[0] = 0; break;  // r - 1
        case 4: memcpy(s, r_le, 32); break;            // r
        case 5: memset(s, 0xff, 32); break;
        case 6: { const uint64_t z = 0xd201000000010000ull; memcpy(s, &z, 8); break; }
    }
}

int main(void) {
    const blst_p1 g1 = *blst_p1_generator();
    const blst_p2 g2 = *blst_p2_generator();
    byte s[32];
    blst_p1 a1, b1;
    blst_p2 a2, b2;
    char tag[64];

    // Scalar multiplication: edge scalars, random 256-bit and short scalars,
    // on the generators and on random subgroup points.
    for (int k = 0; k < 7; ++k) {
        edge_scalar(k, s);
        blst_p1_mult(&a1, &g1, s, 256); snprintf(tag, sizeof tag, "g1mul.edge%d", k); out_p1(tag, &a1);
        blst_p2_mult(&a2, &g2, s, 256); snprintf(tag, sizeof tag, "g2mul.edge%d", k); out_p2(tag, &a2);
    }
    for (int i = 0; i < 24; ++i) {
        rand_bytes(s, 32);
        blst_p1_mult(&b1, &g1, s, 256);
        blst_p2_mult(&b2, &g2, s, 256);
        rand_bytes(s, 32);
        const size_t bits = (i % 3 == 0) ? 64 : (i % 3 == 1) ? 128 : 256;
        blst_p1_mult(&a1, &b1, s, bits); snprintf(tag, sizeof tag, "g1mul.%d.%zu", i, bits); out_p1(tag, &a1);
        blst_p2_mult(&a2, &b2, s, bits); snprintf(tag, sizeof tag, "g2mul.%d.%zu", i, bits); out_p2(tag, &a2);
        printf("in_g %d %d %d\n", i, blst_p1_in_g1(&a1), blst_p2_in_g2(&a2));
    }

    // Pippenger MSM, 1..5 points.
    for (size_t n = 1; n <= 5; ++n) {
        blst_p1_affine p1[5]; blst_p2_affine p2[5];
        byte sc[5][32];
        const blst_p1_affine* pp1[5]; const blst_p2_affine* pp2[5]; const byte* ps[5];
        for (size_t j = 0; j < n; ++j) {
            rand_bytes(s, 32);
            blst_p1_mult(&a1, &g1, s, 256); blst_p1_to_affine(&p1[j], &a1);
            blst_p2_mult(&a2, &g2, s, 256); blst_p2_to_affine(&p2[j], &a2);
            rand_bytes(sc[j], 32);
            pp1[j] = &p1[j]; pp2[j] = &p2[j]; ps[j] = sc[j];
        }
        static limb_t scratch[1 << 16];
        if (blst_p1s_mult_pippenger_scratch_sizeof(n) > sizeof scratch ||
            blst_p2s_mult_pippenger_scratch_sizeof(n) > sizeof scratch) return 2;
        blst_p1s_mult_pippenger(&a1, pp1, n, ps, 256, scratch); snprintf(tag, sizeof tag, "g1msm.%zu", n); out_p1(tag, &a1);
        blst_p2s_mult_pippenger(&a2, pp2, n, ps, 256, scratch); snprintf(tag, sizeof tag, "g2msm.%zu", n); out_p2(tag, &a2);
    }

    // Map to curve (EIP-2537 MAP_FP_TO_G1 / MAP_FP2_TO_G2).
    for (int i = 0; i < 6; ++i) {
        byte le[48];
        blst_fp u; blst_fp2 u2;
        rand_bytes(le, 48); le[47] &= 0x0f; blst_fp_from_lendian(&u, le);
        blst_map_to_g1(&a1, &u, NULL); snprintf(tag, sizeof tag, "map1.%d", i); out_p1(tag, &a1);
        rand_bytes(le, 48); le[47] &= 0x0f; blst_fp_from_lendian(&u2.fp[0], le);
        rand_bytes(le, 48); le[47] &= 0x0f; blst_fp_from_lendian(&u2.fp[1], le);
        blst_map_to_g2(&a2, &u2, NULL); snprintf(tag, sizeof tag, "map2.%d", i); out_p2(tag, &a2);
    }

    // Pairing: e(aG1, bG2) == e(abG1, G2).
    for (int i = 0; i < 3; ++i) {
        byte x[32], y[32];
        rand_bytes(x, 32); rand_bytes(y, 32);
        blst_p1_affine pa, pb; blst_p2_affine qa, qb;
        blst_p1_mult(&a1, &g1, x, 256); blst_p1_to_affine(&pa, &a1);
        blst_p2_mult(&a2, &g2, y, 256); blst_p2_to_affine(&qa, &a2);
        blst_p1_mult(&b1, &a1, y, 256); blst_p1_to_affine(&pb, &b1);
        blst_p2_to_affine(&qb, &g2);
        blst_fp12 f1, f2, e1, e2;
        blst_miller_loop(&f1, &qa, &pa); blst_final_exp(&e1, &f1);
        blst_miller_loop(&f2, &qb, &pb); blst_final_exp(&e2, &f2);
        printf("pairing.%d %d\n", i, blst_fp12_is_equal(&e1, &e2));
        hex("pairing.val", (const byte*)&e1, sizeof e1 < 64 ? sizeof e1 : 64);
    }
    return 0;
}
