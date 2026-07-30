//! CUDA-free algebraic oracle for the four-lane Blake2s compression mapping.
//!
//! Hardware still compares the scalar and quad kernels over real commitment
//! buffers. This test proves the lane ownership and diagonal shuffle schedule
//! independently of nvcc and CUDA execution.

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn mix_words(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, y: u32) {
    *a = a.wrapping_add(*b).wrapping_add(x);
    *d = (*d ^ *a).rotate_right(16);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_right(12);
    *a = a.wrapping_add(*b).wrapping_add(y);
    *d = (*d ^ *a).rotate_right(8);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_right(7);
}

fn mix_indices(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    let (mut va, mut vb, mut vc, mut vd) = (v[a], v[b], v[c], v[d]);
    mix_words(&mut va, &mut vb, &mut vc, &mut vd, x, y);
    (v[a], v[b], v[c], v[d]) = (va, vb, vc, vd);
}

fn scalar_compress(mut h: [u32; 8], message: [u32; 16], bytes: u32, last: u32) -> [u32; 8] {
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(&h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= bytes;
    v[14] ^= last;
    for sigma in SIGMA {
        mix_indices(&mut v, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
        mix_indices(&mut v, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
        mix_indices(&mut v, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
        mix_indices(&mut v, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);
        mix_indices(&mut v, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
        mix_indices(&mut v, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
        mix_indices(&mut v, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
        mix_indices(&mut v, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
    }
    for index in 0..8 {
        h[index] ^= v[index] ^ v[index + 8];
    }
    h
}

fn quad_compress(h: [u32; 8], message: [u32; 16], bytes: u32, last: u32) -> [u32; 8] {
    let mut a = [h[0], h[1], h[2], h[3]];
    let mut b = [h[4], h[5], h[6], h[7]];
    let mut c = [IV[0], IV[1], IV[2], IV[3]];
    let mut d = [IV[4], IV[5], IV[6], IV[7]];
    d[0] ^= bytes;
    d[2] ^= last;

    for sigma in SIGMA {
        for lane in 0..4 {
            mix_words(
                &mut a[lane],
                &mut b[lane],
                &mut c[lane],
                &mut d[lane],
                message[sigma[2 * lane]],
                message[sigma[2 * lane + 1]],
            );
        }
        let mut diagonal_b = [0u32; 4];
        let mut diagonal_c = [0u32; 4];
        let mut diagonal_d = [0u32; 4];
        for lane in 0..4 {
            diagonal_b[lane] = b[(lane + 1) & 3];
            diagonal_c[lane] = c[(lane + 2) & 3];
            diagonal_d[lane] = d[(lane + 3) & 3];
            mix_words(
                &mut a[lane],
                &mut diagonal_b[lane],
                &mut diagonal_c[lane],
                &mut diagonal_d[lane],
                message[sigma[2 * (lane + 4)]],
                message[sigma[2 * (lane + 4) + 1]],
            );
        }
        for lane in 0..4 {
            b[lane] = diagonal_b[(lane + 3) & 3];
            c[lane] = diagonal_c[(lane + 2) & 3];
            d[lane] = diagonal_d[(lane + 1) & 3];
        }
    }

    let mut output = [0u32; 8];
    for lane in 0..4 {
        output[lane] = h[lane] ^ a[lane] ^ c[lane];
        output[lane + 4] = h[lane + 4] ^ b[lane] ^ d[lane];
    }
    output
}

fn random_word(state: &mut u64) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state ^ (*state >> 32)) as u32
}

#[test]
fn four_lane_schedule_matches_scalar_compression_exhaustively_randomized() {
    let mut seed = 0xA5A5_91E1_7C4D_29B3u64;
    for case in 0..4096u32 {
        let mut h = [0u32; 8];
        let mut message = [0u32; 16];
        h.fill_with(|| random_word(&mut seed));
        message.fill_with(|| random_word(&mut seed));
        let bytes = 64 * (1 + random_word(&mut seed) % 1_000_000);
        let last = if case & 1 == 0 { 0 } else { u32::MAX };
        assert_eq!(
            quad_compress(h, message, bytes, last),
            scalar_compress(h, message, bytes, last),
            "quad mapping diverged at case {case}",
        );
    }
}

#[test]
fn every_message_bit_and_streamed_state_transition_match_scalar() {
    let states = [[0u32; 8], IV, [u32::MAX; 8]];
    for initial in states {
        for word in 0..16 {
            for bit in 0..32 {
                let mut message = [0u32; 16];
                message[word] = 1u32 << bit;
                for last in [0, u32::MAX] {
                    assert_eq!(
                        quad_compress(initial, message, 64, last),
                        scalar_compress(initial, message, 64, last),
                        "word {word}, bit {bit}, last {last:#x}",
                    );
                }
            }
        }
    }

    let mut seed = 0xD1B5_4A32_D192_ED03u64;
    for blocks in 1..=19u32 {
        let mut scalar = IV;
        let mut quad = IV;
        for block in 1..=blocks {
            let mut message = [0u32; 16];
            message.fill_with(|| random_word(&mut seed));
            scalar = scalar_compress(scalar, message, block * 64, 0);
            quad = quad_compress(quad, message, block * 64, 0);
        }
        assert_eq!(
            quad, scalar,
            "streamed state diverged after {blocks} blocks"
        );
    }
}
