//! Original FIPS 180-4 SHA-256, specialized for RV64IM software execution.
//! This is a deliberately narrow replacement for sha2 0.10.9 in the pinned
//! guest graph, whose consumers use only Digest and Sha256. It is not a general
//! replacement for RustCrypto sha2: SHA-224/384/512 APIs are not provided.
//! No upstream implementation source is incorporated here. Digest supplies
//! buffering and its existing trait API; all compression rounds are below.
#![no_std]
use core::fmt;
pub use digest;
pub use digest::Digest;
use digest::{
    HashMarker, Output,
    block_buffer::Eager,
    consts::{U32, U64},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
};

pub type Sha256 = CoreWrapper<Sha256Core>;
#[derive(Clone)]
pub struct Sha256Core {
    state: [u32; 8],
    bytes: u64,
}
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
impl Default for Sha256Core {
    fn default() -> Self {
        Self {
            state: IV,
            bytes: 0,
        }
    }
}
impl HashMarker for Sha256Core {}
impl BlockSizeUser for Sha256Core {
    type BlockSize = U64;
}
impl OutputSizeUser for Sha256Core {
    type OutputSize = U32;
}
impl BufferKindUser for Sha256Core {
    type BufferKind = Eager;
}
impl Reset for Sha256Core {
    fn reset(&mut self) {
        *self = Self::default();
    }
}
impl AlgorithmName for Sha256Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256")
    }
}
impl fmt::Debug for Sha256Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256Core { .. }")
    }
}
#[cfg(feature = "oid")]
impl digest::const_oid::AssociatedOid for Sha256Core {
    const OID: digest::const_oid::ObjectIdentifier =
        digest::const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
}
impl UpdateCore for Sha256Core {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.bytes = self
            .bytes
            .wrapping_add((blocks.len() as u64).wrapping_mul(64));
        for block in blocks {
            compress(&mut self.state, block.as_slice());
        }
    }
}
impl FixedOutputCore for Sha256Core {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bits = self
            .bytes
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);
        buffer.len64_padding_be(bits, |block| compress(&mut self.state, block.as_slice()));
        for (word, bytes) in self.state.iter().zip(out.chunks_exact_mut(4)) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
    }
}

#[inline(always)]
fn small0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
#[inline(always)]
fn small1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// Constant indices let LLVM keep the rolling sixteen-word schedule in SSA,
// while rotating round arguments avoids eight assignments in every round.
#[cfg(all(feature = "stwo-candidate-sha256", target_arch = "riscv64"))]
#[inline(never)]
fn compress(state: &mut [u32; 8], block: &[u8]) {
    // Execution-only candidate `sha256_compress` ECALL (tag 0x0003_0010).
    // Packet: H0..H7 as little-endian u32 pairs in four u64 (H0 in the low half
    // of word 0), then the 64 block bytes in stream order. The service updates
    // the state words in place and preserves all registers.
    debug_assert_eq!(block.len(), 64);
    let mut packet = [0u64; 12];
    for i in 0..4 {
        packet[i] = u64::from(state[2 * i]) | (u64::from(state[2 * i + 1]) << 32);
    }
    for i in 0..8 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&block[8 * i..8 * i + 8]);
        packet[4 + i] = u64::from_le_bytes(word);
    }
    // SAFETY: the packet is live, 8-aligned and unique; the service reads 96
    // bytes and writes the first 32 in place.
    unsafe {
        core::arch::asm!("ecall", in("a0") packet.as_mut_ptr(), in("a7") 0x0003_0010usize, options(nostack));
    }
    for i in 0..4 {
        state[2 * i] = packet[i] as u32;
        state[2 * i + 1] = (packet[i] >> 32) as u32;
    }
}

#[cfg(not(all(feature = "stwo-candidate-sha256", target_arch = "riscv64")))]
#[inline(never)]
fn compress(state: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 16];
    if block.as_ptr() as usize & 3 == 0 {
        for i in 0..16 {
            // SAFETY: the branch checks alignment, and all sixteen words are
            // inside this complete block. No loads before or past the slice.
            w[i] =
                u32::from_be(unsafe { core::ptr::read(block.as_ptr().add(4 * i).cast::<u32>()) });
        }
    } else {
        for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().unwrap());
        }
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    macro_rules! round {
        ($i:literal, $k:literal, $a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
            if $i >= 16 {
                w[$i % 16] = w[$i % 16]
                    .wrapping_add(small0(w[($i + 1) % 16]))
                    .wrapping_add(w[($i + 9) % 16])
                    .wrapping_add(small1(w[($i + 14) % 16]));
            }
            let sigma1 = $e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25);
            let choose = $g ^ ($e & ($f ^ $g));
            $h = $h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add($k)
                .wrapping_add(w[$i % 16]);
            $d = $d.wrapping_add($h);
            let sigma0 = $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22);
            let majority = ($a & $b) | ($c & ($a | $b));
            $h = $h.wrapping_add(sigma0).wrapping_add(majority);
        }};
    }
    round!(0, 0x428a2f98, a, b, c, d, e, f, g, h);
    round!(1, 0x71374491, h, a, b, c, d, e, f, g);
    round!(2, 0xb5c0fbcf, g, h, a, b, c, d, e, f);
    round!(3, 0xe9b5dba5, f, g, h, a, b, c, d, e);
    round!(4, 0x3956c25b, e, f, g, h, a, b, c, d);
    round!(5, 0x59f111f1, d, e, f, g, h, a, b, c);
    round!(6, 0x923f82a4, c, d, e, f, g, h, a, b);
    round!(7, 0xab1c5ed5, b, c, d, e, f, g, h, a);
    round!(8, 0xd807aa98, a, b, c, d, e, f, g, h);
    round!(9, 0x12835b01, h, a, b, c, d, e, f, g);
    round!(10, 0x243185be, g, h, a, b, c, d, e, f);
    round!(11, 0x550c7dc3, f, g, h, a, b, c, d, e);
    round!(12, 0x72be5d74, e, f, g, h, a, b, c, d);
    round!(13, 0x80deb1fe, d, e, f, g, h, a, b, c);
    round!(14, 0x9bdc06a7, c, d, e, f, g, h, a, b);
    round!(15, 0xc19bf174, b, c, d, e, f, g, h, a);
    round!(16, 0xe49b69c1, a, b, c, d, e, f, g, h);
    round!(17, 0xefbe4786, h, a, b, c, d, e, f, g);
    round!(18, 0x0fc19dc6, g, h, a, b, c, d, e, f);
    round!(19, 0x240ca1cc, f, g, h, a, b, c, d, e);
    round!(20, 0x2de92c6f, e, f, g, h, a, b, c, d);
    round!(21, 0x4a7484aa, d, e, f, g, h, a, b, c);
    round!(22, 0x5cb0a9dc, c, d, e, f, g, h, a, b);
    round!(23, 0x76f988da, b, c, d, e, f, g, h, a);
    round!(24, 0x983e5152, a, b, c, d, e, f, g, h);
    round!(25, 0xa831c66d, h, a, b, c, d, e, f, g);
    round!(26, 0xb00327c8, g, h, a, b, c, d, e, f);
    round!(27, 0xbf597fc7, f, g, h, a, b, c, d, e);
    round!(28, 0xc6e00bf3, e, f, g, h, a, b, c, d);
    round!(29, 0xd5a79147, d, e, f, g, h, a, b, c);
    round!(30, 0x06ca6351, c, d, e, f, g, h, a, b);
    round!(31, 0x14292967, b, c, d, e, f, g, h, a);
    round!(32, 0x27b70a85, a, b, c, d, e, f, g, h);
    round!(33, 0x2e1b2138, h, a, b, c, d, e, f, g);
    round!(34, 0x4d2c6dfc, g, h, a, b, c, d, e, f);
    round!(35, 0x53380d13, f, g, h, a, b, c, d, e);
    round!(36, 0x650a7354, e, f, g, h, a, b, c, d);
    round!(37, 0x766a0abb, d, e, f, g, h, a, b, c);
    round!(38, 0x81c2c92e, c, d, e, f, g, h, a, b);
    round!(39, 0x92722c85, b, c, d, e, f, g, h, a);
    round!(40, 0xa2bfe8a1, a, b, c, d, e, f, g, h);
    round!(41, 0xa81a664b, h, a, b, c, d, e, f, g);
    round!(42, 0xc24b8b70, g, h, a, b, c, d, e, f);
    round!(43, 0xc76c51a3, f, g, h, a, b, c, d, e);
    round!(44, 0xd192e819, e, f, g, h, a, b, c, d);
    round!(45, 0xd6990624, d, e, f, g, h, a, b, c);
    round!(46, 0xf40e3585, c, d, e, f, g, h, a, b);
    round!(47, 0x106aa070, b, c, d, e, f, g, h, a);
    round!(48, 0x19a4c116, a, b, c, d, e, f, g, h);
    round!(49, 0x1e376c08, h, a, b, c, d, e, f, g);
    round!(50, 0x2748774c, g, h, a, b, c, d, e, f);
    round!(51, 0x34b0bcb5, f, g, h, a, b, c, d, e);
    round!(52, 0x391c0cb3, e, f, g, h, a, b, c, d);
    round!(53, 0x4ed8aa4a, d, e, f, g, h, a, b, c);
    round!(54, 0x5b9cca4f, c, d, e, f, g, h, a, b);
    round!(55, 0x682e6ff3, b, c, d, e, f, g, h, a);
    round!(56, 0x748f82ee, a, b, c, d, e, f, g, h);
    round!(57, 0x78a5636f, h, a, b, c, d, e, f, g);
    round!(58, 0x84c87814, g, h, a, b, c, d, e, f);
    round!(59, 0x8cc70208, f, g, h, a, b, c, d, e);
    round!(60, 0x90befffa, e, f, g, h, a, b, c, d);
    round!(61, 0xa4506ceb, d, e, f, g, h, a, b, c);
    round!(62, 0xbef9a3f7, c, d, e, f, g, h, a, b);
    round!(63, 0xc67178f2, b, c, d, e, f, g, h, a);
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    #[test]
    fn fips_known_answers() {
        assert_eq!(
            <[_; 32]>::from(Sha256::digest(b"abc")),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        assert_eq!(
            <[_; 32]>::from(Sha256::digest(vec![b'a'; 1_000_000])),
            [
                0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
                0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
                0xc7, 0x11, 0x2c, 0xd0
            ]
        );
    }
    #[test]
    fn differential_lengths_alignments_streaming_reset_and_clone() {
        use sha2_reference::Digest as ReferenceDigest;
        let mut input = vec![0u8; 4112];
        let mut rng = 0x193a7e22b5u64;
        for b in &mut input {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            *b = rng as u8;
        }
        // Includes both sides of every one- and two-block padding boundary.
        for len in 0..=4096 {
            let off = len % 16;
            let data = &input[off..off + len];
            let expected: [u8; 32] = sha2_reference::Sha256::digest(data).into();
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(data)),
                expected,
                "len {len} offset {off}"
            );
            for chunk in [1, 7, 63, 64, 65, 137] {
                let mut h = Sha256::default();
                for part in data.chunks(chunk) {
                    h.update(part);
                }
                assert_eq!(<[u8; 32]>::from(h.clone().finalize()), expected);
                assert_eq!(<[u8; 32]>::from(h.finalize_reset()), expected);
                h.update(data);
                assert_eq!(<[u8; 32]>::from(h.finalize()), expected);
            }
        }
    }
}
