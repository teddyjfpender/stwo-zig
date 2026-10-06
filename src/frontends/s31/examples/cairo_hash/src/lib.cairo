// The same 16-byte Blake2s message and M31-reduced digest as hash4.s31.json.
use core::blake::blake2s_finalize;

const M31_MODULUS: u32 = 2147483647;

pub fn hash4(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let state = BoxTrait::new([
        0x6b08e647_u32, 0xbb67ae85_u32, 0x3c6ef372_u32, 0xa54ff53a_u32,
        0x510e527f_u32, 0x9b05688c_u32, 0x1f83d9ab_u32, 0x5be0cd19_u32,
    ]);
    let message = BoxTrait::new([
        a, b, c, d, 0_u32, 0_u32, 0_u32, 0_u32,
        0_u32, 0_u32, 0_u32, 0_u32, 0_u32, 0_u32, 0_u32, 0_u32,
    ]);
    let digest = blake2s_finalize(state, 16_u32, message).unbox();
    let [d0, d1, d2, d3, d4, d5, d6, d7] = digest;
    (
        d0 % M31_MODULUS, d1 % M31_MODULUS,
        d2 % M31_MODULUS, d3 % M31_MODULUS,
        d4 % M31_MODULUS, d5 % M31_MODULUS,
        d6 % M31_MODULUS, d7 % M31_MODULUS,
    )
}

#[executable]
fn main(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    hash4(a, b, c, d)
}
