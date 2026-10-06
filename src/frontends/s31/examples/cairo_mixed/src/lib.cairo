// Equivalent to mixed4.s31.json: eight M31 rounds followed by Blake2s.
use core::blake::blake2s_finalize;

const P: u64 = 2147483647;
const M31_MODULUS: u32 = 2147483647;

fn hash4(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let state = BoxTrait::new([
        0x6b08e647_u32, 0xbb67ae85_u32, 0x3c6ef372_u32, 0xa54ff53a_u32,
        0x510e527f_u32, 0x9b05688c_u32, 0x1f83d9ab_u32, 0x5be0cd19_u32,
    ]);
    let message = BoxTrait::new([
        a, b, c, d, 0_u32, 0_u32, 0_u32, 0_u32,
        0_u32, 0_u32, 0_u32, 0_u32, 0_u32, 0_u32, 0_u32, 0_u32,
    ]);
    let [d0, d1, d2, d3, d4, d5, d6, d7] = blake2s_finalize(state, 16_u32, message).unbox();
    (
        d0 % M31_MODULUS, d1 % M31_MODULUS,
        d2 % M31_MODULUS, d3 % M31_MODULUS,
        d4 % M31_MODULUS, d5 % M31_MODULUS,
        d6 % M31_MODULUS, d7 % M31_MODULUS,
    )
}

fn m31_step(x: u32) -> u32 {
    let wide: u64 = x.into();
    let product = wide * wide + 7_u64;
    let first = (product & P) + (product / 2147483648_u64);
    let second = (first & P) + (first / 2147483648_u64);
    let reduced = if second >= P { second - P } else { second };
    reduced.try_into().unwrap()
}

fn mixed(x: u16) -> u32 {
    let mut value: u32 = x.into();
    let mut i = 0_u32;
    while i < 8_u32 {
        value = m31_step(value);
        i += 1;
    }
    value
}

#[executable]
fn main(a: u16, b: u16, c: u16, d: u16) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    hash4(mixed(a), mixed(b), mixed(c), mixed(d))
}
