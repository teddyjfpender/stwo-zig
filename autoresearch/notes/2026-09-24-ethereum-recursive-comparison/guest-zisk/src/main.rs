#![no_main]
ziskos::entrypoint!(main);
use eth_auth_common::Crypto;
struct Native;
fn limbs(x: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_be_bytes(x[24 - i * 8..32 - i * 8].try_into().unwrap()))
}
impl Crypto for Native {
    fn keccak(d: &[u8]) -> [u8; 32] {
        ziskos::zisklib::keccak256(d)
    }
    fn recover(d: &[u8; 32], r: &[u8; 32], s: &[u8; 32], p: u8) -> Option<[u8; 64]> {
        let key =
            ziskos::zisklib::ecdsa_recover_secp256k1(&limbs(r), &limbs(s), &limbs(d), p).ok()?;
        let mut out = [0; 64];
        for coordinate in 0..2 {
            for i in 0..4 {
                out[coordinate * 32 + i * 8..coordinate * 32 + i * 8 + 8]
                    .copy_from_slice(&key[coordinate * 4 + 3 - i].to_be_bytes());
            }
        }
        Some(out)
    }
}
fn main() {
    let input = ziskos::io::read_slice();
    let len = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
    let out = eth_auth_common::run::<Native>(&input[4..4 + len]).unwrap_or([0; 72]);
    ziskos::io::commit_slice(&out);
}
