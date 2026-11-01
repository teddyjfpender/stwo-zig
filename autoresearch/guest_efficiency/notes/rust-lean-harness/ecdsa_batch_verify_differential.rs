extern crate alloc;
mod recover_block {
    pub struct UncompressedPublicKey(pub [u8; 65]);
}
mod validation {
    #[derive(Debug)]
    pub enum StatelessValidationError { SignerRecovery }
}
#[path = "/private/tmp/stwo-rv64-guest-rust-lean/autoresearch/benchmarks/guest_runtime/ethereum/rv64/vendor/stateless/src/stwo_verify.rs"]
mod stwo_verify;

use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use recover_block::UncompressedPublicKey;

// reference: alloy impl_k256::recover_signer_unchecked + address comparison
fn reference(vk: &UncompressedPublicKey, sig: &Signature, hash: B256) -> bool {
    if vk.0[0] != 4 { return false; }
    let expected = Address::from_raw_public_key(&vk.0[1..]);
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&sig.r().to_be_bytes::<32>());
    b[32..].copy_from_slice(&sig.s().to_be_bytes::<32>());
    let Ok(mut signature) = k256::ecdsa::Signature::from_slice(&b) else { return false };
    let mut recid = sig.v() as u8;
    if let Some(n) = signature.normalize_s() { signature = n; recid ^= 1; }
    let recid = RecoveryId::from_byte(recid).unwrap();
    let Ok(key) = VerifyingKey::recover_from_prehash(&hash[..], &signature, recid) else { return false };
    let pt = key.to_encoded_point(false);
    let addr = Address::from_slice(&keccak256(&pt.as_bytes()[1..])[12..]);
    addr == expected
}

fn ours(items: &[(UncompressedPublicKey, Signature, B256)]) -> bool {
    let v: Vec<_> = items.iter().map(|(k, s, h)| (k, s, *h)).collect();
    let e: Vec<_> = items.iter().map(|(k, _, _)| Address::from_raw_public_key(&k.0[1..])).collect();
    stwo_verify::verify_senders(v, e).is_ok()
}

struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn bytes32(&mut self) -> [u8; 32] { let mut b = [0u8; 32]; for c in b.chunks_mut(8) { c.copy_from_slice(&self.next().to_le_bytes()); } b } }

fn main() {
    let n = U256::from_be_slice(&hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));
    let p = U256::from_be_slice(&hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"));
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut stats = [0usize; 2];
    let mut pool = Vec::new();
    for case in 0..3000 {
        let sk = loop { if let Ok(k) = SigningKey::from_slice(&rng.bytes32()) { break k } };
        let hash = B256::from(rng.bytes32());
        let (s0, recid) = sk.sign_prehash_recoverable(&hash[..]).unwrap();
        let vkb: [u8; 65] = sk.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        let r = U256::from_be_slice(&s0.r().to_bytes());
        let s = U256::from_be_slice(&s0.s().to_bytes());
        let v = recid.is_y_odd();
        let other: [u8; 65] = SigningKey::from_slice(&rng.bytes32()).map(|k| k.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()).unwrap_or(vkb);
        let mut variants: Vec<(UncompressedPublicKey, Signature, B256)> = vec![
            (UncompressedPublicKey(vkb), Signature::new(r, s, v), hash),
            (UncompressedPublicKey(vkb), Signature::new(r, s, !v), hash),
            (UncompressedPublicKey(vkb), Signature::new(r, n - s, !v), hash), // high s, equivalent
            (UncompressedPublicKey(vkb), Signature::new(r, n - s, v), hash),
            (UncompressedPublicKey(other), Signature::new(r, s, v), hash),
            (UncompressedPublicKey(vkb), Signature::new(r, s, v), B256::from(rng.bytes32())),
            (UncompressedPublicKey(vkb), Signature::new(U256::ZERO, s, v), hash),
            (UncompressedPublicKey(vkb), Signature::new(r, U256::ZERO, v), hash),
            (UncompressedPublicKey(vkb), Signature::new(n, s, v), hash),
            (UncompressedPublicKey(vkb), Signature::new(r + n, s, v), hash),
            (UncompressedPublicKey(vkb), Signature::new(r, s + n, v), hash),
            (UncompressedPublicKey(vkb), Signature::new(U256::from_be_slice(&rng.bytes32()) % n, s, v), hash),
        ];
        // off-curve and non-canonical keys
        let mut bad = vkb; bad[64] ^= 1; variants.push((UncompressedPublicKey(bad), Signature::new(r, s, v), hash));
        let mut bad = vkb; bad[0] = 3; variants.push((UncompressedPublicKey(bad), Signature::new(r, s, v), hash));
        let mut bad = vkb; let y = U256::from_be_slice(&vkb[33..]); if y < U256::MAX - p { bad[33..].copy_from_slice(&(y + p).to_be_bytes::<32>()); variants.push((UncompressedPublicKey(bad), Signature::new(r, s, v), hash)); }
        // negated key (same x, other y)
        let mut neg = vkb; neg[33..].copy_from_slice(&(p - U256::from_be_slice(&vkb[33..])).to_be_bytes::<32>()); variants.push((UncompressedPublicKey(neg), Signature::new(r, s, v), hash));
        for (i, item) in variants.into_iter().enumerate() {
            let want = reference(&item.0, &item.1, item.2);
            let got = ours(core::slice::from_ref(&item));
            assert_eq!(want, got, "case {case} variant {i}");
            stats[want as usize] += 1;
            if case % 7 == 0 { pool.push((item, want)); }
        }
    }
    // batches: all-valid batches accept; any invalid member rejects the batch
    let mut k = 0;
    while k + 9 < pool.len() {
        let chunk = &pool[k..k + 9];
        let items: Vec<_> = chunk.iter().map(|((a, b, c), _)| (UncompressedPublicKey(a.0), *b, *c)).collect();
        let want = chunk.iter().all(|(_, w)| *w);
        assert_eq!(ours(&items), want, "batch at {k}");
        let valid: Vec<_> = chunk.iter().filter(|(_, w)| *w).map(|((a, b, c), _)| (UncompressedPublicKey(a.0), *b, *c)).collect();
        assert!(ours(&valid), "valid batch at {k}");
        k += 9;
    }
    println!("ok: accept {} reject {}", stats[1], stats[0]);
}
fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect() }
