//! A hint selects work, never a cryptographic result. False hints use software;
//! a forged success hint must fail in the proved recovery backend.
use alloy_primitives::Address;
use k256::ecdsa::Signature;
use revm_precompile::interface::{Crypto, DefaultCrypto, PrecompileHalt};

pub fn recover(
    sig: &[u8; 64],
    recid: u8,
    msg: &[u8; 32],
    success_hint: bool,
    proved_recovery: impl FnOnce(&[u8; 64], u8, &[u8; 32]) -> [u8; 64],
) -> Result<[u8; 32], PrecompileHalt> {
    if !success_hint || recid > 1 {
        return DefaultCrypto.secp256k1_ecrecover(sig, recid, msg);
    }
    let Ok(signature) = Signature::from_slice(sig) else {
        return DefaultCrypto.secp256k1_ecrecover(sig, recid, msg);
    };
    // EVM accepts high-s signatures. The equivalent low-s signature uses the
    // opposite recovery parity; both must recover exactly the same public key.
    let (signature, parity) = match signature.normalize_s() {
        Some(normalized) => (normalized, recid ^ 1),
        None => (signature, recid),
    };
    let normalized: [u8; 64] = signature.to_bytes().into();
    let public_key = proved_recovery(&normalized, parity, msg);
    let address = Address::from_raw_public_key(&public_key);
    let mut output = [0u8; 32];
    output[12..].copy_from_slice(address.as_slice());
    Ok(output)
}
