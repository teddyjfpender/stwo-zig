//! Service-backed crypto through Revm's existing provider seam. Fork activation,
//! input padding, gas and EVM failure handling remain in pinned Revm/OP Revm.
//! No pairing, KZG or P256 operation is replaced by an unchecked host hint.
use crate::statement_sha2::{Digest, Sha256};
use alloc::vec::Vec;
use revm_precompile::{Crypto, DefaultCrypto, PrecompileHalt};
mod bn254;
mod modular;
#[cfg(feature = "pairing-cache")]
mod pairing;

#[derive(Debug)]
pub struct Services;

impl Crypto for Services {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        Sha256::digest(input).into()
    }

    fn modexp(
        &self,
        base: &[u8],
        exponent: &[u8],
        modulus: &[u8],
    ) -> Result<Vec<u8>, PrecompileHalt> {
        if base.len() <= 32 && modulus.len() <= 32 {
            Ok(modular::pow(base, exponent, modulus))
        } else {
            // Full-width reference remains available; no truncation or odd-only
            // Montgomery restriction is imposed on EVM modular exponentiation.
            DefaultCrypto.modexp(base, exponent, modulus)
        }
    }

    fn bn254_g1_add(&self, p: &[u8], q: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        bn254::add(p, q)
    }

    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        bn254::mul(point, scalar)
    }

    #[cfg(feature = "pairing-cache")]
    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        pairing::check(pairs)
    }
}

/// Called once before any EVM executes. A previously installed provider is an
/// error, not an implicit switch back to a different crypto implementation.
pub fn install() -> bool {
    revm_precompile::install_crypto(Services)
}

#[cfg(test)]
mod tests;
