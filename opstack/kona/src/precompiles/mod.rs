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

#[cfg(feature = "pairing-hints")]
pub fn install_hinted(input: &'static [u8]) -> Option<&'static [u8]> {
    let base = pairing::install_hints(input)?;
    install().then_some(base)
}

#[cfg(all(feature = "pairing-hints", feature = "host"))]
pub fn collect_hints(input: Vec<u8>) -> Result<Vec<u8>, alloc::string::String> {
    use crate::{
        execution::execute,
        witness::{Validation, Witness},
    };
    if !install() {
        return Err("cannot install pairing hint collector".into());
    }
    pairing::start_hint_collection();
    let witness = Witness::parse(&input, Validation::Eager).map_err(|e| alloc::format!("{e}"))?;
    execute(&witness)?;
    pairing::finish_hint_collection(input).ok_or_else(|| "pairing hint size limit".into())
}

/// Replay real requests under the same bounded cache and expose exact public
/// input keys to host-side reuse analysis. This code is absent from RV64 guests.
#[cfg(all(feature = "pairing-hints", feature = "host"))]
pub fn collect_pairing_census(
    input: Vec<u8>,
) -> Result<Vec<pairing::CensusRow>, alloc::string::String> {
    pairing::start_census();
    let result = collect_hints(input);
    let rows = pairing::finish_census();
    result.map(|_| rows)
}

/// Synthetic packet ABI qualification, separate from OP execution admission.
#[cfg(feature = "pairing-packet-probe")]
pub fn pairing_packet_probe() -> [u8; 43] {
    pairing::packet_probe()
}
