#[cfg(not(feature = "stwo-canonical-fr-service"))]
use ark_ff::MontConfig;
use ark_ff::fields::{Fp256, MontBackend};

#[cfg(not(feature = "stwo-canonical-fr-service"))]
#[derive(MontConfig)]
#[modulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[generator = "7"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "1"]
pub struct FrConfig;
#[cfg(feature = "stwo-canonical-fr-service")]
#[path = "fr_canonical.rs"]
pub(super) mod canonical;
#[cfg(feature = "stwo-canonical-fr-service")]
pub use canonical::FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

/// Pure audit encoder for the existing canonical multiplication packet; no ECALL.
#[cfg(feature = "stwo-canonical-fr-service")]
#[doc(hidden)]
pub fn stwo_canonical_fr_packet(a: [u64; 4], b: [u64; 4]) -> [u64; 20] {
    canonical::packet(a, b).0
}
