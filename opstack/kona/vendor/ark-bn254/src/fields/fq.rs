//! Upstream field identity; optional admitted Montgomery adapter.
use ark_ff::fields::{Fp256, MontBackend};
#[cfg(not(any(
    feature = "stwo-montgomery-service",
    feature = "stwo-canonical-service"
)))]
use ark_ff::MontConfig;

#[cfg(not(any(
    feature = "stwo-montgomery-service",
    feature = "stwo-canonical-service"
)))]
#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
pub struct FqConfig;
#[cfg(feature = "stwo-montgomery-service")]
#[path = "fq_service.rs"]
mod service;
#[cfg(feature = "stwo-montgomery-service")]
pub use service::FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

#[cfg(all(
    feature = "stwo-montgomery-service",
    feature = "stwo-canonical-service"
))]
compile_error!("select only one BN254 field service representation");
#[cfg(feature = "stwo-canonical-service")]
#[path = "fq_canonical.rs"]
pub(super) mod canonical;
#[cfg(feature = "stwo-canonical-service")]
pub use canonical::FqConfig;
