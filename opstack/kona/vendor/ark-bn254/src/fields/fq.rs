//! Upstream field identity; optional admitted Montgomery adapter.
use ark_ff::fields::{Fp256, MontBackend};
#[cfg(not(feature = "stwo-montgomery-service"))]
use ark_ff::MontConfig;

#[cfg(not(feature = "stwo-montgomery-service"))]
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
