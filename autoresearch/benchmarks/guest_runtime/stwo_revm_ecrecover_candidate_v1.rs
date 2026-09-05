//! Non-production Revm ECRECOVER adapter for Stwo's authenticated recovery ABI.
//!
//! This file is a disjoint integration candidate. It is intended to be added
//! as a child module of the guest's existing `crypto::stwo` module, so it uses
//! that module's frozen `RecoveryRecord` and `execute_recovery` definitions
//! instead of cloning or changing the cryptographic ABI.
//!
//! Revm requires invalid recoveries to produce an empty precompile output. The
//! `Crypto` trait expresses that behavior by returning `Err`; Revm converts it
//! to the canonical empty output. The current Stwo runner, however, aborts the
//! instruction before publishing a record for an invalid recovery. Therefore
//! this backend MUST NOT be installed in production until the existing ABI has
//! an authenticated, fail-closed invalid-result path. A zero status observed
//! after a completed instruction is handled correctly here, but is not yet a
//! substitute for that missing runner/AIR authority.

use alloy_primitives::Address;
use revm::precompile::{Crypto, PrecompileHalt};

use super::{RECOVERY_STATUS_SUCCESS, RecoveryRecord, execute_recovery};

/// Production activation stays false until invalid-input and event parity are
/// proven over a fresh guest execution and proof-verifier transaction.
pub(super) const PRODUCTION_ACTIVATION: bool = false;

#[derive(Debug, Default)]
pub(super) struct StwoRevmEcrecoverCandidateV1;

impl Crypto for StwoRevmEcrecoverCandidateV1 {
    #[inline]
    fn secp256k1_ecrecover(
        &self,
        signature: &[u8; 64],
        recovery_id: u8,
        digest: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        recover_address_word(signature, recovery_id, digest)
    }
}

#[inline]
fn recover_address_word(
    signature: &[u8; 64],
    recovery_id: u8,
    digest: &[u8; 32],
) -> Result<[u8; 32], PrecompileHalt> {
    let mut signature_with_id = [0u8; 65];
    signature_with_id[..64].copy_from_slice(signature);
    signature_with_id[64] = recovery_id;

    let mut record = RecoveryRecord::new(&signature_with_id, digest)
        .map_err(|_| PrecompileHalt::Secp256k1RecoverFailed)?;
    execute_recovery(&mut record);
    if record.status_le != RECOVERY_STATUS_SUCCESS {
        return Err(PrecompileHalt::Secp256k1RecoverFailed);
    }

    // This reuses the guest's native-Keccak hook. The custom recovery opcode
    // authenticates the raw 64-byte public key; Ethereum's ECRECOVER output is
    // the rightmost 20 bytes of Keccak256(x || y), left-padded to 32 bytes.
    let address = Address::from_raw_public_key(&record.public_key_xy_be);
    let mut output = [0u8; 32];
    output[12..].copy_from_slice(address.as_slice());
    Ok(output)
}

/// The candidate file deliberately exposes no production installer.
///
/// A later integration tranche may add an explicitly non-production feature
/// which calls `revm::install_crypto(StwoRevmEcrecoverCandidateV1)`. The normal
/// Stwo guest must continue installing only Alloy's transaction signer
/// provider while `PRODUCTION_ACTIVATION` is false.
pub(super) const fn production_activation_enabled() -> bool {
    PRODUCTION_ACTIVATION
}
