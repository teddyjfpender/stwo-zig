//! Compatibility exports for shared parent artifact custody and command handling.
const owner = @import("stwo_riscv_frontend").recursion.detached_parent_command_v1;
pub const MAX_KEY_BYTES = owner.MAX_KEY_BYTES;
pub const MAX_INPUT_BYTES = owner.MAX_INPUT_BYTES;
pub const hash = owner.hash;
pub const OwnedKeyV1 = owner.OwnedKeyV1;
pub const decodeExpected = owner.decodeExpected;
pub const encodeExpected = owner.encodeExpected;
pub const ClaimsFileV1 = owner.ClaimsFileV1;
pub const decodeClaims = owner.decodeClaims;
pub const CandidateHashesV1 = owner.CandidateHashesV1;
pub const retainCandidate = owner.retainCandidate;
pub const ReceiptV1 = owner.ReceiptV1;
pub const verifyDirectory = owner.verifyDirectory;
pub const main = owner.main;
pub const deriveExpected = owner.deriveExpected;
pub const foldExpected = owner.foldExpected;
