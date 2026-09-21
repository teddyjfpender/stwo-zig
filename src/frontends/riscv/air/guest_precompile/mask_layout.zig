//! Native OODS mask order shared by prover components and verifier protocols.
pub const SECP256K1_MAIN_MASK_OFFSETS = [_]isize{ 0, -1, 1 };
pub const KECCAKF_STATE_MASK_OFFSETS = [_]isize{ 0, -2, -1, 1, 2, 27 };
