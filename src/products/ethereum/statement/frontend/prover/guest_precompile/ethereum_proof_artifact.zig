//! Immutable v2 Ethereum leaf artifact facade; Blake3 selects explicit v6.
const core = @import("stwo_core");
const implementation = @import("ethereum_proof_artifact_impl.zig");
const Legacy = implementation.ForSuite(core.proof_suites.Blake2s);
pub const Blake3 = implementation.ForSuite(core.proof_suites.Blake3);
pub const Limits = Legacy.Limits;
pub const magic = Legacy.magic;
pub const format_version = Legacy.format_version;
pub const header_size = Legacy.header_size;
pub const HeaderOffset = Legacy.HeaderOffset;
pub const EncodeInput = Legacy.EncodeInput;
pub const Decoded = Legacy.Decoded;
pub const encodeAlloc = Legacy.encodeAlloc;
pub const encodeAllocWithLimits = Legacy.encodeAllocWithLimits;
pub const decodeAllocForConfig = Legacy.decodeAllocForConfig;
pub const proofPreflightShape = Legacy.proofPreflightShape;
