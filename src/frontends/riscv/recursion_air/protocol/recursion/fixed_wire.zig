//! Canonical fixed-width STARK proof substrate for recursive verification.
//!
//! This is not the ordinary owned-slice STWO proof ABI.  Every array dimension
//! is a comptime protocol choice, the PCS configuration is absent from the
//! payload, and variable-depth paths use one canonical zero-padded encoding.
//! A future native adapter may populate this type only after ordinary proof
//! verification has reconstructed the verifier-owned query schedule.
const shard_0 = @import("fixed_wire_fri_layer_wire.zig");
const shard_1 = @import("fixed_wire_fixed_stark_proof_wire.zig");

pub const M31_WORD_BYTES = shard_0.M31_WORD_BYTES;
pub const QM31_BYTES = shard_0.QM31_BYTES;
pub const DIGEST_BYTES = shard_0.DIGEST_BYTES;
pub const U64_BYTES = shard_0.U64_BYTES;
pub const Qm31Wire = shard_0.Qm31Wire;
pub const Error = shard_0.Error;
/// All dimensions of one fixed proof representation.  These values are
/// comptime parameters of `FixedStarkProofWire`; they never appear as
/// proof-selected length prefixes.
pub const Dimensions = shard_1.Dimensions;
pub const MerklePathWire = shard_0.MerklePathWire;
pub const FriQueryWire = shard_0.FriQueryWire;
pub const FriLayerWire = shard_0.FriLayerWire;
/// Produces the exact fixed proof type selected by `dimensions`.
///
/// Large arrays are intentionally inline.  Production callers allocate the
/// value in an arena or dedicated owned buffer; the type itself contains no
/// pointers, slices, optionals, allocator state, or host-sized wire integers.
pub const FixedStarkProofWire = shard_1.FixedStarkProofWire;
pub const validateDimensionsAgainstShape = shard_1.validateDimensionsAgainstShape;
pub const merklePathBytes = shard_0.merklePathBytes;
pub const friQueryBytes = shard_0.friQueryBytes;
pub const friLayerBytes = shard_0.friLayerBytes;
pub const serializedByteCount = shard_1.serializedByteCount;
/// Returns the exact fixed-width encoding size for runtime-selected design
/// dimensions.  This does not confer protocol authority: production wire
/// types still require comptime dimensions and an authenticated shape.
pub const serializedByteCountRuntime = shard_1.serializedByteCountRuntime;
