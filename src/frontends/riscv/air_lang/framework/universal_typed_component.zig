//! Generic native PCS/FRI adapter for an authenticated recursion typed AIR.
//!
//! `Air` supplies only compiler-owned geometry and its typed arena; `Relation`
//! supplies the matching compiler-lowered interaction runtime and event order.
//! This factory evaluates both direct and LogUp constraints from those sealed
//! programs over M31 on the prover domain and QM31 at verifier OODS points.
//! It contains no component equation, tuple transcription, or roster switch.
const shard_0 = @import("universal_typed_component_contract.zig");
const shard_1 = @import("universal_typed_component_component_for_manifest.zig");

pub const Component = shard_1.Component;
/// Equation-free manifest projection shared by every versioned outer
/// protocol.  Geometry is derived only from the authenticated typed AIR; a
/// manifest may select a different AIR for a versioned row, but it cannot
/// transcribe that AIR's widths, degrees, or semantic identity by hand.
pub const manifestGeometryForAir = shard_0.manifestGeometryForAir;
pub const protocolMaximumConstraintDegree = shard_0.protocolMaximumConstraintDegree;
/// The evaluator is independent of roster cardinality and component naming.
/// V1 uses `Component` above; versioned outer protocols may supply a manifest
/// contract with the same geometry/placement interface and a distinct key
/// enum without copying this performance-critical adapter.
pub const ComponentForManifest = shard_1.ComponentForManifest;
