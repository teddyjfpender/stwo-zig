//! Cairo AIR (Algebraic Intermediate Representation) definitions.
//!
//! Contains component constraint files and claim types that define the
//! polynomial constraints for each Cairo opcode, builtin, and memory
//! operation.
//!
//! Constraints are evaluated via the `ExprEvaluator` API from
//! `core/constraint_framework/`.

pub const claims = @import("claims.zig");
pub const components = @import("components/mod.zig");
pub const official_claim_registry = @import("official_claim_registry.zig");

pub const CairoClaim = claims.CairoClaim;
pub const CairoInteractionClaim = claims.CairoInteractionClaim;
pub const PublicData = claims.PublicData;
