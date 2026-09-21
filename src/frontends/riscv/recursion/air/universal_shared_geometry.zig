//! Shared provider geometry and deliberate identity compatibility, without witnesses.
const std = @import("std");
const wide = @import("../../air/memory_commitment/poseidon2_layout.zig");
const compact_air = @import("../../air/memory_commitment/poseidon2_universal_equations_v1.zig");
const compact_identity = @import("../../air/memory_commitment/poseidon2_universal_identity_v2.zig");
const range = @import("range_check_8_8_contract.zig");
const roster = @import("universal_roster.zig");

pub const POSEIDON_SOURCE_AUTHORITY_DIGEST = hexDigest(
    "eb2603d73ce1dd3d71c67bb380a751303782ca668ef0a657eccc668658c57252",
    "invalid recursion Poseidon2 source-authority digest",
);

pub const POSEIDON_PREPROCESSED_COLUMN_COUNT: u16 = 1;
pub const POSEIDON_MAIN_COLUMN_COUNT: u16 = wide.N_MAIN_COLUMNS;
pub const POSEIDON_INTERACTION_BATCH_COUNT: u16 = wide.N_SUMS;
pub const POSEIDON_INTERACTION_COLUMN_COUNT: u16 =
    wide.N_INTERACTION_COLUMNS;
pub const POSEIDON_DIRECT_CONSTRAINT_COUNT: u16 =
    wide.N_CONSTRAINTS;
pub const POSEIDON_PROTOCOL_CONSTRAINT_DEGREE: u8 =
    wide.MAXIMUM_CONSTRAINT_DEGREE;
/// A degree-three component evaluates its quotient on `log_size + 1`.
/// M31's largest constructible circle domain has log size 30, so a trace at
/// log size 30 would be admitted successfully and fail only inside proving.
pub const POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT: u32 = 30;

pub const RANGE_PREPROCESSED_COLUMN_COUNT: u16 =
    range.FRAMEWORK_PREPROCESSED_COLUMN_COUNT;
pub const RANGE_MAIN_COLUMN_COUNT: u16 =
    range.PHYSICAL_MAIN_COLUMN_COUNT;
pub const RANGE_INTERACTION_BATCH_COUNT: u16 =
    range.INTERACTION_BATCH_COUNT;
pub const RANGE_INTERACTION_COLUMN_COUNT: u16 =
    range.INTERACTION_COLUMN_COUNT;
pub const RANGE_DIRECT_CONSTRAINT_COUNT: u16 = 0;
pub const RANGE_PROTOCOL_CONSTRAINT_DEGREE: u8 = 3;

pub fn PoseidonForManifest(comptime manifest_contract: type, comptime compact: bool, comptime compatibility: compact_identity.Compatibility) type {
    const SelectedAir = if (compact) compact_air else wide;
    return struct {
        pub fn manifestGeometry(log_size: u32) manifest_contract.Geometry {
            return .{
                .roster_row = @intFromEnum(roster.Component.poseidon2),
                .log_size = log_size,
                .preprocessed_columns = POSEIDON_PREPROCESSED_COLUMN_COUNT,
                .main_columns = SelectedAir.N_MAIN_COLUMNS,
                .interaction_columns = POSEIDON_INTERACTION_COLUMN_COUNT,
                .direct_constraints = SelectedAir.N_CONSTRAINTS,
                .interaction_batches = POSEIDON_INTERACTION_BATCH_COUNT,
                .protocol_constraint_degree = POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
                .profiled_constraint_degree = POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
                .semantic_digest = if (compact) compact_identity.CANONICAL_DIGEST else POSEIDON_SOURCE_AUTHORITY_DIGEST,
            };
        }

        pub fn acceptsGeometry(geometry: manifest_contract.Geometry) bool {
            var expected = manifestGeometry(geometry.log_size);
            if (compact and compatibility == .allow_reviewed_legacy and
                std.mem.eql(u8, &geometry.semantic_digest, &compact_identity.LEGACY_SOURCE_DIGEST))
                expected.semantic_digest = compact_identity.LEGACY_SOURCE_DIGEST;
            return std.meta.eql(geometry, expected);
        }
    };
}

pub fn RangeForManifest(comptime manifest_contract: type) type {
    return struct {
        pub fn manifestGeometry() manifest_contract.Geometry {
            return .{
                .roster_row = @intFromEnum(roster.Component.range_check_8_8),
                .log_size = range.LOG_SIZE,
                .preprocessed_columns = RANGE_PREPROCESSED_COLUMN_COUNT,
                .main_columns = RANGE_MAIN_COLUMN_COUNT,
                .interaction_columns = RANGE_INTERACTION_COLUMN_COUNT,
                .direct_constraints = RANGE_DIRECT_CONSTRAINT_COUNT,
                .interaction_batches = RANGE_INTERACTION_BATCH_COUNT,
                .protocol_constraint_degree = RANGE_PROTOCOL_CONSTRAINT_DEGREE,
                .profiled_constraint_degree = RANGE_PROTOCOL_CONSTRAINT_DEGREE,
                .semantic_digest = range.BINDING_DIGEST,
            };
        }
    };
}

fn hexDigest(
    comptime value: []const u8,
    comptime message: []const u8,
) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (POSEIDON_MAIN_COLUMN_COUNT != 445 or
        POSEIDON_INTERACTION_COLUMN_COUNT != 8 or
        POSEIDON_DIRECT_CONSTRAINT_COUNT != 430 or
        RANGE_PREPROCESSED_COLUMN_COUNT != 3 or
        RANGE_MAIN_COLUMN_COUNT != 1 or
        RANGE_INTERACTION_COLUMN_COUNT != 4 or
        POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT != 30)
    {
        @compileError("universal shared-provider geometry drifted");
    }
}
