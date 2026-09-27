//! Genuine typed SHA local-zero source. The containing profile must select a
//! concrete reviewed digest; a generated candidate is never receiver authority.
//! All original program/retirement/RW events and their order remain unchanged.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const original = @import("sha256_memory_caller.zig");
const envelope = @import("x0_caller_envelope_v1.zig");
const lang = @import("../lang/definition.zig");
pub const Layout = original.Layout;
pub const PHYSICAL_MAIN_COLUMN_COUNT = original.PHYSICAL_MAIN_COLUMN_COUNT + 4;
pub const PREPROCESSED_COLUMN_COUNT = original.PREPROCESSED_COLUMN_COUNT;
pub const LOGICAL_INPUT_COUNT = PHYSICAL_MAIN_COLUMN_COUNT + 1;
pub const DIRECT_CONSTRAINT_COUNT = original.DIRECT_CONSTRAINT_COUNT + 34;
pub const RELATION_EVENT_COUNT = original.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE = original.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = original.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = original.INTERACTION_COLUMN_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const PROGRAM_BOUND_PC_INPUTS = original.PROGRAM_BOUND_PC_INPUTS;
/// Reviewed authoring identity, qualified by the parent caller scalar gate.
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, "512c30efdf23c16a4a22a5635e92a764bde2331c1282b08fdd25d42e0e04d914") catch unreachable;
    break :blk result;
};
pub const Definition = ForDigest(SEMANTIC_DIGEST).Definition;
pub const build = ForDigest(SEMANTIC_DIGEST).build;
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const buildCandidate = original.buildLocalZeroCandidate;
pub fn abiId() [32]u8 {
    return envelope.abiId(.sha);
}

pub fn row(record: @import("sha256_memory_record.zig").Record) !Row {
    const old = try original.row(record);
    var result: Row = @splat(M.zero());
    @memcpy(result[0..original.PHYSICAL_MAIN_COLUMN_COUNT], old[0..original.PHYSICAL_MAIN_COLUMN_COUNT]);
    result[PHYSICAL_MAIN_COLUMN_COUNT] = old[original.PHYSICAL_MAIN_COLUMN_COUNT];
    try envelope.fillHintsAndNormalize(.sha, result[0..PHYSICAL_MAIN_COLUMN_COUNT], result[PHYSICAL_MAIN_COLUMN_COUNT]);
    return result;
}

/// The reviewed digest is a compile-time profile parameter, never a proof,
/// statement, tape or receipt field. The canonical profile migration selects this literal explicitly; authoring
/// candidates never replace it at receiver admission.
pub fn ForDigest(comptime expected_digest: [32]u8) type {
    comptime {
        if (std.mem.allEqual(u8, &expected_digest, 0)) @compileError("SHA local-zero AIR requires an independently reviewed semantic digest");
    }
    return struct {
        pub const SEMANTIC_DIGEST = expected_digest;
        pub const PHYSICAL_MAIN_COLUMN_COUNT = @import("sha256_caller_local_zero_v1.zig").PHYSICAL_MAIN_COLUMN_COUNT;
        pub const PREPROCESSED_COLUMN_COUNT = original.PREPROCESSED_COLUMN_COUNT;
        pub const LOGICAL_INPUT_COUNT = @import("sha256_caller_local_zero_v1.zig").LOGICAL_INPUT_COUNT;
        pub const DIRECT_CONSTRAINT_COUNT = @import("sha256_caller_local_zero_v1.zig").DIRECT_CONSTRAINT_COUNT;
        pub const RELATION_EVENT_COUNT = original.RELATION_EVENT_COUNT;
        pub const LOOKUP_BATCH_SIZE = original.LOOKUP_BATCH_SIZE;
        pub const INTERACTION_BATCH_COUNT = original.INTERACTION_BATCH_COUNT;
        pub const INTERACTION_COLUMN_COUNT = original.INTERACTION_COLUMN_COUNT;
        pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
        pub const PROGRAM_BOUND_PC_INPUTS = original.PROGRAM_BOUND_PC_INPUTS;
        pub const Definition = struct {
            arena: lang.ir.Arena,
            events: [original.RELATION_EVENT_COUNT]lang.types.EffectId,
            pub fn deinit(self: *@This()) void {
                self.arena.deinit();
            }
            pub fn validate(self: *const @This()) !void {
                try lang.validate.validate(&self.arena);
                if (self.arena.constraintsView().len != @import("sha256_caller_local_zero_v1.zig").DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != original.RELATION_EVENT_COUNT) return error.InvalidShaCallerGeometry;
                if (!std.mem.eql(u8, &(try lang.digest.computeIdentity(&self.arena)).bytes, &expected_digest)) return error.InvalidShaCallerLocalZeroIdentity;
            }
        };
        pub fn build(a: std.mem.Allocator) !@This().Definition {
            const candidate = try buildCandidate(a);
            var result = @This().Definition{ .arena = candidate.arena, .events = candidate.events };
            errdefer result.deinit();
            try result.validate();
            return result;
        }
        pub const row = @import("sha256_caller_local_zero_v1.zig").row;
    };
}
