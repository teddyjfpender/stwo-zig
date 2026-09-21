//! Ethereum row-10 profile for VM composition's two statement-root consumers.
//! Reuses the admitted V2 AIR, changing only its scoped emission weight.
//! The extra multiplicity is fixed preprocessing, never a witness choice.
//! V2 and its native/CSP identities remain unchanged.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("statement_input.zig");
const witness = @import("statement_input_witness.zig");
const roots = @import("vm_statement_roots.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const validate_ir = @import("../../air/lang/validate.zig");

pub const STABLE_NAME = "recursion.statement_input.roots.v3";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 1;
pub const PARAMETER_COUNT = legacy.PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT + 1;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
// Conservative typed-profile bound, including the additional lookup weight.
pub const LOWERED_MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = legacy.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = legacy.INTERACTION_COLUMN_COUNT;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const SEMANTIC_DIGEST_HEX = "3b632ab5b96cdbc56fbcf28c5e10b45db8a6ff933c227d400ad3e75ef44481f2";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk bytes;
};
const event_ids: [RELATION_EVENT_COUNT]types.EffectId = .{
    @enumFromInt(0), @enumFromInt(1), @enumFromInt(2), @enumFromInt(3),
};

pub const Definition = struct {
    arena: ir.Arena,
    events: [RELATION_EVENT_COUNT]types.EffectId = event_ids,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try validate_ir.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.typed_effect_format_version or
            !std.meta.eql(identity.bytes, SEMANTIC_DIGEST) or
            !std.meta.eql(self.events, event_ids))
        {
            return error.InvalidStatementRootRoutingDefinition;
        }
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    // Physical and logical order agree: main, preprocessing, parameters.
    var result = Definition{ .arena = try legacy.buildRootRoutingArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}

/// A stateless, verifier-reconstructible schedule. Callers cannot provide or
/// mutate a use-count array. Hashing includes the AIR seal and every fixed row.
pub const Routing = struct {
    pub const ROW_COUNT = legacy.CANONICAL_WORD_COUNT * legacy.STATEMENT_LANE_COUNT;

    pub fn extraUses(row: witness.Row) u32 {
        return @intFromBool(row.segment_mask == 1 and roots.contains(row.word_index));
    }

    pub fn preprocessing(row: witness.Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return row.values() ++ .{M31.fromCanonical(extraUses(row))};
    }

    pub fn logicalRow(row: witness.Row, words: witness.StatementWitness) !Relation.Row {
        return (try witness.mainRow(row, words)) ++ preprocessing(row) ++ witness.parameters(words.proofKind());
    }

    /// The Ethereum admission owner supplies one fixed plan to both ends of
    /// statement fan-out. These counts are committed preprocessing, never
    /// proof-dependent main columns. The legacy root-only entry point above
    /// retains its original schedule and identity.
    pub fn logicalRowForPlan(row: witness.Row, words: witness.StatementWitness, plan: anytype) !Relation.Row {
        const main = try witness.mainRow(row, words);
        const uses = plan.extraUses(row);
        if (uses >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidStatementRootRoutingDefinition;
        return main ++ row.values() ++ .{M31.fromCanonical(uses)} ++ witness.parameters(words.proofKind());
    }

    /// Writes verifier-reconstructible commitment columns, including padding.
    /// Shape and alias checks precede every write; no intermediate slab exists.
    pub fn fillPreprocessedInto(pp: *const witness.Preprocessed, columns: *[PREPROCESSED_COLUMN_COUNT][]M31) !void {
        try pp.validate();
        const Writer = struct {
            fn validate(row: witness.Row) @import("../../air/lang/direct_witness_executor.zig").Error!void {
                _ = witness.mainRow(row, .empty_leaf) catch return error.InvalidTraceRow;
            }
            fn write(destination: *[PREPROCESSED_COLUMN_COUNT][]M31, index: usize, row: witness.Row) void {
                for (destination, preprocessing(row)) |column, value| column[index] = value;
            }
        };
        try @import("../../air/lang/direct_witness_executor.zig").generateMainInto(M31, witness.Row, PREPROCESSED_COLUMN_COUNT, columns, pp.rows, pp.log_size, M31.zero(), pp, Writer.validate, Writer.write);
    }

    pub fn identity(preprocessed: *const witness.Preprocessed) ![32]u8 {
        try preprocessed.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/statement-root-routing/v3\x00");
        hash.update(&SEMANTIC_DIGEST);
        for (preprocessed.rows) |row| for (preprocessing(row)) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word.toU32(), .little);
            hash.update(&bytes);
        };
        return hash.finalResult();
    }
};
