//! Physical row-34 writer for the directly proven recursive leaf.
//!
//! This writes the pinned Poseidon2 AIR's preprocessed, main, and interaction
//! columns from an exact ordered call buffer. It is witness materialization,
//! not a proof gate or authority for any requester tuple.

const std = @import("std");
const core = @import("stwo_core");
const poseidon = @import("../air/memory_commitment/poseidon2_air.zig");
const calls_mod = @import("segment_leaf_wrapper_cohort_calls_v3.zig");
const provider_relations = @import("air/universal_provider_relations.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const MAIN_COLUMNS = poseidon.N_MAIN_COLUMNS;
pub const INTERACTION_COLUMNS = poseidon.N_INTERACTION_COLUMNS;
pub const Interaction = poseidon.Interaction;

pub const Writer = struct {
    allocator: std.mem.Allocator,
    buffer: *const calls_mod.Buffer,
    parts: []const []const calls_mod.Call,

    pub fn init(
        allocator: std.mem.Allocator,
        buffer: *const calls_mod.Buffer,
        parts: []const []const calls_mod.Call,
    ) !Writer {
        try buffer.validateAgainst(parts);
        return .{ .allocator = allocator, .buffer = buffer, .parts = parts };
    }

    pub fn logSize(self: *const Writer) !u32 {
        try self.buffer.validateAgainst(self.parts);
        return self.buffer.log_size;
    }

    /// The enclosing cohort compares this with its row-34 placement before
    /// committing Tree 0; an arbitrary caller cannot choose padding.
    pub fn requireLogSize(self: *const Writer, expected: u32) !void {
        if (try self.logSize() != expected) return error.PoseidonProviderGeometryMismatch;
    }

    pub fn fillPreprocessedInto(self: *const Writer, column: []core.fields.m31.M31) !void {
        const log_size = try self.logSize();
        if (column.len != (@as(usize, 1) << @intCast(log_size)))
            return error.PoseidonProviderTraceShapeMismatch;
        @memset(column, core.fields.m31.M31.zero());
        const committed = core.utils.bitReverseIndex(
            core.utils.cosetIndexToCircleDomainIndex(0, log_size),
            log_size,
        );
        column[committed] = core.fields.m31.M31.one();
    }

    pub fn fillMainInto(
        self: *const Writer,
        columns: *[MAIN_COLUMNS][]core.fields.m31.M31,
    ) !void {
        const log_size = try self.logSize();
        try poseidon.generateMainInto(self.allocator, columns, self.buffer.calls, log_size);
    }

    pub fn generateInteraction(
        self: *const Writer,
        relations: *const provider_relations.SharedProviderRelations,
    ) !Interaction {
        const log_size = try self.logSize();
        try relations.validate();
        return poseidon.generateInteraction(
            self.allocator,
            self.buffer.calls,
            log_size,
            &relations.native,
        );
    }
};
