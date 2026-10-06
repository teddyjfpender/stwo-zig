//! Physical row-34 writer for the directly proven recursive leaf.
//!
//! This writes the pinned Poseidon2 AIR's preprocessed, main, and interaction
//! columns from an exact ordered call buffer. It is witness materialization,
//! not a proof gate or authority for any requester tuple.

const std = @import("std");
const core = @import("stwo_core");
const poseidon = @import("../air/memory_commitment/poseidon2_air.zig");
const poseidon_layout = @import("../air/memory_commitment/poseidon2_layout.zig");
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

    /// Reuses outputs in the committed main trace instead of running every
    /// Poseidon permutation again. The row-34 AIR constrains those outputs to
    /// the input calls; this witness shortcut does not replace that check.
    pub fn generateInteractionFromMain(
        self: *const Writer,
        columns: *const [MAIN_COLUMNS][]core.fields.m31.M31,
        relations: *const provider_relations.SharedProviderRelations,
    ) !Interaction {
        const log_size = try self.logSize();
        try relations.validate();
        const size = @as(usize, 1) << @intCast(log_size);
        for (columns) |column| if (column.len != size)
            return error.PoseidonProviderTraceShapeMismatch;
        const outputs = try self.allocator.alloc([poseidon.WIDTH]u32, self.buffer.calls.len);
        defer self.allocator.free(outputs);
        for (self.buffer.calls, outputs, 0..) |call, *output, logical_row| {
            const committed = core.utils.bitReverseIndex(
                core.utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
                log_size,
            );
            if (!columns[0][committed].isOne() or
                !columns[poseidon_layout.WIDE_COLUMN][committed].isZero() or
                !columns[poseidon_layout.IO_COLUMN][committed].isOne())
                return error.PoseidonProviderMainMismatch;
            for (call.input, 0..) |word, lane| {
                if (columns[poseidon_layout.INPUT_START + lane][committed].toU32() != word)
                    return error.PoseidonProviderMainMismatch;
            }
            for (output, 0..) |*word, lane| {
                word.* = columns[poseidon_layout.OUTPUT_START + lane][committed].toU32();
                if (word.* >= core.fields.m31.Modulus)
                    return error.NonCanonicalPoseidonOutput;
            }
        }
        return poseidon.generateIoInteractionFromOutputs(
            self.allocator,
            self.buffer.calls,
            outputs,
            log_size,
            &relations.native,
        );
    }
};
