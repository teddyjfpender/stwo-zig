//! Native witness bridge for the full-state incremental-memory V3 profile.
//!
//! The changed-only transition owner authenticates the raw entry/exit Merkle
//! paths and reuses untouched subtrees. This adapter supplies the real entry
//! predecessor clocks and the independently derived ternary memory-bus
//! multiplicities without changing any raw word, root, node, or Poseidon row.
//!
//! Role derivation and public-I/O linkage live at the versioned statement
//! boundary. This module accepts only the already-derived typed policy and
//! checks its shape against the transition before exposing a proof witness.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const incremental_bridge =
    @import("../air/memory_commitment/incremental_bridge_v2.zig");
const transition_v1 = @import("../air/memory_commitment/incremental_transition_v1.zig");
const transition_v2 = @import("../air/memory_commitment/incremental_transition_v2.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const public_data_mod = @import("../air/public_data.zig");
const memory_state = @import("../runner/memory_state.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");

pub const PRODUCTION_ACTIVE = false;
pub const PROFILE = "riscv-incremental-commitment-witness-v3";

pub const MemoryMultiplicityV3 = enum(i8) {
    exit = -1,
    none = 0,
    entry = 1,

    fn field(self: MemoryMultiplicityV3) M31 {
        return switch (self) {
            .entry => M31.one(),
            .none => M31.zero(),
            .exit => M31.one().neg(),
        };
    }
};

pub const RowPolicyV3 = struct {
    entry_clock: u32,
    entry_memory: MemoryMultiplicityV3,
    exit_memory: MemoryMultiplicityV3,
};

pub const ExpectedRootsV3 = struct {
    entry: u32,
    exit: u32,
};

pub const BoundaryWitnessV3 = struct {
    transition: transition_v2.Witness,

    pub fn deinit(self: *BoundaryWitnessV3) void {
        self.transition.deinit();
        self.* = undefined;
    }

    pub fn rows(self: *const BoundaryWitnessV3) []const memory_boundary.Row {
        return self.transition.boundary_rows;
    }

    /// Exact changed-only bridge rows retained by the transition owner. The
    /// native base consumes `rows()` while the appended V3 component consumes
    /// this disjoint view; neither caller reaches through the transition's
    /// storage representation or takes ownership of its buffers.
    pub fn bridgeRows(
        self: *const BoundaryWitnessV3,
    ) []const incremental_bridge.Row {
        return self.transition.bridge_rows;
    }

    pub fn roots(self: *const BoundaryWitnessV3) ExpectedRootsV3 {
        return .{
            .entry = self.transition.entry_root,
            .exit = self.transition.exit_root,
        };
    }

    pub fn verifyMerkleAndPoseidonCancellation(
        self: *const BoundaryWitnessV3,
        relations: *const relations_mod.Relations,
    ) !void {
        try self.transition.verifyMerkleAndPoseidonCancellation(relations);
    }
};

/// Complete base-prover custody for one incremental segment. `base` owns the
/// program, boundary, Merkle and Poseidon tables; `boundary` retains the same
/// transition independently so its bridge rows can be committed as an
/// appended component under the shared relation draw.
pub const FullWitnessV3 = struct {
    base: commitment_witness.CommitmentWitness,
    boundary: BoundaryWitnessV3,

    pub fn deinit(self: *FullWitnessV3, allocator: std.mem.Allocator) void {
        self.boundary.deinit();
        self.base.deinit(allocator);
        self.* = undefined;
    }
};

pub fn buildFull(
    allocator: std.mem.Allocator,
    exec_trace: *const trace_mod.Trace,
    opt_memory: ?*const memory_state.Snapshot,
    completion: public_data_mod.Completion,
    touched_words: []const transition_v1.TouchedWord,
    canonical_frontier: []const transition_v1.FrontierNode,
    row_policy: []const RowPolicyV3,
    expected_roots: ExpectedRootsV3,
) !FullWitnessV3 {
    var boundary = try buildBoundary(
        allocator,
        touched_words,
        canonical_frontier,
        row_policy,
        expected_roots,
    );
    errdefer boundary.deinit();
    const base = try commitment_witness.CommitmentWitness
        .buildWithIncrementalBoundaryV3(
        allocator,
        exec_trace,
        opt_memory,
        completion,
        boundary.transition.boundary_rows,
        boundary.transition.merkle_rows,
        boundary.transition.poseidon_calls,
        .{ .entry = expected_roots.entry, .exit = expected_roots.exit },
    );
    return .{ .base = base, .boundary = boundary };
}

/// Joined external-profile constructor. `execution_sources` remains a tuple
/// of borrowed statement-ordered row tapes; no concatenation or second base
/// witness is permitted. The independently retained boundary continues to
/// supply the appended bridge while `base` owns the copied transition tables.
pub fn buildFullExternalProfile(
    allocator: std.mem.Allocator,
    selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
    execution_sources: anytype,
    opt_memory: ?*const memory_state.Snapshot,
    completion: public_data_mod.Completion,
    touched_words: []const transition_v1.TouchedWord,
    canonical_frontier: []const transition_v1.FrontierNode,
    row_policy: []const RowPolicyV3,
    expected_roots: ExpectedRootsV3,
) !FullWitnessV3 {
    var boundary = try buildBoundary(
        allocator,
        touched_words,
        canonical_frontier,
        row_policy,
        expected_roots,
    );
    errdefer boundary.deinit();
    const base = try commitment_witness.CommitmentWitness
        .buildExternalProfileWithIncrementalBoundaryV3(
        allocator,
        selected_profile,
        execution_sources,
        opt_memory,
        completion,
        boundary.transition.boundary_rows,
        boundary.transition.merkle_rows,
        boundary.transition.poseidon_calls,
        .{ .entry = expected_roots.entry, .exit = expected_roots.exit },
    );
    return .{ .base = base, .boundary = boundary };
}

/// Builds the external-profile base around an already cold-derived boundary.
/// On success `boundary` is moved into the returned owner and set undefined;
/// on failure the caller retains it unchanged. This lets an integration mint
/// its profile geometry and proof witness from one STWIMT reconstruction.
pub fn buildFullExternalProfileFromBoundary(
    allocator: std.mem.Allocator,
    selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
    execution_sources: anytype,
    opt_memory: ?*const memory_state.Snapshot,
    completion: public_data_mod.Completion,
    boundary: *BoundaryWitnessV3,
) !FullWitnessV3 {
    const roots_value = boundary.roots();
    const base = try commitment_witness.CommitmentWitness
        .buildExternalProfileWithIncrementalBoundaryV3(
        allocator,
        selected_profile,
        execution_sources,
        opt_memory,
        completion,
        boundary.transition.boundary_rows,
        boundary.transition.merkle_rows,
        boundary.transition.poseidon_calls,
        .{ .entry = roots_value.entry, .exit = roots_value.exit },
    );
    const moved = boundary.*;
    boundary.* = undefined;
    return .{ .base = base, .boundary = moved };
}

/// Prepared-program twin of `buildFullExternalProfileFromBoundary`.
/// The boundary move and failure ownership are identical. The statically
/// typed prepared owner remains borrowed; `base` owns only the leaf-specific
/// program rows and its ordinary copied Merkle/Poseidon tables.
pub fn buildFullExternalProfileFromBoundaryPreparedProgram(
    allocator: std.mem.Allocator,
    selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
    execution_sources: anytype,
    opt_memory: ?*const memory_state.Snapshot,
    completion: public_data_mod.Completion,
    prepared_program: anytype,
    boundary: *BoundaryWitnessV3,
) !FullWitnessV3 {
    const roots_value = boundary.roots();
    const base = try commitment_witness.CommitmentWitness
        .buildExternalProfileWithPreparedProgramAndIncrementalBoundaryV3(
        allocator,
        selected_profile,
        execution_sources,
        opt_memory,
        completion,
        prepared_program,
        boundary.transition.boundary_rows,
        boundary.transition.merkle_rows,
        boundary.transition.poseidon_calls,
        .{ .entry = roots_value.entry, .exit = roots_value.exit },
    );
    const moved = boundary.*;
    boundary.* = undefined;
    return .{ .base = base, .boundary = moved };
}

pub fn buildBoundary(
    allocator: std.mem.Allocator,
    touched_words: []const transition_v1.TouchedWord,
    canonical_frontier: []const transition_v1.FrontierNode,
    row_policy: []const RowPolicyV3,
    expected_roots: ExpectedRootsV3,
) !BoundaryWitnessV3 {
    if (touched_words.len == 0 or touched_words.len != row_policy.len)
        return error.InvalidIncrementalBoundaryPolicyShape;

    var transition = try transition_v2.build(
        allocator,
        touched_words,
        canonical_frontier,
    );
    errdefer transition.deinit();
    if (transition.entry_root != expected_roots.entry or
        transition.exit_root != expected_roots.exit)
    {
        return error.IncrementalBoundaryRootMismatch;
    }
    const expected_rows = std.math.mul(usize, touched_words.len, 2) catch
        return error.InvalidIncrementalBoundaryPolicyShape;
    if (transition.boundary_rows.len != expected_rows)
        return error.InvalidIncrementalBoundaryPolicyShape;

    for (touched_words, row_policy, 0..) |word, policy, index| {
        if (policy.entry_clock > word.final_clock or
            (policy.entry_clock == word.final_clock and
                word.old_word != word.new_word))
        {
            return error.InvalidIncrementalBoundaryClock;
        }
        const entry = &transition.boundary_rows[index * 2];
        const exit = &transition.boundary_rows[index * 2 + 1];
        if (entry.addr != word.address or exit.addr != word.address or
            entry.root != expected_roots.entry or
            exit.root != expected_roots.exit or
            !std.meta.eql(entry.value, wordBytes(word.old_word)) or
            !std.meta.eql(exit.value, wordBytes(word.new_word)) or
            exit.clock != word.final_clock)
        {
            return error.InvalidIncrementalBoundaryTransition;
        }
        entry.clock = policy.entry_clock;
        entry.multiplicity = policy.entry_memory.field();
        exit.multiplicity = policy.exit_memory.field();
    }

    return .{ .transition = transition };
}

fn wordBytes(word: u32) [4]u8 {
    return .{
        @truncate(word),
        @truncate(word >> 8),
        @truncate(word >> 16),
        @truncate(word >> 24),
    };
}

test "incremental commitment V3 retains raw Merkle rows with split memory policy" {
    const allocator = std.testing.allocator;
    const words = [_]transition_v1.TouchedWord{.{
        .address = 0x1000,
        .old_word = 0x1122_3344,
        .new_word = 0x5566_7788,
        .final_clock = 9,
    }};
    const expected = ExpectedRootsV3{
        .entry = try rootForWords(allocator, &words, false),
        .exit = try rootForWords(allocator, &words, true),
    };
    var witness = try buildBoundary(
        allocator,
        &words,
        &.{},
        &.{.{
            .entry_clock = 3,
            .entry_memory = .none,
            .exit_memory = .exit,
        }},
        expected,
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 2), witness.rows().len);
    try std.testing.expectEqual(@as(u32, 3), witness.rows()[0].clock);
    try std.testing.expect(witness.rows()[0].multiplicity.isZero());
    try std.testing.expect(witness.rows()[1].multiplicity.eql(M31.one().neg()));
    try std.testing.expectEqual(expected, witness.roots());
    try witness.verifyMerkleAndPoseidonCancellation(
        &relations_mod.Relations.dummy(),
    );
    try std.testing.expect(!PRODUCTION_ACTIVE);
}

test "incremental commitment V3 rejects clock and root drift" {
    const allocator = std.testing.allocator;
    const words = [_]transition_v1.TouchedWord{.{
        .address = 0x2000,
        .old_word = 5,
        .new_word = 6,
        .final_clock = 7,
    }};
    const expected = ExpectedRootsV3{
        .entry = try rootForWords(allocator, &words, false),
        .exit = try rootForWords(allocator, &words, true),
    };
    try std.testing.expectError(
        error.InvalidIncrementalBoundaryClock,
        buildBoundary(
            allocator,
            &words,
            &.{},
            &.{.{
                .entry_clock = 8,
                .entry_memory = .entry,
                .exit_memory = .exit,
            }},
            expected,
        ),
    );
    var changed_roots = expected;
    changed_roots.exit +%= 1;
    try std.testing.expectError(
        error.IncrementalBoundaryRootMismatch,
        buildBoundary(
            allocator,
            &words,
            &.{},
            &.{.{
                .entry_clock = 1,
                .entry_memory = .entry,
                .exit_memory = .exit,
            }},
            changed_roots,
        ),
    );
}

test "incremental full witness rejects an empty multiproof before program access" {
    const allocator = std.testing.allocator;
    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    try std.testing.expectError(
        error.InvalidStatement,
        commitment_witness.CommitmentWitness.buildWithIncrementalBoundaryV3(
            allocator,
            &trace,
            null,
            undefined,
            &.{},
            &.{},
            &.{},
            .{ .entry = 1, .exit = 2 },
        ),
    );
}

fn rootForWords(
    allocator: std.mem.Allocator,
    words: []const transition_v1.TouchedWord,
    comptime final: bool,
) !u32 {
    const sparse_merkle = @import("../air/memory_commitment/sparse_merkle.zig");
    var leaves: std.ArrayList(sparse_merkle.Leaf) = .empty;
    defer leaves.deinit(allocator);
    try leaves.ensureTotalCapacity(allocator, words.len * 4);
    for (words) |word| {
        const value = if (final) word.new_word else word.old_word;
        const bytes = wordBytes(value);
        for (bytes, 0..) |byte, limb| {
            if (byte == 0) continue;
            leaves.appendAssumeCapacity(.{
                .index = word.address + @as(u32, @intCast(limb)),
                .value = byte,
            });
        }
    }
    var tree = try sparse_merkle.build(allocator, leaves.items);
    defer tree.deinit(allocator);
    return tree.root;
}
