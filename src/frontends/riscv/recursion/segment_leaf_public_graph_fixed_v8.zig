//! Candidate exact fixed-key authority for direct-wrapper rows 15 and 16.
//!
//! The native public graphs are compiled from a verifier-selected claim
//! capacity and claimed-sum count. Their input multiplicities are therefore
//! fixed only *within that exact graph profile*. This module never infers a
//! fixed key from a captured leaf or from the source writer's rows. A caller
//! must admit the profile before the leaf proof is read and include both
//! complete padded fixed-column IDs in the outer verifier key.
//!
//! This is a candidate writer, not proof activation. The 50-row roster must
//! still seal this profile and the graph-lowering rows 30--32 together.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const claim_layout = @import("vm_public_claim_layout.zig");
const graphs = @import("vm_public_semantics_circuit.zig");
const source_mod = @import("segment_public_outer_source.zig");
const claim_air = @import("air/vm_public_claim_semantics_input.zig");
const claim_witness = @import("air/vm_public_claim_semantics_input_witness.zig");
const logup_air = @import("air/vm_public_logup_input.zig");
const logup_witness = @import("air/vm_public_logup_input_witness.zig");
const framework = @import("air/framework_interaction.zig");
const schedule = @import("air/verifier_schedule.zig");
const source_stage = @import("segment_public_outer_source_stage.zig");
const leaf_authority = @import("segment_leaf_authority.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROWS = [_]u8{ 15, 16 };
const DOMAIN = "stwo-zig/riscv-direct-public-graph-fixed/v1\x00";

/// These fields must be selected by the verifier before receiving the child
/// proof. In particular, `max_input_words` and `max_output_words` are the
/// capacity, not request-specific active lengths. The policy is pinned to the
/// current native row-15 source graph, which uses the legacy-zero I/O graph.
pub const AdmittedShape = struct {
    claim: claim_layout.Shape,
    claimed_sum_count: u32,
};

pub const FixedKey = struct {
    shape: AdmittedShape,
    row15_log_size: u32,
    row16_log_size: u32,
    row15_id: [32]u8,
    row16_id: [32]u8,
    claim_graph_id: [32]u8,
    logup_graph_id: [32]u8,
    seal: [32]u8,

    /// The claimed-sum count comes from the verifier-owned native schedule.
    /// The claim capacity must independently be selected in the wrapper key.
    pub fn buildFromVerifierPlan(
        allocator: std.mem.Allocator,
        claim_shape: claim_layout.Shape,
        plan: *const schedule.Plan,
    ) !FixedKey {
        try plan.validate();
        return build(allocator, .{
            .claim = claim_shape,
            .claimed_sum_count = try source_stage.planClaimedSumCount(plan),
        });
    }

    pub fn validateAgainstVerifierPlan(
        self: *const FixedKey,
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
    ) !void {
        try self.validate(allocator);
        try plan.validate();
        if (self.shape.claimed_sum_count != try source_stage.planClaimedSumCount(plan))
            return error.PublicGraphVerifierPlanMismatchV8;
    }

    pub fn build(allocator: std.mem.Allocator, admitted: AdmittedShape) !FixedKey {
        var claim = try graphs.ClaimReference.init(
            allocator,
            admitted.claim,
            source_mod.CLAIM_CIRCUIT_ID,
        );
        defer claim.deinit();
        var logup = try graphs.LogupReference.init(
            allocator,
            admitted.claim,
            source_mod.PUBLIC_LOGUP_CIRCUIT_ID,
            admitted.claimed_sum_count,
        );
        defer logup.deinit();
        const row16_reference = try logup_witness.Reference.seal(
            logup.circuit_id,
            logup.claim_kinds,
            logup.claimed_sum_count,
            logup.row_bindings,
        );
        var row16 = try logup_witness.Preprocessed.init(allocator, row16_reference);
        defer row16.deinit();
        const row15_id = try fixedId(
            15,
            claim.row_preprocessing.log_size,
            claim_air.PREPROCESSED_COLUMN_COUNT,
            claim_air.SEMANTIC_DIGEST,
            claim.row_preprocessing.rows,
        );
        const row16_id = try fixedId(
            16,
            row16.log_size,
            logup_air.PREPROCESSED_COLUMN_COUNT,
            logup_air.SEMANTIC_DIGEST,
            row16.rows,
        );
        var result = FixedKey{
            .shape = admitted,
            .row15_log_size = claim.row_preprocessing.log_size,
            .row16_log_size = row16.log_size,
            .row15_id = row15_id,
            .row16_id = row16_id,
            .claim_graph_id = claim.authority_digest,
            .logup_graph_id = logup.authority_digest,
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        return result;
    }

    /// Recompile from admitted dimensions. A self-consistent but mutated key
    /// cannot pass; a digest copied from one particular leaf is insufficient.
    pub fn validate(self: *const FixedKey, allocator: std.mem.Allocator) !void {
        const fresh = try build(allocator, self.shape);
        if (!std.meta.eql(self.*, fresh)) return error.PublicGraphFixedKeyMismatchV8;
    }

    /// Check exact source parity without using that source to construct the
    /// expected key. This is an admission check, not a substitute for AIR.
    pub fn validateAgainstSource(
        self: *const FixedKey,
        allocator: std.mem.Allocator,
        source: *const source_mod.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try self.validateAgainstVerifierPlan(allocator, vm_plan);
        try source.validateAgainst(vm_plan, recursion_plan, preprocessing);
        if (!std.meta.eql(source.shape, self.shape.claim) or
            source.claimed_sum_count != self.shape.claimed_sum_count or
            source.claim_reference.row_preprocessing.log_size != self.row15_log_size or
            source.public_logup_preprocessing.log_size != self.row16_log_size or
            !std.mem.eql(u8, &source.claim_reference.authority_digest, &self.claim_graph_id) or
            !std.mem.eql(u8, &source.logup_reference.authority_digest, &self.logup_graph_id))
            return error.PublicGraphSourceMismatchV8;
        const source15 = try fixedId(
            15,
            self.row15_log_size,
            claim_air.PREPROCESSED_COLUMN_COUNT,
            claim_air.SEMANTIC_DIGEST,
            source.claim_reference.row_preprocessing.rows,
        );
        const source16 = try fixedId(
            16,
            self.row16_log_size,
            logup_air.PREPROCESSED_COLUMN_COUNT,
            logup_air.SEMANTIC_DIGEST,
            source.public_logup_preprocessing.rows,
        );
        if (!std.mem.eql(u8, &source15, &self.row15_id) or
            !std.mem.eql(u8, &source16, &self.row16_id))
            return error.PublicGraphSourceMismatchV8;
    }

    /// Write a fresh row's complete fixed columns. Canonical graph compilation
    /// is repeated here so mutable key fields cannot influence written data.
    pub fn writeRow(
        self: *const FixedKey,
        allocator: std.mem.Allocator,
        row: u8,
        columns: [][]M31,
    ) !void {
        if (row != 15 and row != 16) return error.UnqualifiedPublicGraphFixedRowV8;
        try self.validate(allocator);
        var claim = try graphs.ClaimReference.init(
            allocator,
            self.shape.claim,
            source_mod.CLAIM_CIRCUIT_ID,
        );
        defer claim.deinit();
        if (row == 15) return writeFixed(
            columns,
            self.row15_log_size,
            claim_air.PREPROCESSED_COLUMN_COUNT,
            claim.row_preprocessing.rows,
        );
        var logup = try graphs.LogupReference.init(
            allocator,
            self.shape.claim,
            source_mod.PUBLIC_LOGUP_CIRCUIT_ID,
            self.shape.claimed_sum_count,
        );
        defer logup.deinit();
        const reference = try logup_witness.Reference.seal(
            logup.circuit_id,
            logup.claim_kinds,
            logup.claimed_sum_count,
            logup.row_bindings,
        );
        var preprocessing = try logup_witness.Preprocessed.init(allocator, reference);
        defer preprocessing.deinit();
        return writeFixed(
            columns,
            self.row16_log_size,
            logup_air.PREPROCESSED_COLUMN_COUNT,
            preprocessing.rows,
        );
    }

    fn computeSeal(self: *const FixedKey) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hashInt(&hash, u32, self.shape.claim.max_input_words);
        hashInt(&hash, u32, self.shape.claim.max_output_words);
        hashInt(&hash, u32, self.shape.claimed_sum_count);
        hashInt(&hash, u32, self.row15_log_size);
        hashInt(&hash, u32, self.row16_log_size);
        hash.update(&self.row15_id);
        hash.update(&self.row16_id);
        hash.update(&self.claim_graph_id);
        hash.update(&self.logup_graph_id);
        return hash.finalResult();
    }
};

fn writeFixed(columns: [][]M31, log_size: u32, width: usize, rows: anytype) !void {
    if (log_size >= @bitSizeOf(usize)) return error.PublicGraphFixedGeometryMismatchV8;
    const capacity = @as(usize, 1) << @intCast(log_size);
    if (columns.len != width or rows.len > capacity)
        return error.PublicGraphFixedGeometryMismatchV8;
    for (columns) |column| {
        if (column.len != capacity) return error.PublicGraphFixedGeometryMismatchV8;
        for (column) |value| if (!value.isZero())
            return error.PublicGraphFixedDestinationNotFreshV8;
    }
    for (rows, 0..) |row, logical| {
        const values = row.values();
        const committed = framework.committedRow(logical, log_size);
        for (columns, values) |column, value| column[committed] = value;
    }
}

fn fixedId(
    comptime roster_row: u8,
    log_size: u32,
    comptime width: usize,
    semantic_digest: [32]u8,
    rows: anytype,
) ![32]u8 {
    if (log_size >= @bitSizeOf(usize)) return error.PublicGraphFixedGeometryMismatchV8;
    const capacity = @as(usize, 1) << @intCast(log_size);
    if (rows.len > capacity) return error.PublicGraphFixedGeometryMismatchV8;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u8, roster_row);
    hashInt(&hash, u32, log_size);
    hashInt(&hash, u32, width);
    hash.update(&semantic_digest);
    // Column-major, logical row order. The physical writer applies the same
    // deterministic committed-row permutation to every source and verifier.
    for (0..width) |column| for (0..capacity) |logical| {
        const value = if (logical < rows.len) rows[logical].values()[column] else M31.zero();
        hashInt(&hash, u32, value.toU32());
    };
    return hash.finalResult();
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    const bytes = std.mem.toBytes(std.mem.nativeToLittle(T, value));
    hash.update(&bytes);
}

test "V8 public graph key is exact-capacity and writes complete fixed rows" {
    const allocator = std.testing.allocator;
    const shape = AdmittedShape{
        .claim = try claim_layout.Shape.init(0, 0),
        .claimed_sum_count = 4,
    };
    const key = try FixedKey.build(allocator, shape);
    try key.validate(allocator);
    const independent = try FixedKey.build(allocator, shape);
    try std.testing.expectEqualDeep(key, independent);
    for (ROWS) |row| {
        const log_size = if (row == 15) key.row15_log_size else key.row16_log_size;
        const width: usize = if (row == 15) claim_air.PREPROCESSED_COLUMN_COUNT else logup_air.PREPROCESSED_COLUMN_COUNT;
        const capacity = @as(usize, 1) << @intCast(log_size);
        const columns = try allocator.alloc([]M31, width);
        defer allocator.free(columns);
        for (columns) |*column| {
            column.* = try allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        defer for (columns) |column| allocator.free(column);
        try key.writeRow(allocator, row, columns);
        try std.testing.expect(columns[0][framework.committedRow(0, log_size)].eql(M31.one()));
        if (row == 15) {
            var reference = try graphs.ClaimReference.init(
                allocator,
                shape.claim,
                source_mod.CLAIM_CIRCUIT_ID,
            );
            defer reference.deinit();
            const metadata = try claim_witness.Reference.seal(
                reference.circuit_id,
                reference.row_bindings,
            );
            try expectPreprocessedParity(
                claim_witness,
                allocator,
                &reference.row_preprocessing,
                metadata,
                columns,
                log_size,
            );
        } else {
            var reference = try graphs.LogupReference.init(
                allocator,
                shape.claim,
                source_mod.PUBLIC_LOGUP_CIRCUIT_ID,
                shape.claimed_sum_count,
            );
            defer reference.deinit();
            const metadata = try logup_witness.Reference.seal(
                reference.circuit_id,
                reference.claim_kinds,
                reference.claimed_sum_count,
                reference.row_bindings,
            );
            var preprocessing = try logup_witness.Preprocessed.init(allocator, metadata);
            defer preprocessing.deinit();
            try expectPreprocessedParity(
                logup_witness,
                allocator,
                &preprocessing,
                metadata,
                columns,
                log_size,
            );
        }
        try std.testing.expectError(
            error.PublicGraphFixedDestinationNotFreshV8,
            key.writeRow(allocator, row, columns),
        );
    }
    var corrupted = key;
    corrupted.row15_id[0] ^= 1;
    try std.testing.expectError(error.PublicGraphFixedKeyMismatchV8, corrupted.validate(allocator));
    try std.testing.expectError(
        error.PublicGraphFixedKeyMismatchV8,
        corrupted.validateAgainstSource(allocator, undefined, undefined, undefined, undefined),
    );
    const more_sums = try FixedKey.build(allocator, .{
        .claim = shape.claim,
        .claimed_sum_count = shape.claimed_sum_count + 1,
    });
    try std.testing.expect(!std.mem.eql(u8, &key.row16_id, &more_sums.row16_id));
    const more_capacity = try FixedKey.build(allocator, .{
        .claim = try claim_layout.Shape.init(1, 0),
        .claimed_sum_count = shape.claimed_sum_count,
    });
    try std.testing.expect(!std.mem.eql(u8, &key.row15_id, &more_capacity.row15_id));
}

fn expectPreprocessedParity(
    comptime Witness: type,
    allocator: std.mem.Allocator,
    preprocessing: *const Witness.Preprocessed,
    reference: Witness.Reference,
    physical: [][]M31,
    log_size: u32,
) !void {
    const capacity = @as(usize, 1) << @intCast(log_size);
    var logical: [Witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&logical) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
    }
    defer for (logical) |column| allocator.free(column);
    try preprocessing.generateInto(&logical, reference);
    for (logical, physical) |expected, actual| for (expected, 0..) |value, row| {
        try std.testing.expectEqual(value.toU32(), actual[framework.committedRow(row, log_size)].toU32());
    };
}
