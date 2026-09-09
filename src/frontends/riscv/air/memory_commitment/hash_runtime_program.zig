//! Runtime polynomial export for mixed hash AIR components.
//!
//! The direct and lookup DAGs are recorded from the same production-generic
//! Poseidon evaluator used by the verifier. Keeping this owner independent of
//! the Metal backend makes the capability reusable by any backend that can
//! execute the backend-neutral programs.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const entry = @import("../lookups/entry.zig");
const runtime_program = @import("../extract/runtime_program.zig");
const symbolic = @import("../extract/symbolic.zig");
const relations_mod = @import("../relation_challenges.zig");
const poseidon2_air = @import("poseidon2_air.zig");

pub const DirectMode = enum { narrow_memory, universal };
pub const DIRECT_PARTITION_COUNT: usize = 4;

pub fn directConstraintCount(mode: DirectMode) usize {
    return switch (mode) {
        .narrow_memory => poseidon2_air.N_CONSTRAINTS + 3,
        .universal => poseidon2_air.N_CONSTRAINTS,
    };
}

pub fn directPartitionRange(
    mode: DirectMode,
    partition: usize,
) prover_component.ComponentConstraintRangeV1 {
    std.debug.assert(partition < DIRECT_PARTITION_COUNT);
    const total = directConstraintCount(mode);
    const start = total * partition / DIRECT_PARTITION_COUNT;
    const end = total * (partition + 1) / DIRECT_PARTITION_COUNT;
    return .{ .start = start, .count = end - start };
}

pub fn buildPoseidonDirect(
    allocator: std.mem.Allocator,
    mode: DirectMode,
) !prover_component.OwnedBasePolynomialProgram {
    return buildPoseidonDirectRange(
        allocator,
        mode,
        .{ .start = 0, .count = directConstraintCount(mode) },
    );
}

pub fn buildPoseidonDirectRange(
    allocator: std.mem.Allocator,
    mode: DirectMode,
    range: prover_component.ComponentConstraintRangeV1,
) !prover_component.OwnedBasePolynomialProgram {
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var main: [poseidon2_air.N_MAIN_COLUMNS]symbolic.Scalar = undefined;
    for (&main) |*column| column.* = arena.column("main");
    const selector = arena.column("selector");
    const air = poseidon2_air.evaluateGeneric(symbolic.Scalar, main);
    return switch (mode) {
        .universal => blk: {
            const end = std.math.add(usize, range.start, range.count) catch
                return error.InvalidHashRuntimeProgram;
            if (range.count == 0 or end > air.len) return error.InvalidHashRuntimeProgram;
            break :blk runtime_program.ownDirectProgram(
                allocator,
                &arena,
                air[range.start..end],
                poseidon2_air.N_MAIN_COLUMNS,
            );
        },
        .narrow_memory => blk: {
            var direct: [poseidon2_air.N_CONSTRAINTS + 3]symbolic.Scalar = undefined;
            @memcpy(direct[0..poseidon2_air.N_CONSTRAINTS], &air);
            direct[poseidon2_air.N_CONSTRAINTS] = main[0].sub(selector);
            const narrow = poseidon2_air.narrowModeConstraintsGeneric(
                symbolic.Scalar,
                main,
            );
            @memcpy(direct[poseidon2_air.N_CONSTRAINTS + 1 ..], &narrow);
            const end = std.math.add(usize, range.start, range.count) catch
                return error.InvalidHashRuntimeProgram;
            if (range.count == 0 or end > direct.len) return error.InvalidHashRuntimeProgram;
            break :blk runtime_program.ownDirectProgram(
                allocator,
                &arena,
                direct[range.start..end],
                poseidon2_air.N_MAIN_COLUMNS,
            );
        },
    };
}

pub fn buildPoseidonLookups(
    allocator: std.mem.Allocator,
) !prover_component.OwnedLookupPolynomialProgram {
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var main: [poseidon2_air.N_MAIN_COLUMNS]symbolic.Scalar = undefined;
    for (&main) |*column| column.* = arena.column("main");
    var lookups = poseidon2_air.entriesGeneric(symbolic.Scalar, main);
    return runtime_program.ownLookupProgram(
        allocator,
        &arena,
        &lookups,
        poseidon2_air.N_MAIN_COLUMNS,
    );
}

pub fn poseidonParameters(
    allocator: std.mem.Allocator,
    relations: *const relations_mod.Relations,
    claims: *const [poseidon2_air.N_SUMS]QM31,
) ![]QM31 {
    const zero = QM31.zero();
    const main = [_]QM31{zero} ** poseidon2_air.N_MAIN_COLUMNS;
    const lookups = poseidon2_air.entries(main);
    var parameters = std.ArrayList(QM31).empty;
    errdefer parameters.deinit(allocator);
    for (lookups.entries[0..lookups.len]) |lookup| {
        try entry.appendRelationParameters(
            &parameters,
            allocator,
            relations,
            lookup.domain,
        );
    }
    try parameters.appendSlice(allocator, claims);
    return parameters.toOwnedSlice(allocator);
}

test "Poseidon mixed runtime programs bind complete direct and lookup geometry" {
    var narrow = try buildPoseidonDirect(std.testing.allocator, .narrow_memory);
    defer narrow.deinit();
    var universal = try buildPoseidonDirect(std.testing.allocator, .universal);
    defer universal.deinit();
    var lookups = try buildPoseidonLookups(std.testing.allocator);
    defer lookups.deinit();

    try std.testing.expectEqual(
        @as(usize, poseidon2_air.N_CONSTRAINTS + 3),
        narrow.roots.len,
    );
    try std.testing.expectEqual(
        @as(usize, poseidon2_air.N_CONSTRAINTS),
        universal.roots.len,
    );
    try std.testing.expectEqual(@as(usize, poseidon2_air.N_SUMS), lookups.batchCount());
    try std.testing.expectEqual(
        @as(usize, poseidon2_air.N_INTERACTION_COLUMNS),
        4 * lookups.batchCount(),
    );
    var covered: usize = 0;
    for (0..DIRECT_PARTITION_COUNT) |partition| {
        const range = directPartitionRange(.narrow_memory, partition);
        var split = try buildPoseidonDirectRange(std.testing.allocator, .narrow_memory, range);
        defer split.deinit();
        try std.testing.expectEqual(range.count, split.roots.len);
        try std.testing.expectEqual(covered, range.start);
        covered += range.count;
    }
    try std.testing.expectEqual(narrow.roots.len, covered);
}
