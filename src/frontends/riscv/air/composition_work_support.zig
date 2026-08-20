//! Shared cold-path support for exact RISC-V AIR composition profiles.
//!
//! Component owners replay their production generic evaluator over the
//! counting scalar below. The real-value backing preserves structural branch
//! behavior; only the completed one-row operation tally is scaled by the
//! authenticated evaluation-domain geometry.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const composition_work = @import("stwo_prover_engine").air.composition_work;

pub const Scalar = composition_work.CountingScalar;
pub const FieldOperations = composition_work.FieldOperations;
pub const ComponentKind = composition_work.ComponentKind;
pub const ComponentProfile = composition_work.ComponentProfile;
pub const OodsComponentProfile = @import("stwo_prover_engine").air.oods_work.ComponentProfile;

pub fn oodsProfile(
    source: *const ComponentProfile,
    trace_log_size: u32,
    max_log_degree_bound: u32,
    partial_evaluation_count: usize,
    uses_previous_row: bool,
) !OodsComponentProfile {
    return OodsComponentProfile.init(
        source,
        trace_log_size,
        max_log_degree_bound,
        partial_evaluation_count,
        uses_previous_row,
    );
}

pub fn Relation(comptime arity: usize) type {
    return struct {
        z: Scalar,
        alpha_powers: [arity]Scalar,

        pub fn init(seed: u32) @This() {
            const alpha = QM31.fromU32Unchecked(seed + 2, 1, 0, 0);
            var power = QM31.one();
            var powers: [arity]Scalar = undefined;
            for (&powers) |*slot| {
                slot.* = .fromValue(power);
                power = power.mul(alpha);
            }
            return .{
                .z = .fromValue(QM31.fromU32Unchecked(seed + 1, 0, 0, 0)),
                .alpha_powers = powers,
            };
        }

        pub fn combine(self: @This(), inputs: [arity]Scalar) Scalar {
            var result = Scalar.zero();
            for (inputs, self.alpha_powers) |value, power| {
                result = result.add(power.mul(value));
            }
            return result.sub(self.z);
        }
    };
}

/// Exact field names and arities of `relation_challenges.Relations`. This is a
/// type adapter only; draw order and challenge-generation work belong to the
/// distinct relation/interaction producer family.
pub const Relations = struct {
    registers_state: Relation(2),
    memory_access: Relation(7),
    program_access: Relation(5),
    merkle: Relation(4),
    poseidon2: Relation(16),
    poseidon2_io: Relation(32),
    bitwise: Relation(4),
    range_check_20: Relation(1),
    range_check_8_11: Relation(2),
    range_check_8_8_4: Relation(3),
    range_check_8_8: Relation(2),
    range_check_m31: Relation(2),

    pub fn init() Relations {
        return .{
            .registers_state = .init(1),
            .memory_access = .init(2),
            .program_access = .init(3),
            .merkle = .init(4),
            .poseidon2 = .init(5),
            .poseidon2_io = .init(6),
            .bitwise = .init(7),
            .range_check_20 = .init(8),
            .range_check_8_11 = .init(9),
            .range_check_8_8_4 = .init(10),
            .range_check_8_8 = .init(11),
            .range_check_m31 = .init(12),
        };
    }
};

/// Guest Poseidon appends one 32-ary relation to the unchanged base schedule.
/// Keeping the same nesting as the production challenge view lets the
/// authenticated guest event plan replay without a parallel transcription.
pub const GuestRelations = struct {
    base: Relations,
    guest_poseidon2_io: Relation(32),

    pub fn init() GuestRelations {
        return .{
            .base = .init(),
            .guest_poseidon2_io = .init(13),
        };
    }
};

pub fn values(comptime count: usize, seed: usize) [count]Scalar {
    var result: [count]Scalar = undefined;
    for (&result, 0..) |*value, index|
        value.* = composition_work.dummyScalar(seed + index);
    return result;
}

pub fn begin(operations: *FieldOperations) !void {
    return composition_work.beginMeasurement(operations);
}

pub fn end() void {
    composition_work.endMeasurement();
}

pub fn profile(
    kind: ComponentKind,
    label: []const u8,
    evaluation_log_size: u32,
    constraint_count: usize,
    expression: FieldOperations,
    extra_constraint: FieldOperations,
    geometry: []const u64,
) !ComponentProfile {
    const constraint = try composition_work.addOperations(
        try composition_work.rootFoldWork(constraint_count),
        extra_constraint,
    );
    const authority = composition_work.sourceAuthority(
        label,
        geometry,
        expression,
        constraint,
    );
    return ComponentProfile.init(
        kind,
        authority,
        evaluation_log_size,
        constraint_count,
        expression,
        constraint,
        .{},
    );
}

pub fn baseProgramProfile(
    allocator: std.mem.Allocator,
    kind: ComponentKind,
    label: []const u8,
    evaluation_log_size: u32,
    program: anytype,
) !ComponentProfile {
    const reachable = try reachableBase(allocator, program);
    defer allocator.free(reachable);
    const expression = try composition_work.nodeWork(program.nodes, reachable);
    const constraint = try composition_work.rootFoldWork(program.roots.len);
    const authority = composition_work.sourceAuthority(
        label,
        &.{
            evaluation_log_size,
            program.nodes.len,
            program.roots.len,
            program.column_count,
        },
        expression,
        constraint,
    );
    return ComponentProfile.init(
        kind,
        authority,
        evaluation_log_size,
        program.roots.len,
        expression,
        constraint,
        .{},
    );
}

pub fn lookupProgramProfile(
    allocator: std.mem.Allocator,
    label: []const u8,
    evaluation_log_size: u32,
    program: anytype,
) !ComponentProfile {
    const reachable = try reachableLookup(allocator, program);
    defer allocator.free(reachable);
    const expression = try composition_work.nodeWork(program.nodes, reachable);
    const constraint = try composition_work.lookupConstraintWork(program);
    const authority = composition_work.sourceAuthority(
        label,
        &.{
            evaluation_log_size,
            program.nodes.len,
            program.entries.len,
            program.batchCount(),
            program.column_count,
        },
        expression,
        constraint,
    );
    return ComponentProfile.init(
        .lookup_polynomial_v1,
        authority,
        evaluation_log_size,
        program.batchCount(),
        expression,
        constraint,
        .{},
    );
}

pub fn lookupProgramV2Profile(
    allocator: std.mem.Allocator,
    label: []const u8,
    evaluation_log_size: u32,
    program: anytype,
) !ComponentProfile {
    const reachable = try reachableLookup(allocator, program);
    defer allocator.free(reachable);
    const expression = try composition_work.nodeWork(program.nodes, reachable);
    const constraint = try composition_work.lookupConstraintWorkV2(program);
    const authority = composition_work.sourceAuthority(
        label,
        &.{
            evaluation_log_size,
            program.nodes.len,
            program.entries.len,
            program.batches.len,
            program.layout.column_count,
        },
        expression,
        constraint,
    );
    return ComponentProfile.init(
        .lookup_polynomial_v2,
        authority,
        evaluation_log_size,
        program.batches.len,
        expression,
        constraint,
        .{},
    );
}

fn reachableBase(allocator: std.mem.Allocator, program: anytype) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.roots) |root| reachable[root] = true;
    markAncestors(program.nodes, reachable);
    return reachable;
}

fn reachableLookup(allocator: std.mem.Allocator, program: anytype) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.entries) |entry| {
        reachable[entry.numerator] = true;
        for (entry.values[0..entry.arity]) |value| reachable[value] = true;
    }
    markAncestors(program.nodes, reachable);
    return reachable;
}

fn markAncestors(nodes: anytype, reachable: []bool) void {
    var cursor = nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
}

test "composition profile support counts relation combination from SSOT" {
    const relations = Relations.init();
    const row = values(2, 0);
    var operations: FieldOperations = undefined;
    try begin(&operations);
    defer end();
    _ = relations.registers_state.combine(row);
    try std.testing.expectEqual(@as(u64, 3), operations.additions);
    try std.testing.expectEqual(@as(u64, 2), operations.multiplications);
}
