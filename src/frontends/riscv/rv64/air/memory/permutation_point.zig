//! Lane-generic point evaluation for the RAM Poseidon2 universal provider.
//! It replays `air/memory_commitment/poseidon2_degree3_verifier.zig` (whose
//! point path speaks QM31 only) residual for residual, so an external lane can
//! instantiate the same equations with its own wires and relation draws.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const lane = @import("../lane.zig");
const geometry = @import("../geometry.zig");
const universal = @import("../../../air/memory_commitment/poseidon2_universal_degree3_v1.zig");
pub const Relations = @import("../../../air/relation_challenges.zig").Relations;
pub const Q = E.Q;
pub const N_MAIN = universal.N_MAIN_COLUMNS;
pub const N_SUMS = universal.N_SUMS;
pub const N_INTERACTION = universal.N_INTERACTION_COLUMNS;
pub const N_CONSTRAINTS = universal.N_CONSTRAINTS + universal.N_SUMS;
/// Draws consumed by `Relations.draw`: twelve `(z, alpha)` pairs in schema order.
pub const RELATION_DRAWS = 24;
/// Schema index of the Poseidon2 full-I/O relation inside the twelve pairs.
pub const POSEIDON2_IO_INDEX = 5;

/// One pinned Stark-V relation over lane C: `z`, `alpha` and the alpha powers
/// derived from them with lane multiplications (`RelationElements.init`).
pub fn RelationElementsFor(comptime C: type, comptime arity: usize) type {
    return struct {
        z: C,
        alpha: C,
        alpha_powers: [arity]C,
        pub fn init(z: C, alpha: C) @This() {
            var power = C.one();
            var powers: [arity]C = undefined;
            for (&powers) |*slot| {
                slot.* = power;
                power = power.mul(alpha);
            }
            return .{ .z = z, .alpha = alpha, .alpha_powers = powers };
        }
        /// `v_0 + alpha*v_1 + ... - z`, the `RelationElements.combine` polynomial.
        pub fn combine(self: @This(), values: [arity]C) C {
            var result = C.zero();
            for (values, self.alpha_powers) |value, power| result = result.add(power.mul(value));
            return result.sub(self.z);
        }
    };
}

/// The twelve relations over lane C in pinned schema order. RAM components
/// read only `poseidon2` and `poseidon2_io`; the rest keep the draw layout so
/// the shared lookup-entry switch resolves every arm.
pub fn RelationsFor(comptime C: type) type {
    return struct {
        registers_state: RelationElementsFor(C, 2),
        memory_access: RelationElementsFor(C, 7),
        program_access: RelationElementsFor(C, 5),
        merkle: RelationElementsFor(C, 4),
        poseidon2: RelationElementsFor(C, 16),
        poseidon2_io: RelationElementsFor(C, 32),
        bitwise: RelationElementsFor(C, 4),
        range_check_20: RelationElementsFor(C, 1),
        range_check_8_11: RelationElementsFor(C, 2),
        range_check_8_8_4: RelationElementsFor(C, 3),
        range_check_8_8: RelationElementsFor(C, 2),
        range_check_m31: RelationElementsFor(C, 2),
        /// Rebuilds every relation from the 24 draws `(z_i, alpha_i)`.
        pub fn fromDraws(draws: *const [RELATION_DRAWS]C) @This() {
            return .{
                .registers_state = .init(draws[0], draws[1]),
                .memory_access = .init(draws[2], draws[3]),
                .program_access = .init(draws[4], draws[5]),
                .merkle = .init(draws[6], draws[7]),
                .poseidon2 = .init(draws[8], draws[9]),
                .poseidon2_io = .init(draws[10], draws[11]),
                .bitwise = .init(draws[12], draws[13]),
                .range_check_20 = .init(draws[14], draws[15]),
                .range_check_8_11 = .init(draws[16], draws[17]),
                .range_check_8_8_4 = .init(draws[18], draws[19]),
                .range_check_8_8 = .init(draws[20], draws[21]),
                .range_check_m31 = .init(draws[22], draws[23]),
            };
        }
    };
}
/// Native components borrow the verifier's pinned relations; external lanes own theirs.
pub fn RelationsStorageFor(comptime Lane: type) type {
    E.assertConstLane(Lane);
    return if (Lane == Q) *const Relations else RelationsFor(Lane);
}

/// Point-evaluation view of the universal provider component. Mask map:
/// fixed[is_first_col_idx] sample 0 (the universal layout binds no active
/// selector); main[main_col_offset + c] sample 0 for c < N_MAIN; interaction
/// [interaction_col_offset + 4k + j] samples 0/1 for k < N_SUMS.
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: RelationsStorageFor(Lane),
        claims: [N_SUMS]Lane,
        const Self = @This();
        pub fn nConstraints(_: *const Self) usize {
            return N_CONSTRAINTS;
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != Lane) @compileError("Poseidon provider lane mismatch");
            if (self.log_size == 0 or self.log_size >= core.circle.M31_CIRCLE_LOG_ORDER - 1 or global_log < self.log_size) return error.InvalidRv64MaskShape;
            const first = try lane.sample(F, masks, 0, self.is_first_col_idx, 0, 1);
            var main: [N_MAIN]F = undefined;
            for (&main, 0..) |*value, c| value.* = try lane.sample(F, masks, 1, self.main_col_offset + c, 0, 1);
            var sums: [N_SUMS]F = undefined;
            var previous: [N_SUMS]F = undefined;
            for (&sums, &previous, 0..) |*sum, *prior, k| {
                sum.* = try lane.secureSample(F, masks, 2, self.interaction_col_offset + 4 * k, 0, 2);
                prior.* = try lane.secureSample(F, masks, 2, self.interaction_col_offset + 4 * k, 1, 2);
            }
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            for (universal.evaluateGeneric(F, main)) |constraint| sink.emit(constraint);
            const relations = if (Lane == Q) self.relations else &self.relations;
            for (universal.interactionConstraintsGeneric(F, main, first, sums, previous, self.claims, relations)) |constraint| sink.emit(constraint);
        }
    };
}
pub const Component = ComponentFor(Q);

test "lane relation elements match the pinned Stark-V combination" {
    const Elements = @import("../../../air/relation_challenges.zig").RelationElements(32);
    const z = Q.fromU32Unchecked(3, 1, 4, 1);
    const alpha = Q.fromU32Unchecked(5, 9, 2, 6);
    const pinned = Elements.init(z, alpha);
    const mirrored = RelationElementsFor(Q, 32).init(z, alpha);
    var values: [32]Q = undefined;
    for (&values, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(i + 7), @intCast(2 * i + 1), 11, @intCast(i));
    try @import("std").testing.expect(pinned.combine(values).eql(mirrored.combine(values)));
}
