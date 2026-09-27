//! Export the actual word-v4/range16 typed equations, not a second AIR.
//! Programs own only bounded expression/parameter metadata. Their identity is
//! not a proof receipt; independently pinned Spec admission remains required.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v1;
const E = ir.Expr;
const word = @import("../air/block/word_memory_v5.zig");
const trace = @import("../air/block/word_memory_trace_v5.zig");
const interaction = @import("block_v5_word_memory_interaction_v1.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const elements = @import("../air/relation_challenges.zig");
const WordSpec = @import("block_v5_word_memory_component_v1.zig").Spec;
const RangeSpec = @import("block_v5_range16_component_v1.zig").Spec;
const range_algebra = @import("block_v5_range16_algebra_v1.zig");

/// Exact equation/mapping bytes plus protocol ABI invalidate stale executables.
pub fn authority() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/block-v5/word-device-algebra/v1\x00");
    h.update(&protocol.abiId());
    inline for (.{ @embedFile("../air/block/word_memory_v5.zig"), @embedFile("../air/block/word_memory_trace_v5.zig"), @embedFile("block_v5_word_memory_interaction_v1.zig"), @embedFile("block_v5_range16_algebra_v1.zig"), @embedFile("block_v5_word_gpu_program_v1.zig") }) |bytes| h.update(bytes);
    return h.finalResult();
}
fn Relation(comptime n: usize) type {
    return struct {
        z: E,
        powers: [n]E,
        fn init(source: elements.RelationElements(n)) @This() {
            var out: @This() = .{ .z = E.splat(source.z), .powers = undefined };
            for (&out.powers, source.alpha_powers) |*target, value| target.* = E.splat(value);
            return out;
        }
        pub fn combineSecure(self: @This(), values: [n]E) E {
            return elements.combineGeneric(E, self.z, self.powers, values);
        }
    };
}
pub const Challenges = struct {
    transition: Relation(protocol.TRANSITION_ARITY),
    link: Relation(protocol.LINK_ARITY),
    initial: Relation(protocol.INITIAL_ARITY),
    endpoint: Relation(protocol.ENDPOINT_ARITY),
    range16: Relation(1),
    pub fn init(c: *const protocol.Challenges) Challenges {
        return .{ .transition = .init(c.transition), .link = .init(c.link), .initial = .init(c.initial), .endpoint = .init(c.endpoint), .range16 = .init(c.range16) };
    }
};
fn inputs(comptime n: usize, b: *ir.Builder, tree: u8, previous: bool) [n]E {
    var out: [n]E = undefined;
    for (&out, 0..) |*target, column| target.* = b.input(.{ .tree = tree, .column = @intCast(column), .previous = previous });
    return out;
}
fn previousMain(b: *ir.Builder) [27]E {
    var out: [27]E = @splat(E.zero());
    for (&out, 0..) |*target, column| if (WordSpec.previousMainNeeded(column)) {
        target.* = b.input(.{ .tree = 1, .column = @intCast(column), .previous = true });
    };
    return out;
}
fn wordGeometry(spec: WordSpec, size: u32) !void {
    try word.validatePublicClaim(spec.claim);
    if (spec.claim.log_size < 1 or spec.claim.log_size > 24 or size != @as(u32, 1) << @intCast(spec.claim.log_size)) return error.InvalidWordDeviceGeometry;
    if (!spec.challenges.range16.alpha_powers[0].eql(Q.one())) return error.InvalidSecureRangeChallenge;
}
pub fn wordEquations(a: std.mem.Allocator, spec: WordSpec, size: u32) !ir.Program {
    try wordGeometry(spec, size);
    const domain = try spec.prepareDomain(size);
    var b = ir.Builder.init(a);
    defer b.deinit();
    const fixed = trace.fixedPointGeneric(E, inputs(12, &b, 0, false), spec.claim);
    const main = inputs(27, &b, 1, false);
    const prior = previousMain(&b);
    const current = inputs(68, &b, 2, false);
    const previous = inputs(68, &b, 2, true);
    const challenges = Challenges.init(spec.challenges);
    const endpoints = interaction.liftEndpoints(E, domain.endpoints);
    var normalized: [17]E = undefined;
    for (&normalized, domain.normalized) |*target, value| target.* = E.splat(value);
    const roots = word.Algebra(E).constraints(spec.claim, fixed, main, prior) ++ interaction.Algebra(E).constraintsPrepared(&challenges, &endpoints, fixed, main, prior, current, previous, normalized);
    return b.finish(.word_equations_v4, authority(), &roots);
}
pub fn wordFractions(a: std.mem.Allocator, spec: WordSpec, size: u32) !ir.Program {
    try wordGeometry(spec, size);
    var b = ir.Builder.init(a);
    defer b.deinit();
    const fixed = trace.fixedPointGeneric(E, inputs(12, &b, 0, false), spec.claim);
    const main = inputs(27, &b, 1, false);
    const prior = previousMain(&b);
    const challenges = Challenges.init(spec.challenges);
    const endpoints = interaction.liftEndpoints(E, try interaction.publicEndpoints(spec.claim, spec.challenges));
    const points = word.Algebra(E).rangePoints(fixed, main);
    const t = interaction.Algebra(E).terms(&challenges, &endpoints, fixed, main, prior, points, false);
    const range_z = b.parameter(spec.challenges.range16.z);
    var roots: [17]E = undefined;
    roots[0] = E.fraction(t.weights[0], t.denominators[0]);
    roots[1] = E.fraction(t.weights[1], t.denominators[1]).add(E.fraction(t.weights[2], t.denominators[2]));
    roots[2] = E.fraction(t.weights[3], t.denominators[3]);
    roots[3] = E.fraction(t.weights[4], t.denominators[4]).add(E.fraction(t.weights[5], t.denominators[5]));
    roots[4] = t.endpoint_count;
    roots[5] = t.range_count;
    roots[6] = E.fraction(t.weights[6], t.denominators[6]).add(E.fraction(t.weights[7], t.denominators[7]));
    roots[7] = t.register_endpoint_count;
    for (0..9) |batch| {
        const first = 8 + 2 * batch;
        roots[8 + batch] = E.rangeFraction(t.weights[first], points[2 * batch].value, range_z);
        if (2 * batch + 1 < word.RANGE_COUNT) roots[8 + batch] = roots[8 + batch].add(E.rangeFraction(t.weights[first + 1], points[2 * batch + 1].value, range_z));
    }
    return b.finish(.word_fractions_v4, authority(), &roots);
}
pub fn rangeEquations(a: std.mem.Allocator, spec: RangeSpec) !ir.Program {
    const domain = try spec.prepareDomain(65536);
    var b = ir.Builder.init(a);
    defer b.deinit();
    const relation = Relation(1).init(spec.challenges.range16);
    const roots = range_algebra.equations(E, inputs(1, &b, 0, false), inputs(1, &b, 1, false), inputs(8, &b, 2, false), inputs(8, &b, 2, true), E.splat(domain.sum), E.splat(domain.count), relation);
    return b.finish(.range16_equations_v4, authority(), &roots);
}
pub fn rangeFractions(a: std.mem.Allocator, spec: RangeSpec) !ir.Program {
    _ = try spec.prepareDomain(65536);
    if (!spec.challenges.range16.alpha_powers[0].eql(Q.one())) return error.InvalidSecureRangeChallenge;
    var b = ir.Builder.init(a);
    defer b.deinit();
    const fixed = inputs(1, &b, 0, false);
    const main = inputs(1, &b, 1, false);
    const roots = [_]E{ E.rangeFraction(main[0], fixed[0], b.parameter(spec.challenges.range16.z)), main[0] };
    return b.finish(.range16_fractions_v4, authority(), &roots);
}

/// Resolve independently supplied OOD/trace evaluations in exact exported
/// mask order. No trace values enter a kernel's executable identity.
pub fn wordValues(a: std.mem.Allocator, program: *const ir.Program, fixed: [12]Q, main: [27]Q, prior: [27]Q, current: [68]Q, previous: [68]Q) ![]Q {
    try program.validate();
    const result = try a.alloc(Q, program.inputs.len);
    for (program.inputs, result) |input, *out| out.* = switch (input.tree) {
        0 => fixed[input.column],
        1 => if (input.previous) prior[input.column] else main[input.column],
        2 => if (input.previous) previous[input.column] else current[input.column],
        else => unreachable,
    };
    return result;
}
