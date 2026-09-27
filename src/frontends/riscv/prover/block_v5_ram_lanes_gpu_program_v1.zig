//! Canonical two-event RAM exports from the qualified generic Algebra. No
//! virtual event-log domain and no hand-transcribed equations enter this DAG.
const std = @import("std");
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v1;
const E = ir.Expr;
const Spec = @import("block_v5_ram_lanes_component_v1.zig").Spec;
const Air = @import("../air/block/word_memory_lanes_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Challenges = @import("block_v5_word_gpu_program_v1.zig").Challenges;
pub fn authority() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/block-v5/ram-lanes-device-algebra/v1\x00");
    inline for (.{ @embedFile("../air/block/word_memory_lanes_v1.zig"), @embedFile("../air/block/word_memory_lanes_trace_v1.zig"), @embedFile("block_v5_ram_lanes_protocol_v1.zig"), @embedFile("block_v5_ram_lanes_interaction_v1.zig"), @embedFile("block_v5_ram_lanes_gpu_program_v1.zig") }) |bytes| hash.update(bytes);
    // The delegated oracle and its public endpoint/challenge implementation
    // participate in authority as well, rather than only the lane wrapper.
    hash.update(&@import("block_v5_word_gpu_program_v1.zig").authority());
    return hash.finalResult();
}
fn inputs(comptime n: usize, b: *ir.Builder, tree: u8, previous: bool) [n]E {
    var result: [n]E = undefined;
    for (&result, 0..) |*out, column| out.* = b.input(.{ .tree = tree, .column = @intCast(column), .previous = previous });
    return result;
}
fn prior(b: *ir.Builder) [54]E {
    var result: [54]E = @splat(E.zero());
    for (Air.shiftedColumns) |column| result[column] = b.input(.{ .tree = 1, .column = @intCast(column), .previous = true });
    return result;
}
fn lanes(values: [54]E) Air.Algebra(E).Row {
    return .{ values[0..27].*, values[27..54].* };
}
fn validate(spec: Spec, size: u32) !void {
    try spec.claim.validate();
    if (size != spec.claim.rowCapacity() or !spec.challenges.range16.alpha_powers[0].eql(@import("stwo_core").fields.qm31.QM31.one())) return error.InvalidSecureRamLanesGeometry;
}
pub fn equations(a: std.mem.Allocator, spec: Spec, size: u32) !ir.Program {
    try validate(spec, size);
    const domain = try spec.prepareDomain(size);
    var builder = ir.Builder.init(a);
    defer builder.deinit();
    const fixed = Trace.fixedPoint(E, inputs(24, &builder, 0, false), spec.claim);
    const current = lanes(inputs(54, &builder, 1, false));
    const previous = lanes(prior(&builder));
    const challenges = Challenges.init(spec.challenges);
    const endpoints = Interaction.liftEndpoints(E, domain.endpoints);
    var normalized: [Interaction.PLANES]E = undefined;
    for (&normalized, domain.normalized) |*out, value| out.* = E.splat(value);
    const roots = Air.Algebra(E).constraints(spec.claim, fixed, current, previous) ++ Interaction.Algebra(E).constraintsPrepared(&challenges, &endpoints, fixed, current, previous, inputs(92, &builder, 2, false), inputs(92, &builder, 2, true), normalized);
    return builder.finish(.ram_lanes_equations_v1, authority(), &roots);
}
pub fn fractions(a: std.mem.Allocator, spec: Spec, size: u32) !ir.Program {
    try validate(spec, size);
    _ = try spec.prepareDomain(size);
    var builder = ir.Builder.init(a);
    defer builder.deinit();
    const fixed = Trace.fixedPoint(E, inputs(24, &builder, 0, false), spec.claim);
    const challenges = Challenges.init(spec.challenges);
    const endpoints = Interaction.liftEndpoints(E, try Interaction.publicEndpoints(spec.claim, spec.challenges));
    const terms = Interaction.Algebra(E).terms(&challenges, &endpoints, fixed, lanes(inputs(54, &builder, 1, false)), lanes(prior(&builder)));
    var roots: [Interaction.PLANES]E = undefined;
    roots[0] = E.fraction(terms.weights[0], terms.denominators[0]).add(E.fraction(terms.weights[1], terms.denominators[1]));
    roots[1] = E.fraction(terms.weights[2], terms.denominators[2]).add(E.fraction(terms.weights[3], terms.denominators[3])).add(terms.public_link);
    roots[2] = E.fraction(terms.weights[4], terms.denominators[4]).add(E.fraction(terms.weights[5], terms.denominators[5]));
    roots[3] = E.fraction(terms.weights[6], terms.denominators[6]).add(E.fraction(terms.weights[7], terms.denominators[7])).add(terms.public_endpoint);
    roots[4] = terms.endpoint_count;
    roots[5] = terms.range_count;
    const z = builder.parameter(spec.challenges.range16.z);
    // Preserve the shared 65,536-value sealed inverse table: no per-row
    // inversion for any of the 17 pairwise limb request planes.
    for (0..Interaction.RANGE_PLANES) |i| roots[6 + i] = E.rangeFraction(terms.points[0][i].weight.neg(), terms.points[0][i].value, z).add(E.rangeFraction(terms.points[1][i].weight.neg(), terms.points[1][i].value, z));
    return builder.finish(.ram_lanes_fractions_v1, authority(), &roots);
}
