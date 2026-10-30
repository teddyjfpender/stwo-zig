//! Decode caller accounting from already authenticated recursive public values.
//! These helpers enforce independent original admission and exact public frames;
//! they do not themselves verify a parent proof or close any global relation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Auxiliary = @import("../recursion/block_v6_auxiliary_direct_public_v1.zig");
const Arithmetic = Auxiliary.Definition(.caller_arithmetic);
const Fused = Auxiliary.Definition(.caller_fused);
const Protocol = @import("block_v5_caller_fused_proof_v1.zig");
pub const ArithmeticExports = struct { binding: @import("block_v5_precompile_family_proof_v1.zig").CallerBinding, open_sum: Q };

pub fn arithmetic(admitted: *const Arithmetic.Admission.Prepared, values: Arithmetic.Bus.Values) !ArithmeticExports {
    try admitted.validate(admitted.template_id);
    try values.validate();
    const expected = Arithmetic.Bus.Values{ .template = admitted.template_id, .statement = admitted.statement, .total_steps = admitted.total_steps, .config = admitted.config, .binding = admitted.binding, .claims = values.claims, .open_sum = values.claims.componentSum() };
    try expected.validate();
    const got = [_]Auxiliary.Child{.{ .index = admitted.binding.execution_index, .value = .{ .caller_arithmetic = values } }};
    const want = [_]Auxiliary.Child{.{ .index = admitted.binding.execution_index, .value = .{ .caller_arithmetic = expected } }};
    try (Auxiliary.Values{ .children = &got }).requireSameFrame(.{ .children = &want });
    // Arithmetic Values.mix does not serialize the full statement. Pin it
    // explicitly to admission in addition to comparing routed values.
    if (!std.meta.eql(values.statement, admitted.statement)) return error.UntrustedCallerArithmeticStatement;
    return .{ .binding = admitted.binding, .open_sum = expected.open_sum };
}

pub fn fused(a: std.mem.Allocator, admitted: *const Fused.Admission.Prepared, values: Fused.Bus.Values) !Protocol.Verified {
    try admitted.validate(admitted.template_id);
    try values.validate();
    const schedule = &admitted.schedule;
    if (values.public.len != try @import("../recursion/air/block_v5_caller_fused_composition_v1.zig").publicCount(schedule.program.len, schedule.tables.len, schedule.memory.len)) return error.UntrustedCallerFusedPublicExports;
    const programs = try a.alloc(@import("block_v5_program_extension_proof_v1.zig").Claim, schedule.program.len);
    defer a.free(programs);
    const states = try a.alloc(@import("block_v5_program_extension_proof_v1.zig").Claim, schedule.program.len);
    defer a.free(states);
    const tables = try a.alloc(@import("block_v5_precompile_lookup_algebra_v1.zig").Claim, schedule.tables.len);
    defer a.free(tables);
    const MemoryClaim = std.meta.Elem(@FieldType(Protocol.ClaimFrames, "memory_claims"));
    const memory = try a.alloc(MemoryClaim, schedule.memory.len);
    defer a.free(memory);
    var at: usize = 8;
    inline for (.{ programs, states }) |partition| for (partition, schedule.program) |*claim, slot| {
        claim.* = .{ .sum = values.public[at], .fetch_count = slot.active_calls };
        at += 1;
    };
    for (tables, schedule.tables) |*claim, slot| {
        claim.* = .{ .sum = values.public[at], .row_count = slot.n_rows };
        at += 1;
    }
    for (memory, schedule.memory) |*claim, slot| {
        const count = values.public[at + 2];
        const limbs = count.toM31Array();
        if (!count.eql(Q.fromBase(limbs[0])) or limbs[0].toU32() > (@as(u32, 1) << @intCast(slot.log_size))) return error.UntrustedCallerFusedPublicCensus;
        claim.* = .{ .transition_sum = values.public[at], .universal_sum = values.public[at + 1], .active_count = limbs[0].toU32(), .range_claims = values.public[at + 3 ..][0..7].* };
        at += 10;
    }
    const claims = Protocol.ClaimFrames{ .program_claims = programs, .state_claims = states, .table_claims = tables, .memory_claims = memory };
    var expected = try Fused.Bus.Values.init(a, admitted, claims);
    defer expected.deinit();
    const got = [_]Auxiliary.Child{.{ .index = admitted.binding.execution_index, .value = .{ .caller_fused = values } }};
    const want = [_]Auxiliary.Child{.{ .index = admitted.binding.execution_index, .value = .{ .caller_fused = expected } }};
    try (Auxiliary.Values{ .children = &got }).requireSameFrame(.{ .children = &want });
    var result = try Protocol.deriveOpenReceipts(a, &claims, schedule, admitted.binding, admitted.witness_root, admitted.sealed);
    errdefer result.deinit(a);
    if (result.memory.event_count != admitted.expected_rw_events) return error.UntrustedCallerFusedPublicCensus;
    return result;
}

test "caller public exports rebuild canonical claim frames and reject changed routing" {
    const a = std.testing.allocator;
    const fixture = try @import("tests/block_v5_caller_capture_unit_test.zig").Fixture.init(a);
    const pair = try @import("block_v5_caller_recursive_admission_pair_v1.zig").Pair.create(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer pair.deinit();
    const admitted = &pair.fused;
    const programs = try a.alloc(@import("block_v5_program_extension_proof_v1.zig").Claim, admitted.schedule.program.len);
    defer a.free(programs);
    for (programs, admitted.schedule.program) |*claim, slot| claim.* = .{ .sum = Q.one(), .fetch_count = slot.active_calls };
    const tables = try a.alloc(@import("block_v5_precompile_lookup_algebra_v1.zig").Claim, admitted.schedule.tables.len);
    defer a.free(tables);
    for (tables, admitted.schedule.tables) |*claim, slot| claim.* = .{ .sum = Q.one(), .row_count = slot.n_rows };
    const MemoryClaim = std.meta.Elem(@FieldType(Protocol.ClaimFrames, "memory_claims"));
    const memory = try a.alloc(MemoryClaim, admitted.schedule.memory.len);
    defer a.free(memory);
    var remaining = admitted.expected_rw_events;
    for (memory, admitted.schedule.memory) |*claim, slot| {
        const count = @min(remaining, @as(u64, 1) << @intCast(slot.log_size));
        claim.* = .{ .transition_sum = Q.one(), .universal_sum = Q.one(), .active_count = count, .range_claims = @splat(Q.one()) };
        remaining -= count;
    }
    try std.testing.expectEqual(@as(u64, 0), remaining);
    var values = try Fused.Bus.Values.init(a, admitted, .{ .program_claims = programs, .state_claims = programs, .table_claims = tables, .memory_claims = memory });
    defer values.deinit();
    var exports = try fused(a, admitted, values);
    defer exports.deinit(a);
    try std.testing.expectEqual(admitted.expected_rw_events, exports.memory.event_count);
    values.statement.roots_offset[0] += 1;
    try std.testing.expectError(error.UntrustedAuxiliaryDirectPublic, fused(a, admitted, values));
    // Synthetic proposed claims test conversion only, never proof acceptance.
    const ar = &pair.arithmetic;
    const ar_claims = try Arithmetic.Admission.Profile.ExtensionClaim.zeroForStatement(&ar.statement);
    const ar_values = Arithmetic.Bus.Values{ .template = ar.template_id, .statement = ar.statement, .total_steps = ar.total_steps, .config = ar.config, .binding = ar.binding, .claims = ar_claims, .open_sum = ar_claims.componentSum() };
    const ar_exports = try arithmetic(ar, ar_values);
    try std.testing.expect(ar_exports.open_sum.isZero());
    var wrong_ar = ar_values;
    wrong_ar.template[0] ^= 1;
    try std.testing.expectError(error.UntrustedAuxiliaryDirectPublic, arithmetic(ar, wrong_ar));
}
