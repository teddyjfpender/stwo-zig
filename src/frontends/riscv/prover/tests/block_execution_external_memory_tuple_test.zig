//! Compare sidecar tuples to shipped caller AIR events, not a second formula.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const bridge = @import("../block_execution_external_access_bridge_v2.zig");
const pairs = @import("../block_execution_access_bridge_v2.zig");
const universal = @import("../block_v5_opcode_memory_interaction_v1.zig");
const integer = @import("../block_execution_integer_bridge_v2.zig");
const keccak = @import("../../air/guest_precompile/keccakf_caller.zig");
const signer = @import("../../air/guest_precompile/secp256k1_recovery_caller.zig");
const Relations = @import("../guest_precompile/ethereum_transcript.zig").Relations;
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
fn check(access: pairs.Pair(Q), consumed: anytype, emitted: anytype, elements: anytype, slot: usize) !void {
    const point = try universal.pointFromPair(access);
    try std.testing.expect(consumed.n1.eql(access.active.neg()));
    try std.testing.expect(emitted.n1.eql(access.active));
    try std.testing.expect(consumed.d1.eql(elements.combineSecure(point.consumed)));
    try std.testing.expect(emitted.d1.eql(elements.combineSecure(point.emitted)));
    var former = access;
    if (slot == 0) {
        try std.testing.expectEqual(pairs.AddressUnit.word_index, access.address_unit);
        try std.testing.expect(access.space.isZero());
    } else {
        try std.testing.expectEqual(pairs.AddressUnit.byte_address, access.address_unit);
        try std.testing.expect(access.space.eql(Q.one()));
        const address = access.source_address.toM31Array()[0].toU32();
        try std.testing.expect(address > 0x10000 and address % 4 == 0);
        former.source_address = q(address / 4);
        former.address_unit = .word_index;
    }
    const witness = try integer.Witness.fromPair(access, 0x12345678);
    const old_witness = try integer.Witness.fromPair(former, 0x12345678);
    try std.testing.expect(std.meta.eql(integer.transitionAtPoint(access, witness), integer.transitionAtPoint(former, old_witness)));
    try std.testing.expect(integer.constraints(access, witness, 0x12345678).allZero());
}
test "block-v5 Keccak universal memory tuples match authentic caller events" {
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try Relations.draw(std.testing.allocator, &channel);
    var main: [keccak.Layout.main_columns]Q = undefined;
    for (&main, 0..) |*value, i| value.* = q(@intCast(i % 251));
    main[keccak.Layout.enabler] = Q.one();
    main[keccak.Layout.execution_clock] = q(0x34567);
    main[keccak.Layout.pointer_register] = q(19);
    main[keccak.Layout.pointer_previous_clock] = q(0x12340);
    main[keccak.Layout.pointer_double_word_index] = q(0x123450);
    for (0..keccak.word_count) |word| main[keccak.Layout.previousClock(word)] = q(@intCast(0x23450 + word));
    const state_count = @import("../../air/guest_precompile/keccakf_witness.zig").state_cell_count;
    var input: [state_count]Q = undefined;
    var output: [state_count]Q = undefined;
    for (&input, &output, 0..) |*before, *after, i| {
        before.* = q(@intFromBool(i % 3 == 0));
        after.* = q(@intFromBool(i % 5 == 0));
    }
    const events = keccak.coreEvents(Q, &main, &input, &output, &relations.keccak);
    for (0..bridge.KECCAK_ACCESS_COUNT) |slot| {
        const first: usize = if (slot == 0) 3 else 6 + 3 * (slot - 1);
        try check(try bridge.keccakPair(Q, &main, &input, &output, slot), events[first], events[first + 1], &relations.base.memory_access, slot);
    }
}
test "block-v5 signer universal memory tuples match authentic caller events" {
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try Relations.draw(std.testing.allocator, &channel);
    var main: [signer.Layout.main_columns]Q = undefined;
    for (&main, 0..) |*value, i| value.* = q(@intCast(i % 251));
    main[signer.Layout.is_active] = Q.one();
    main[signer.Layout.execution_clock] = q(0x34567);
    main[signer.Layout.pointer_register] = q(23);
    main[signer.Layout.pointer_previous_clock] = q(0x12340);
    main[signer.Layout.pointer_word_index] = q(0x123450);
    for (0..signer.input_word_count) |word| main[signer.Layout.inputPreviousClock(word)] = q(@intCast(0x23450 + word));
    for (0..signer.output_word_count) |word| main[signer.Layout.outputPreviousClock(word)] = q(@intCast(0x234a0 + word));
    const events = signer.rowEvents(Q, &main, &relations.secp);
    for (0..bridge.SIGNER_ACCESS_COUNT) |slot| {
        const first: usize = if (slot == 0) 3 else 6 + 3 * (slot - 1);
        try check(try bridge.signerPair(Q, &main, slot), events[first], events[first + 1], &relations.base.memory_access, slot);
    }
}
