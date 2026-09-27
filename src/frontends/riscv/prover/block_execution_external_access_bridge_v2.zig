//! Exact external-caller access tuples from the committed Ethereum/SHA
//! extension columns. Each formula mirrors the corresponding native caller
//! interaction; the sidecar quotient must sample these same PCS columns.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const pair_mod = @import("block_execution_access_bridge_v2.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const keccak_state = @import("../air/guest_precompile/keccakf_witness.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");

pub const SHA_ACCESS_COUNT: usize = 26;
pub const KECCAK_ACCESS_COUNT: usize = keccak.word_count + 1;
pub const SIGNER_ACCESS_COUNT: usize = signer.memory_word_count + 1;

fn scalar(comptime S: type, value: u32) S {
    const base = M.fromCanonical(value);
    return if (S == M) base else S.fromBase(base);
}
fn bytes(comptime S: type, main: []const S, offset: usize) [4]S {
    return main[offset..][0..4].*;
}
fn pair(comptime S: type, active: S, space: u32, address: S, previous_clock: S, clock: S, before: [4]S, after: [4]S) pair_mod.Pair(S) {
    return .{ .active = active, .space = scalar(S, space), .source_address = address, .local_clock = clock, .consume_clock = previous_clock, .before = before, .after = after, .pair_residuals = .{S.zero()} ** 3, .access_ordinal = null };
}
fn externalClock(comptime S: type, cycle: S, ordinal: u32) S {
    return cycle.sub(scalar(S, 1)).mul(scalar(S, 4)).add(scalar(S, ordinal));
}

/// The SHA caller's selector is its native fixed column, not prover-owned
/// main data. Slots 0-1 are register pointers; slots 2-25 are memory words.
pub fn shaPair(comptime S: type, main: []const S, active: S, slot: usize) !pair_mod.Pair(S) {
    if (main.len != sha.PHYSICAL_MAIN_COLUMN_COUNT or slot >= SHA_ACCESS_COUNT)
        return error.InvalidShaAccessSlot;
    if (slot < 2) {
        const pointer = bytes(S, main, sha.Layout.pointers + 4 * slot);
        return pair(S, active, 0, main[sha.Layout.registers + slot], main[sha.Layout.register_previous + slot], main[sha.Layout.register_clock], pointer, pointer);
    }
    const word = slot - 2;
    const before = bytes(S, main, sha.Layout.before + 4 * word);
    const after = if (word < 8) bytes(S, main, sha.Layout.output + 4 * word) else before;
    // SHA's typed alignedWordAddress emits a byte address on the universal
    // VM bus. Mark that unit explicitly so the separate sorted-memory bridge
    // keeps the same byte address instead of multiplying it a second time.
    var access = pair(S, active, 1, main[sha.Layout.addresses + word].mul(scalar(S, 4)), main[sha.Layout.previous + word], main[sha.Layout.memory_clock], before, after);
    access.address_unit = .byte_address;
    return access;
}

fn stateBytes(comptime S: type, bits: []const S, word: usize) [4]S {
    var result: [4]S = undefined;
    for (&result, 0..) |*byte, byte_index| {
        byte.* = S.zero();
        for (0..8) |bit| byte.* = byte.*.add(bits[word * 32 + byte_index * 8 + bit].mul(scalar(S, @as(u32, 1) << @intCast(bit))));
    }
    return result;
}

/// Keccak state bit cells are separate native extension main columns. Both
/// input and output state openings must be sampled by the sidecar quotient.
pub fn keccakPair(comptime S: type, caller: []const S, input_state: []const S, output_state: []const S, slot: usize) !pair_mod.Pair(S) {
    if (caller.len != keccak.Layout.main_columns or input_state.len != keccak_state.state_cell_count or
        output_state.len != keccak_state.state_cell_count or slot >= KECCAK_ACCESS_COUNT)
        return error.InvalidKeccakAccessSlot;
    const before = if (slot == 0) @as([4]S, @splat(S.zero())) else stateBytes(S, input_state, slot - 1);
    const after = if (slot == 0) @as([4]S, @splat(S.zero())) else stateBytes(S, output_state, slot - 1);
    return keccakPairFromBytes(S, caller, before, after, slot);
}

/// Algebraic evaluations of exactly one selected state word. This must also
/// work away from the Boolean/base domain; never branch on the enabler here.
pub fn keccakPairFromWordBits(comptime S: type, caller: []const S, input_word: [32]S, output_word: [32]S, slot: usize) !pair_mod.Pair(S) {
    const before = if (slot == 0) @as([4]S, @splat(S.zero())) else stateBytes(S, &input_word, 0);
    const after = if (slot == 0) @as([4]S, @splat(S.zero())) else stateBytes(S, &output_word, 0);
    return keccakPairFromBytes(S, caller, before, after, slot);
}

/// Same algebraic tuple formula, with only the selected state's four bytes.
/// Host trace construction can recover one word without reading all 1,600
/// bits. PCS/OODS callers still reconstruct bytes from their complete openings.
pub fn keccakPairFromBytes(comptime S: type, caller: []const S, before: [4]S, after: [4]S, slot: usize) !pair_mod.Pair(S) {
    if (caller.len != keccak.Layout.main_columns or slot >= KECCAK_ACCESS_COUNT)
        return error.InvalidKeccakAccessSlot;
    const active = caller[keccak.Layout.enabler];
    const cycle = caller[keccak.Layout.execution_clock];
    if (slot == 0) {
        const pointer = bytes(S, caller, keccak.Layout.pointer_bytes);
        return pair(S, active, 0, caller[keccak.Layout.pointer_register], caller[keccak.Layout.pointer_previous_clock], externalClock(S, cycle, 1), pointer, pointer);
    }
    const word = slot - 1;
    const address = caller[keccak.Layout.pointer_double_word_index].mul(scalar(S, 8)).add(scalar(S, @intCast(4 * word)));
    var access = pair(S, active, 1, address, caller[keccak.Layout.previousClock(word)], externalClock(S, cycle, 2), before, after);
    access.address_unit = .byte_address;
    return access;
}

fn signerInputBytes(comptime S: type, main: []const S, word: usize) [4]S {
    if (word < 8) return bytes(S, main, signer.Layout.digest_big_endian + 4 * word);
    if (word < 16) return bytes(S, main, signer.Layout.r_big_endian + 4 * (word - 8));
    if (word < 24) return bytes(S, main, signer.Layout.s_big_endian + 4 * (word - 16));
    return bytes(S, main, signer.Layout.recovery_id_bytes);
}
fn signerOutputBytes(comptime S: type, main: []const S, word: usize) [4]S {
    if (word < 16) return bytes(S, main, signer.Layout.public_key_big_endian + 4 * word);
    return bytes(S, main, signer.Layout.status_bytes);
}
pub fn signerPair(comptime S: type, main: []const S, slot: usize) !pair_mod.Pair(S) {
    if (main.len != signer.Layout.main_columns or slot >= SIGNER_ACCESS_COUNT)
        return error.InvalidSignerAccessSlot;
    const active = main[signer.Layout.is_active];
    const cycle = main[signer.Layout.execution_clock];
    if (slot == 0) {
        const pointer = bytes(S, main, signer.Layout.pointer_bytes);
        return pair(S, active, 0, main[signer.Layout.pointer_register], main[signer.Layout.pointer_previous_clock], externalClock(S, cycle, 1), pointer, pointer);
    }
    const word = slot - 1;
    const address = main[signer.Layout.pointer_word_index].mul(scalar(S, 4)).add(scalar(S, @intCast(4 * word)));
    if (word < signer.input_word_count) {
        const value = signerInputBytes(S, main, word);
        var access = pair(S, active, 1, address, main[signer.Layout.inputPreviousClock(word)], externalClock(S, cycle, 2), value, value);
        access.address_unit = .byte_address;
        return access;
    }
    const output = word - signer.input_word_count;
    var access = pair(S, active, 1, address, main[signer.Layout.outputPreviousClock(output)], externalClock(S, cycle, 2), bytes(S, main, signer.Layout.output_previous_bytes + 4 * output), signerOutputBytes(S, main, output));
    access.address_unit = .byte_address;
    return access;
}

test {
    _ = @import("block_execution_external_memory_tuple_test.zig");
}

test "block-v2 external access bridge enumerates SHA, Keccak and signer caller slots" {
    const Q = core.fields.qm31.QM31;
    const sha_main: [sha.PHYSICAL_MAIN_COLUMN_COUNT]Q = @splat(Q.zero());
    const keccak_main: [keccak.Layout.main_columns]Q = @splat(Q.zero());
    const keccak_bits: [keccak_state.state_cell_count]Q = @splat(Q.zero());
    const signer_main: [signer.Layout.main_columns]Q = @splat(Q.zero());
    try std.testing.expectEqual(@as(usize, 26), SHA_ACCESS_COUNT);
    try std.testing.expectEqual(@as(usize, 51), KECCAK_ACCESS_COUNT);
    for (0..SHA_ACCESS_COUNT) |slot| {
        const value = try shaPair(Q, &sha_main, Q.zero(), slot);
        try std.testing.expect(value.active.isZero());
    }
    for (0..KECCAK_ACCESS_COUNT) |slot| {
        const value = try keccakPair(Q, &keccak_main, &keccak_bits, &keccak_bits, slot);
        try std.testing.expect(value.active.isZero());
    }
    for (0..SIGNER_ACCESS_COUNT) |slot| {
        const value = try signerPair(Q, &signer_main, slot);
        try std.testing.expect(value.active.isZero());
    }
}

test "block-v5 external access bridge preserves exact native consumed clocks" {
    const Q = core.fields.qm31.QM31;
    var sha_main: [sha.PHYSICAL_MAIN_COLUMN_COUNT]Q = @splat(Q.zero());
    sha_main[sha.Layout.register_previous] = Q.fromBase(M.fromCanonical(3));
    sha_main[sha.Layout.previous] = Q.fromBase(M.fromCanonical(7));
    try std.testing.expect((try shaPair(Q, &sha_main, Q.one(), 0)).consume_clock.?.eql(Q.fromBase(M.fromCanonical(3))));
    try std.testing.expect((try shaPair(Q, &sha_main, Q.one(), 2)).consume_clock.?.eql(Q.fromBase(M.fromCanonical(7))));
    var keccak_main: [keccak.Layout.main_columns]Q = @splat(Q.zero());
    const state: [keccak_state.state_cell_count]Q = @splat(Q.zero());
    keccak_main[keccak.Layout.pointer_previous_clock] = Q.fromBase(M.fromCanonical(11));
    keccak_main[keccak.Layout.previousClock(0)] = Q.fromBase(M.fromCanonical(13));
    try std.testing.expect((try keccakPair(Q, &keccak_main, &state, &state, 0)).consume_clock.?.eql(Q.fromBase(M.fromCanonical(11))));
    try std.testing.expect((try keccakPair(Q, &keccak_main, &state, &state, 1)).consume_clock.?.eql(Q.fromBase(M.fromCanonical(13))));
    var signer_main: [signer.Layout.main_columns]Q = @splat(Q.zero());
    signer_main[signer.Layout.pointer_previous_clock] = Q.fromBase(M.fromCanonical(17));
    signer_main[signer.Layout.inputPreviousClock(0)] = Q.fromBase(M.fromCanonical(19));
    signer_main[signer.Layout.outputPreviousClock(0)] = Q.fromBase(M.fromCanonical(23));
    try std.testing.expect((try signerPair(Q, &signer_main, 0)).consume_clock.?.eql(Q.fromBase(M.fromCanonical(17))));
    try std.testing.expect((try signerPair(Q, &signer_main, 1)).consume_clock.?.eql(Q.fromBase(M.fromCanonical(19))));
    try std.testing.expect((try signerPair(Q, &signer_main, 1 + signer.input_word_count)).consume_clock.?.eql(Q.fromBase(M.fromCanonical(23))));
}

test "block-v5 SHA universal memory tuples match authenticated caller IR" {
    const a = std.testing.allocator;
    const Q = core.fields.qm31.QM31;
    const types = @import("../air/lang/types.zig");
    const relation = @import("../air/lang/relation.zig");
    const integer = @import("block_execution_integer_bridge_v2.zig");
    const universal = @import("block_v5_opcode_memory_interaction_v1.zig");
    var definition = try sha.build(a);
    defer definition.deinit();
    _ = try @import("../recursion/air/universal_relation_binding.zig").Binding(sha).authenticate(&definition);
    var main: [sha.PHYSICAL_MAIN_COLUMN_COUNT]M = @splat(M.zero());
    main[sha.Layout.register_clock] = M.fromCanonical(0x34567);
    main[sha.Layout.memory_clock] = M.fromCanonical(0x45678);
    for (0..2) |pointer| {
        main[sha.Layout.registers + pointer] = M.fromCanonical(@intCast(17 + pointer));
        main[sha.Layout.register_previous + pointer] = M.fromCanonical(@intCast(0x12340 + pointer));
        for (0..4) |byte| main[sha.Layout.pointers + 4 * pointer + byte] = M.fromCanonical(@intCast(97 + 4 * pointer + byte));
    }
    for (0..24) |word| {
        main[sha.Layout.addresses + word] = M.fromCanonical(@intCast(0x123450 + word));
        main[sha.Layout.previous + word] = M.fromCanonical(@intCast(0x23450 + word));
        for (0..4) |byte| main[sha.Layout.before + 4 * word + byte] = M.fromCanonical(@intCast((11 + 4 * word + byte) % 256));
    }
    for (0..32) |byte| main[sha.Layout.output + byte] = M.fromCanonical(@intCast(201 + byte));
    const row = main ++ [1]M{M.one()};
    const evaluated = try @import("../recursion/air/test_support.zig").evaluateArena(a, &definition.arena, &row);
    defer a.free(evaluated);
    var main_q: [sha.PHYSICAL_MAIN_COLUMN_COUNT]Q = undefined;
    for (main, &main_q) |value, *out| out.* = Q.fromBase(value);
    var event_count: usize = 0;
    for (definition.events) |id| {
        const event = definition.arena.effect(id).?;
        const binding = event.binding.?;
        if (!std.meta.eql(binding.schema, relation.get(.memory_access).id)) continue;
        const slot = event_count / 2;
        const consume = event_count % 2 == 0;
        try std.testing.expectEqual(if (consume) relation.Role.consume else relation.Role.emit, binding.role);
        const pair_value = try shaPair(Q, &main_q, Q.one(), slot);
        const point = try universal.pointFromPair(pair_value);
        const actual = if (consume) point.consumed else point.emitted;
        const ids = definition.arena.effectValues(id).?;
        try std.testing.expectEqual(@as(usize, 7), ids.len);
        for (ids, actual) |value_id, received| try std.testing.expect(received.eql(Q.fromBase(evaluated[types.idIndex(value_id)])));
        try std.testing.expect(pair_value.active.eql(Q.fromBase(evaluated[types.idIndex(event.liveness.?)])));
        event_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 52), event_count);
    // Universal SHA addresses changed to bytes; the sorted-memory tuple must
    // still describe exactly the same physical address, with no second *4.
    for (0..SHA_ACCESS_COUNT) |slot| {
        const current = try shaPair(Q, &main_q, Q.one(), slot);
        var old_word_bridge = current;
        if (slot >= 2) {
            try std.testing.expectEqual(pair_mod.AddressUnit.byte_address, current.address_unit);
            old_word_bridge.source_address = main_q[sha.Layout.addresses + slot - 2];
            old_word_bridge.address_unit = .word_index;
        }
        const witness = try integer.Witness.fromPair(current, 0x12345678);
        const old_witness = try integer.Witness.fromPair(old_word_bridge, 0x12345678);
        try std.testing.expect(std.meta.eql(integer.transitionAtPoint(current, witness), integer.transitionAtPoint(old_word_bridge, old_witness)));
        try std.testing.expect(integer.constraints(current, witness, 0x12345678).allZero());
    }
}

test "block-v4 active signer source matches native byte addresses and clocks" {
    const Q = core.fields.qm31.QM31;
    const integer = @import("block_execution_integer_bridge_v2.zig");
    var main: [signer.Layout.main_columns]Q = @splat(Q.zero());
    main[signer.Layout.is_active] = Q.one();
    main[signer.Layout.execution_clock] = scalar(Q, 3);
    main[signer.Layout.pointer_register] = scalar(Q, 5);
    main[signer.Layout.pointer_word_index] = scalar(Q, 10);
    main[signer.Layout.pointer_bytes] = scalar(Q, 40);
    main[signer.Layout.digest_big_endian] = scalar(Q, 0x12);
    main[signer.Layout.output_previous_bytes] = scalar(Q, 0x34);
    main[signer.Layout.public_key_big_endian] = scalar(Q, 0x56);

    const pointer = try signerPair(Q, &main, 0);
    const input = try signerPair(Q, &main, 1);
    const output = try signerPair(Q, &main, 1 + signer.input_word_count);
    try std.testing.expectEqual(@as(u32, 5), pointer.source_address.toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 9), pointer.local_clock.toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 10), input.source_address.toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 10), input.local_clock.toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0x12), input.before[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0x12), input.after[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, @intCast(10 + signer.input_word_count)), output.source_address.toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0x34), output.before[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0x56), output.after[0].toM31Array()[0].toU32());
    const accesses = [_]pair_mod.Pair(Q){ pointer, input, output };
    for (accesses, 0..) |access, index| {
        const witness = try integer.Witness.fromPair(access, 0);
        try std.testing.expect(integer.constraints(access, witness, 0).allZero());
        const byte_address = witness.byte_address[0].toM31Array()[0].toU32();
        const expected: u32 = if (index == 0) 5 else if (index == 1) 40 else @intCast(4 * (10 + signer.input_word_count));
        try std.testing.expectEqual(expected, byte_address);
    }
}
