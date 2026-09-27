//! Exact public wire coordinates for statement-authority Poseidon calls.
const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const poseidon2 = @import("../air/memory_commitment/poseidon2.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_call.zig");
const air = @import("air/vm_public_claim_hash_authority_v2.zig");
pub const CALL_WIRE_CIRCUIT_ID = air.CALL_WIRE_CIRCUIT_ID;
pub const CALL_WIRE_GROUP_COUNT = air.CALL_WIRE_GROUP_COUNT;

/// Shared exact public tuple projection; expected callers regenerate calls
/// from expected public data and fixed admitted descriptors first.
pub fn callWireTuples(call_index: usize, call: poseidon2_air.Call) [CALL_WIRE_GROUP_COUNT][6]M31 {
    const words = tupleForCall(call);
    var tuples: [CALL_WIRE_GROUP_COUNT][6]M31 = undefined;
    for (&tuples, 0..) |*tuple, group| tuple.* = callWireTupleFromWords(call_index, group, &words);
    return tuples;
}

pub fn callWireTuple(call_index: usize, group: usize, call: poseidon2_air.Call) [6]M31 {
    return callWireTupleFromWords(call_index, group, &tupleForCall(call));
}

pub fn callWireTupleFromWords(call_index: usize, group: usize, words: *const [air.POSEIDON_TUPLE_WIDTH]M31) [6]M31 {
    return callWireTupleGeneric(M31, identityBase, call_index, group, words);
}
fn identityBase(value: M31) M31 {
    return value;
}
/// Canonical circuit/node/word projection, shared by native public boundary
/// calculation and the parent's provider-authenticated symbolic call words.
pub fn callWireTupleGeneric(comptime S: type, from_base: anytype, call_index: usize, group: usize, words: *const [air.POSEIDON_TUPLE_WIDTH]S) [6]S {
    std.debug.assert(group < CALL_WIRE_GROUP_COUNT);
    std.debug.assert(call_index <= (m31.Modulus - 1 - group) / CALL_WIRE_GROUP_COUNT);
    return .{ from_base(felt(CALL_WIRE_CIRCUIT_ID)), from_base(felt(@as(u32, @intCast(call_index * CALL_WIRE_GROUP_COUNT + group)))) } ++ words[group * 4 ..][0..4].*;
}

pub fn tupleForCall(call: poseidon2_air.Call) [air.POSEIDON_TUPLE_WIDTH]M31 {
    var input: [poseidon2_air.WIDTH]M31 = undefined;
    for (&input, call.input) |*destination, word|
        destination.* = M31.fromCanonical(word);
    var output = input;
    poseidon2.permute(&output);
    return input ++ output;
}

fn felt(value: anytype) M31 {
    const canonical: u32 = @intCast(value);
    std.debug.assert(canonical < m31.Modulus);
    return M31.fromCanonical(canonical);
}
