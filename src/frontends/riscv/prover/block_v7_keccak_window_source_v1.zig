//! Pure source algebra for a shared Keccak inventory. `owner` is an opening
//! of the independently reconstructed fixed owner column, not a witness tag.
//! The full original Keccak AIR remains mandatory on these same columns.
//! These helpers alone provide neither a proof nor an execution receipt.
const core = @import("stwo_core");
const std = @import("std");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Caller = @import("../air/guest_precompile/keccakf_caller.zig");
const Local = @import("../air/guest_precompile/keccakf_caller_local_zero_v1.zig");
const Envelope = @import("../air/guest_precompile/x0_caller_envelope_v1.zig");
const State = @import("../air/guest_precompile/keccakf_witness.zig");
const Relations = @import("../air/guest_precompile/keccakf_relations.zig");
const Memory = @import("block_v7_memory_relations_v1.zig");
const External = @import("block_execution_external_access_bridge_v2.zig");
const Pair = @import("block_execution_access_bridge_v2.zig").Pair;

pub fn For(comptime local_zero: bool) type {
    return struct {
        pub const caller_width = if (local_zero) Local.Layout.main_columns else Caller.Layout.main_columns;
        pub const control_planes = 3;
        /// Exact original program/state/register events. Range-gap and RAM
        /// events remain enforced by the full original AIR and global bridge;
        /// they are not approximated by public host accounting here.
        pub fn control(owner: Q, caller: []const Q, relations: *const Relations.Relations) ![control_planes]Memory.Term(Q) {
            if (caller.len != caller_width) return error.InvalidKeccakWindowSource;
            const unused: [State.state_cell_count]Q = @splat(Q.zero());
            const events = if (local_zero)
                try Local.coreEvents(Q, caller, &unused, &unused, relations)
            else
                Caller.coreEvents(Q, caller, &unused, &unused, relations);
            return .{
                .{ .wl = owner.mul(events[0].n1), .left = events[0].d1 },
                .{ .wl = owner.mul(events[1].n1), .left = events[1].d1, .wr = owner.mul(events[2].n1), .right = events[2].d1 },
                .{ .wl = owner.mul(events[3].n1), .left = events[3].d1, .wr = owner.mul(events[4].n1), .right = events[4].d1 },
            };
        }
        /// Both state words must be opened from the same original arithmetic
        /// columns at current and +27 points. The surrounding AIR still proves
        /// integer decomposition, frame translation and the transition lookup.
        pub fn memoryPair(comptime S: type, owner: S, caller: []const S, input_word: [32]S, output_word: [32]S, slot: usize) !Pair(S) {
            if (caller.len != caller_width) return error.InvalidKeccakWindowSource;
            var pair = try External.keccakPairFromWordBits(S, caller[0..Caller.Layout.main_columns], input_word, output_word, slot);
            pair.active = pair.active.mul(owner);
            if (local_zero and slot == 0) pair.active = pair.active.mul(try Envelope.weight(S, .keccak, caller, caller[Caller.Layout.enabler], 0));
            return pair;
        }
    };
}

test "Keccak selected sources preserve exact original tuples off domain" {
    const record = @import("../runner/guest_precompile/keccakf_call_buffer.zig").Record{
        .execution_clock = 7,
        .pc = 1024,
        .state_ptr = 4096,
        .pointer_register = 4,
        .pointer_previous_clock = 1,
        .input = @splat(9),
        .output = @splat(17),
        .memory_previous_clocks = @splat(2),
    };
    const base = try Local.fill(record);
    var caller: [Local.Layout.main_columns]Q = undefined;
    for (&caller, base) |*out, value| out.* = Q.fromBase(value);
    const relations = Relations.Relations.dummy();
    const zero_state: [State.state_cell_count]Q = @splat(Q.zero());
    const events = try Local.coreEvents(Q, &caller, &zero_state, &zero_state, &relations);
    const owner = Q.fromBase(M.fromCanonical(7)); // OODS need not be Boolean.
    const terms = try For(true).control(owner, &caller, &relations);
    try std.testing.expectEqualDeep(owner.mul(events[0].n1), terms[0].wl);
    try std.testing.expectEqualDeep(events[0].d1, terms[0].left);
    for ([_][2]usize{ .{ 1, 2 }, .{ 3, 4 } }, terms[1..]) |pair, term| {
        try std.testing.expectEqualDeep(owner.mul(events[pair[0]].n1), term.wl);
        try std.testing.expectEqualDeep(owner.mul(events[pair[1]].n1), term.wr);
        try std.testing.expectEqualDeep(events[pair[0]].d1, term.left);
        try std.testing.expectEqualDeep(events[pair[1]].d1, term.right);
    }
    const input: [32]Q = @splat(Q.one());
    const output: [32]Q = @splat(Q.zero());
    const original = try External.keccakPairFromWordBits(Q, caller[0..Caller.Layout.main_columns], input, output, 1);
    var expected = original;
    expected.active = expected.active.mul(owner);
    try std.testing.expectEqualDeep(expected, try For(true).memoryPair(Q, owner, &caller, input, output, 1));
    const disabled = try For(true).memoryPair(Q, Q.zero(), &caller, input, output, 1);
    try std.testing.expect(disabled.active.isZero());
    // Values are not silently zeroed: the same openings and tuple identity
    // remain visible to the AIR even at an unselected row.
    try std.testing.expectEqualDeep(original.before, disabled.before);
    try std.testing.expectEqualDeep(original.after, disabled.after);
}

test "Keccak selected sources retain local x0 register suppression" {
    const record = @import("../runner/guest_precompile/keccakf_call_buffer.zig").Record{
        .execution_clock = 1,
        .pc = 1024,
        .state_ptr = 0,
        .pointer_register = 0,
        .pointer_previous_clock = 0,
        .input = @splat(0),
        .output = @splat(0),
        .memory_previous_clocks = @splat(0),
    };
    const base = try Local.fill(record);
    var caller: [Local.Layout.main_columns]Q = undefined;
    for (&caller, base) |*out, value| out.* = Q.fromBase(value);
    const relations = Relations.Relations.dummy();
    const terms = try For(true).control(Q.one(), &caller, &relations);
    try std.testing.expect(terms[2].wl.isZero() and terms[2].wr.isZero());
    const bits: [32]Q = @splat(Q.zero());
    const pointer = try For(true).memoryPair(Q, Q.one(), &caller, bits, bits, 0);
    try std.testing.expect(pointer.active.isZero());
    const ram = try For(true).memoryPair(Q, Q.one(), &caller, bits, bits, 1);
    try std.testing.expect(ram.active.eql(Q.one()));
}
