//! Direct-constraint mutation fleet for the paired Keccak-f witness.

const std = @import("std");
const authority = @import("keccakf_authority.zig");
const witness = @import("keccakf_witness.zig");

fn state(seed: u64) authority.State {
    var result: authority.State = undefined;
    for (&result, 0..) |*lane, index|
        lane.* = seed +% (@as(u64, index) *% 0x9e3779b97f4a7c15);
    return result;
}

test "keccakf witness: empty, odd, and paired slots validate" {
    const empty = try witness.buildSlot(null, null);
    try witness.validateSlot(&empty);

    const odd = try witness.buildSlot(state(1), null);
    try witness.validateSlot(&odd);
    try std.testing.expectEqual(@as(u8, 1), odd.rows[0].in_use_a);
    try std.testing.expectEqual(@as(u8, 0), odd.rows[0].in_use_b);

    const paired = try witness.buildSlot(state(1), state(2));
    try witness.validateSlot(&paired);
    try std.testing.expectEqual(@as(u8, 1), paired.rows[28].in_use_b);
    try std.testing.expect(!std.meta.eql(odd.rows[26].state, paired.rows[26].state));
}

test "keccakf witness: activation and inactive mutations reject" {
    var invalid_order = try witness.buildSlot(state(1), state(2));
    invalid_order.rows[7].in_use_a = 0;
    try std.testing.expectError(error.InvalidActivation, witness.validateSlot(&invalid_order));

    var invalid_selector = try witness.buildSlot(state(1), null);
    invalid_selector.rows[0].in_use_b = 2;
    try std.testing.expectError(error.InvalidActivation, witness.validateSlot(&invalid_selector));

    var dirty_empty = try witness.buildSlot(null, null);
    dirty_empty.rows[12].state[99] = 1;
    try std.testing.expectError(error.EmptySlotNotCanonical, witness.validateSlot(&dirty_empty));
    try std.testing.expectError(error.InvalidActivation, witness.buildSlot(null, state(3)));
}

test "keccakf witness: boundary and slice mutations reject" {
    var boundary = try witness.buildSlot(state(3), state(5));
    boundary.rows[0].state[17] = 2;
    try std.testing.expectError(error.BoundaryNotBoolean, witness.validateSlot(&boundary));

    var input_glue = try witness.buildSlot(state(3), state(5));
    input_glue.rows[2].state[17] ^= 1;
    try std.testing.expectError(error.InvalidSliceGlue, witness.validateSlot(&input_glue));

    var output_glue = try witness.buildSlot(state(3), state(5));
    output_glue.rows[27].state[41] ^= 1;
    try std.testing.expectError(error.InvalidSliceGlue, witness.validateSlot(&output_glue));
}

test "keccakf witness: parity and nonlinear transition mutations reject" {
    var parity = try witness.buildSlot(state(7), state(11));
    parity.rows[9].parity[123] ^= 1;
    try std.testing.expectError(
        error.InvalidParityNormalization,
        witness.validateSlot(&parity),
    );

    var round = try witness.buildSlot(state(7), state(11));
    round.rows[14].state[777] ^= 1;
    try std.testing.expectError(error.InvalidChiTransition, witness.validateSlot(&round));

    var terminal_parity = try witness.buildSlot(state(7), null);
    terminal_parity.rows[26].parity[0] = 1;
    try std.testing.expectError(error.InvalidRoundState, witness.validateSlot(&terminal_parity));
}
