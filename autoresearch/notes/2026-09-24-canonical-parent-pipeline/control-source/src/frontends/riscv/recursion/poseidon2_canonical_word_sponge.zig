//! Canonical-word sponge framing shared by native hashing and authenticated
//! provider-call recording. The caller supplies the scalar and permutation;
//! this module owns only absorption, domain placement and final padding.
pub const WIDTH = @import("../air/memory_commitment/poseidon2.zig").WIDTH;
pub const RATE = WIDTH / 2;

pub fn initialState(comptime S: type, zero: S, tag: S) [WIDTH]S {
    var state: [WIDTH]S = @splat(zero);
    state[WIDTH - 1] = tag;
    return state;
}

/// Caller has `state`, `filled`, and `permute()` over that state.
pub fn absorb(sponge: anytype, word: @TypeOf(sponge.state[0])) void {
    sponge.state[sponge.filled] = sponge.state[sponge.filled].add(word);
    sponge.filled += 1;
    if (sponge.filled == RATE) {
        sponge.permute();
        sponge.filled = 0;
    }
}

pub fn finish(sponge: anytype, one: @TypeOf(sponge.state[0])) void {
    absorb(sponge, one);
    if (sponge.filled != 0) {
        sponge.permute();
        sponge.filled = 0;
    }
}
