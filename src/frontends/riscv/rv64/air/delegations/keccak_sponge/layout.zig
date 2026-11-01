//! Column maps of the two Keccak-sponge bridge kinds (both inside the CPU proof).
//!
//! `call`: one row per ECALL (packet, 25 state words, links, token).
//! `perm`: one row per permutation; the rows of one call are a contiguous run.
//! Every RAM access embeds one strict-clock block of six columns
//! `before_epoch, before_low, before_high, same, gap16, gap8`; all accesses of
//! one call share the CPU step's after clock `(E, TL, TH)`.
pub const Kind = enum { call, perm };
pub const FIXED = 3; // logical row index, first-row, last-row selectors
pub const CLOCK = 6;
pub const clock = struct {
    pub const epoch = 0;
    pub const low = 1;
    pub const high = 2;
    pub const same = 3;
    pub const gap16 = 4;
    pub const gap8 = 5;
};
pub const call = struct {
    pub const active = 0;
    pub const pointer = 1; // a0 limbs
    pub const pcarry = 5; // 3 steps x 3 carries: a0 -> a0+8 -> a0+16 -> a0+24
    pub const epoch = 14;
    pub const tick_low = 15;
    pub const tick_high = 16;
    pub const state = 17; // packet word 0: state pointer limbs
    pub const shift = 21; // one-hot of in & 7
    pub const in_q0 = 29; // in limb 0 = shift + 8 * in_q0
    pub const in_hi = 30; // in limbs 1..3
    pub const len0 = 33; // len limbs 0, 1 (limbs 2, 3 zero)
    pub const len1 = 34;
    pub const fin = 35; // flags = fin + 2 fresh
    pub const fresh = 36;
    pub const q = 37; // len = 136 q + r
    pub const r = 38;
    pub const zero = 39; // len == 0
    pub const zinv = 40;
    pub const e = 41; // shift + len - 1 = 8 (words - 1) + e when len > 0
    pub const words = 42;
    pub const id = 43; // IO11 ID of the call's first permutation
    pub const pclock = 44; // 4 x CLOCK
    pub const pwritable = 68; // 4 packet W bits
    pub const sclock = 72; // 25 x CLOCK
    pub const scarry = 222; // lanes 1..24 x 3 carries: state + 8 l
    pub const old = 294; // 25 x 8 state bytes before
    pub const new = 494; // 25 x 8 state bytes after
    pub const MAIN = 694;
};
pub const perm = struct {
    pub const active = 0;
    pub const first = 1;
    pub const last = 2;
    pub const lastfin = 3; // last * fin
    pub const freshfirst = 4; // first row of a fresh call
    pub const epoch = 5;
    pub const tick_low = 6;
    pub const tick_high = 7;
    pub const fin = 8;
    pub const shift = 9; // 8 one-hot
    pub const base = 17; // 4 limbs: aligned address of word 17k
    pub const bcarry = 21; // base = previous base + 136
    pub const rb = 24; // message bytes remaining at this block
    pub const wr = 25; // message words remaining at this block
    pub const pre = 26; // 25 x 8 bytes of the state before absorption
    pub const and_ = 226; // 136 bytes pre AND msg (rate lanes)
    pub const msg = 362; // 136 absorbed bytes (masked data and padding)
    pub const mask = 498; // 136 thermometer bits: byte t is message data
    pub const window = 634; // 18 slots x 8 bytes of message words 17k + j
    pub const read = 778; // 18 read flags
    pub const wcarry = 796; // slots 1..17 x 3 carries: base + 8 j
    pub const wclock = 847; // 18 x CLOCK
    pub const wwritable = 955; // 18 slot W bits
    pub const MAIN = 973;
};

pub fn main(kind: Kind) usize {
    return switch (kind) {
        .call => call.MAIN,
        .perm => perm.MAIN,
    };
}
/// Fractions per row (equations.fractions order):
/// call: OWNER 2, RAM 58, IO 50, U16 33, U8 34;
/// perm: OWNER 1, IO 50, AND 136, RAM 36, U16 18, U8 90.
pub fn range16Count(kind: Kind) usize {
    return switch (kind) {
        .call => 33,
        .perm => 18,
    };
}
pub fn range8Count(kind: Kind) usize {
    return switch (kind) {
        .call => 34,
        .perm => 90,
    };
}
pub fn andCount(kind: Kind) usize {
    return switch (kind) {
        .call => 0,
        .perm => 136,
    };
}
pub fn fractionCount(kind: Kind) usize {
    return switch (kind) {
        .call => 2 + 58 + 50 + 33 + 34,
        .perm => 1 + 50 + 136 + 36 + 18 + 90,
    };
}
pub fn slots(kind: Kind) usize {
    return (fractionCount(kind) + 1) / 2;
}
/// Relation prefixes follow the inverse slots: RAM, OWNER, IO, AND, U16, U8.
pub fn prefix(kind: Kind, relation: usize) usize {
    return 4 * slots(kind) + 4 * relation;
}
pub fn interaction(kind: Kind) usize {
    return 4 * slots(kind) + 4 * 6;
}
pub fn widths(kind: Kind) [3]usize {
    return .{ FIXED, main(kind), interaction(kind) };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .call => CALL_CONSTRAINTS,
        .perm => PERM_CONSTRAINTS,
    };
}
pub const CALL_CONSTRAINTS = 325;
pub const PERM_CONSTRAINTS = 1025;
pub fn previousMainFor(kind: Kind, c: usize) bool {
    return switch (kind) {
        .call => c == call.active,
        .perm => c == perm.active or c == perm.last or (c >= perm.epoch and c < perm.bcarry) or c == perm.rb or c == perm.wr or (c >= perm.window + 8 * 17 and c < perm.window + 8 * 18) or (c >= perm.read and c < perm.read + 18),
    };
}
pub fn previousInterFor(kind: Kind, c: usize) bool {
    return c >= 4 * slots(kind);
}
