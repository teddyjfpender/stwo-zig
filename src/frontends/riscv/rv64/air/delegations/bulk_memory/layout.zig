//! Column maps for the three bulk-memory bridge kinds.
//!
//! Every RAM access embeds one strict-clock block of six columns
//! `before_epoch, before_low, before_high, same, gap16, gap8` (offsets below).
//! All accesses of one call share the CPU step's after clock `(E, TL, TH)`.
pub const Kind = enum { desc, copy, set };
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
pub const desc = struct {
    pub const active = 0;
    pub const set = 1;
    pub const pointer = 2; // 4 limbs, a0
    pub const carry8 = 6; // 3 carries: pointer -> pointer + 8
    pub const carry16 = 9; // 3 carries: pointer + 8 -> pointer + 16
    pub const epoch = 12;
    pub const tick_low = 13;
    pub const tick_high = 14;
    pub const dst = 15; // packet word 0
    pub const word1 = 19; // packet word 1: src (copy) or fill word (set)
    pub const len_q0 = 23; // len limb 0 / 8
    pub const len_l1 = 24; // len limb 1; limbs 2, 3 are zero
    pub const fill_low = 25; // low byte of word1 limb 0
    pub const fill_high = 26; // high byte of word1 limb 0
    pub const clocks = 27; // 3 x CLOCK
    pub const writable = 45; // 3 packet W bits
    pub const MAIN = 48;
};
pub const copy = struct {
    pub const active = 0;
    pub const start = 1;
    pub const epoch = 2;
    pub const tick_low = 3;
    pub const tick_high = 4;
    pub const remaining = 5;
    pub const dst = 6;
    pub const dst_carry = 10;
    pub const src = 13;
    pub const src_carry = 17;
    pub const value = 20; // src value = dst after value
    pub const dst_before = 24;
    pub const dst_clock = 28;
    pub const src_clock = 34;
    pub const src_writable = 40;
    pub const MAIN = 41;
};
pub const set = struct {
    pub const active = 0;
    pub const start = 1;
    pub const epoch = 2;
    pub const tick_low = 3;
    pub const tick_high = 4;
    pub const remaining = 5;
    pub const dst = 6;
    pub const dst_carry = 10;
    pub const fill = 13;
    pub const dst_before = 14;
    pub const dst_clock = 18;
    pub const MAIN = 24;
};
/// Fractions per row: desc 6 RAM + 3 OWNER + 17 range16; copy 4 + 1 + 6;
/// set 2 + 1 + 3. Consecutive fractions share one inverse column group.
pub fn fractionCount(kind: Kind) usize {
    return switch (kind) {
        .desc => 26,
        .copy => 11,
        .set => 6,
    };
}
pub fn range16Count(kind: Kind) usize {
    return switch (kind) {
        .desc => 17,
        .copy => 6,
        .set => 3,
    };
}
pub fn slots(kind: Kind) usize {
    return (fractionCount(kind) + 1) / 2;
}
/// Relation prefixes follow the inverse slots: RAM, OWNER, RANGE16.
pub fn prefix(kind: Kind, relation: usize) usize {
    return 4 * slots(kind) + 4 * relation;
}
pub fn main(kind: Kind) usize {
    return switch (kind) {
        .desc => desc.MAIN,
        .copy => copy.MAIN,
        .set => set.MAIN,
    };
}
pub fn interaction(kind: Kind) usize {
    return 4 * slots(kind) + 12;
}
pub fn widths(kind: Kind) [3]usize {
    return .{ FIXED, main(kind), interaction(kind) };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .desc => 94,
        .copy => 93,
        .set => 59,
    };
}
pub fn previousMainFor(kind: Kind, c: usize) bool {
    return switch (kind) {
        .desc => c == desc.active,
        .copy => c == copy.active or (c >= copy.epoch and c <= copy.remaining) or (c >= copy.dst and c < copy.dst + 4) or (c >= copy.src and c < copy.src + 4),
        .set => c == set.active or (c >= set.epoch and c <= set.remaining) or (c >= set.dst and c < set.dst + 4) or c == set.fill,
    };
}
pub fn previousInterFor(kind: Kind, c: usize) bool {
    return c >= 4 * slots(kind);
}
