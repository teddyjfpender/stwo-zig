//! Column maps for the six bulk-memory bridge kinds: `desc` (memcpy/memset
//! descriptor), `copy` (aligned source), `set`, `ucopy` (unaligned source),
//! `cdesc` (memcmp descriptor) and `cmp` (memcmp body).
//!
//! Every RAM access embeds one strict-clock block of six columns
//! `before_epoch, before_low, before_high, same, gap16, gap8` (offsets below).
//! All accesses of one call share the CPU step's after clock `(E, TL, TH)`.
pub const Kind = enum { desc, copy, set, ucopy, cdesc, cmp, jdesc, jscan, jtab };
/// The bulk-memory kinds (the JUMPDEST kinds below form their own block).
pub const kinds = [_]Kind{ .desc, .copy, .set, .ucopy, .cdesc, .cmp };
/// JUMPDEST analysis (proposals/jumpdest-bitmap.md): descriptor, one scan row
/// per 64 code bytes (8 code reads, 1 bitmap write) and the fixed transition
/// table with its multiplicities.
pub const jumpdest_kinds = [_]Kind{ .jdesc, .jscan, .jtab };
pub const UCOPY_CONSTRAINTS = 134;
pub const CDESC_CONSTRAINTS = 117;
pub const CMP_CONSTRAINTS = 148;
pub const JDESC_CONSTRAINTS = 88;
pub const JSCAN_CONSTRAINTS = 497;
pub const JTAB_CONSTRAINTS = 7;
pub const FIXED = 3; // logical row index, first-row, last-row selectors
/// jtab adds the four table columns (pending, byte, next, jumpdest) after FIXED.
pub const JTAB_FIXED = FIXED + 4;
pub fn fixedWidth(kind: Kind) usize {
    return if (kind == .jtab) JTAB_FIXED else FIXED;
}
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
/// Unaligned copy: one row per source word. Row 0 of a run (the lead row,
/// `start`) only reads source word 0; row r >= 1 reads source word r and
/// writes destination word r - 1 from the bytes of source words r - 1
/// (previous row) and r at the call's byte shift (one-hot `sel`).
pub const ucopy = struct {
    pub const active = 0;
    pub const start = 1;
    pub const epoch = 2;
    pub const tick_low = 3;
    pub const tick_high = 4;
    pub const remaining = 5;
    pub const dst = 6;
    pub const dst_carry = 10;
    pub const src = 13; // aligned source word address
    pub const src_carry = 17;
    pub const sel = 20; // 7 one-hot shift selectors, shift = 1 + index
    pub const bytes = 27; // 8 bytes of the source word read on this row
    pub const out = 35; // destination after limbs
    pub const dst_before = 39;
    pub const dst_clock = 43;
    pub const src_clock = 49;
    pub const src_writable = 55;
    pub const MAIN = 56;
};
/// memcmp descriptor: packet a, b, len, result at P, P+8, P+16, P+24.
pub const cdesc = struct {
    pub const active = 0;
    pub const pointer = 1;
    pub const carry8 = 5;
    pub const carry16 = 8;
    pub const carry24 = 11;
    pub const epoch = 14;
    pub const tick_low = 15;
    pub const tick_high = 16;
    pub const a = 17;
    pub const b = 21;
    pub const len_q0 = 25;
    pub const len_l1 = 26;
    pub const clocks = 27; // 4 x CLOCK (three packet reads, result write)
    pub const writable = 51; // 3 packet-read W bits
    pub const result_before = 54;
    pub const neg = 58;
    pub const pos = 59;
    pub const len_inv = 60; // (len / 8)^-1: memcmp length is nonzero
    pub const MAIN = 61;
};
/// memcmp body: one row per compared word pair, up to the first difference.
pub const cmp = struct {
    pub const active = 0;
    pub const start = 1;
    pub const epoch = 2;
    pub const tick_low = 3;
    pub const tick_high = 4;
    pub const remaining = 5;
    pub const last = 6;
    pub const is_one = 7; // remaining == 1
    pub const inv = 8; // (remaining - 1)^-1 when remaining != 1
    pub const a = 9;
    pub const a_carry = 13;
    pub const b = 16;
    pub const b_carry = 20;
    pub const va = 23;
    pub const vb = 27;
    pub const a_clock = 31;
    pub const b_clock = 37;
    pub const a_writable = 43;
    pub const b_writable = 44;
    pub const diff = 45;
    pub const limbsel = 46; // one-hot first differing limb (diff rows)
    pub const hb = 50; // first difference in the high byte of that limb
    pub const lt = 51; // a < b at the first differing byte
    pub const alo = 52;
    pub const ahi = 53;
    pub const blo = 54;
    pub const bhi = 55;
    pub const da = 56; // first differing byte of a
    pub const db = 57;
    pub const gap = 58; // (1 - 2 lt)(da - db) - 1 in [0, 2^16)
    pub const MAIN = 59;
};
/// JUMPDEST descriptor: packet code (64 * code_q, limbs 1..3), len (8 * q0,
/// l1, 0, 0), bitmap at P, P+8, P+16.
pub const jdesc = struct {
    pub const active = 0;
    pub const pointer = 1;
    pub const carry8 = 5;
    pub const carry16 = 8;
    pub const epoch = 11;
    pub const tick_low = 12;
    pub const tick_high = 13;
    pub const code_q = 14; // code limb 0 / 64
    pub const code = 15; // code limbs 1..3
    pub const len_q0 = 18;
    pub const len_l1 = 19;
    pub const bitmap = 20; // 4 limbs
    pub const clocks = 24; // 3 x CLOCK
    pub const writable = 42; // 3 packet W bits
    pub const MAIN = 45;
};
/// JUMPDEST scan: one row per 8 code words (64 bytes) and its bitmap word.
/// Byte k of the row has value `bytes + k`, pending PUSH-data counter
/// `pending + k` before it (`pending + 64` after the row) and JUMPDEST bit
/// `jd + k`; `(pending_k, byte_k, pending_{k+1}, jd_k)` is a table lookup.
/// Word w of the row (code + 8w) is read when valid (`valid + w - 1` for
/// w >= 1; word 0 is valid on every active row).
pub const jscan = struct {
    pub const active = 0;
    pub const start = 1;
    pub const last = 2;
    pub const epoch = 3;
    pub const tick_low = 4;
    pub const tick_high = 5;
    pub const remaining = 6; // code words left including this row's
    pub const code = 7; // row base address (64-aligned)
    pub const code_carry = 11;
    pub const bitmap = 14;
    pub const bitmap_carry = 18;
    pub const valid = 21; // 7 bits, words 1..7
    pub const clocks = 28; // 8 x CLOCK (code reads)
    pub const writable = 76; // 8 W bits of the code words
    pub const bytes = 84; // 64
    pub const pending = 148; // 65
    pub const jd = 213; // 64
    pub const before = 277; // bitmap word predecessor value
    pub const wclock = 281; // bitmap write clock block
    pub const MAIN = 287;
};
/// JUMPDEST transition table: MAIN is the multiplicity of the fixed entry.
pub const jtab = struct {
    pub const multiplicity = 0;
    pub const MAIN = 1;
    /// Fixed columns after the FIXED selectors.
    pub const pending = FIXED;
    pub const byte = FIXED + 1;
    pub const next = FIXED + 2;
    pub const jumpdest = FIXED + 3;
};

/// Fractions per row (RAM + OWNER + range16): desc 6 + 3 + 17; copy 4 + 1 + 6;
/// set 2 + 1 + 3; ucopy 4 + 1 + 18; cdesc 8 + 3 + 16; cmp 4 + 2 + 13.
/// Consecutive fractions share one inverse column group.
pub fn fractionCount(kind: Kind) usize {
    return switch (kind) {
        .desc => 26,
        .copy => 11,
        .set => 6,
        .ucopy => 23,
        .cdesc => 27,
        .cmp => 19,
        // 6 RAM + 2 OWNER + (1 + 2 + 1 + 2 + 9) U16
        .jdesc => 23,
        // 18 RAM + (1 + 64) OWNER + 27 U16
        .jscan => 110,
        .jtab => 1,
    };
}
pub fn range16Count(kind: Kind) usize {
    return switch (kind) {
        .desc => 17,
        .copy => 6,
        .set => 3,
        .ucopy => 18,
        .cdesc => 16,
        .cmp => 13,
        .jdesc => 15,
        .jscan => 27,
        .jtab => 0,
    };
}
/// RAM14 fractions per row (each access is a consume/produce pair).
pub fn ramCount(kind: Kind) usize {
    return switch (kind) {
        .desc, .cdesc => if (kind == .desc) 6 else 8,
        .copy, .ucopy, .cmp => 4,
        .set => 2,
        .jdesc => 6,
        .jscan => 18,
        .jtab => 0,
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
        .ucopy => ucopy.MAIN,
        .cdesc => cdesc.MAIN,
        .cmp => cmp.MAIN,
        .jdesc => jdesc.MAIN,
        .jscan => jscan.MAIN,
        .jtab => jtab.MAIN,
    };
}
pub fn interaction(kind: Kind) usize {
    return 4 * slots(kind) + 12;
}
pub fn widths(kind: Kind) [3]usize {
    return .{ fixedWidth(kind), main(kind), interaction(kind) };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .desc => 94,
        .copy => 93,
        .set => 59,
        .ucopy => UCOPY_CONSTRAINTS,
        .cdesc => CDESC_CONSTRAINTS,
        .cmp => CMP_CONSTRAINTS,
        .jdesc => JDESC_CONSTRAINTS,
        .jscan => JSCAN_CONSTRAINTS,
        .jtab => JTAB_CONSTRAINTS,
    };
}
pub fn previousMainFor(kind: Kind, c: usize) bool {
    return switch (kind) {
        .desc => c == desc.active,
        .copy => c == copy.active or (c >= copy.epoch and c <= copy.remaining) or (c >= copy.dst and c < copy.dst + 4) or (c >= copy.src and c < copy.src + 4),
        .set => c == set.active or (c >= set.epoch and c <= set.remaining) or (c >= set.dst and c < set.dst + 4) or c == set.fill,
        .ucopy => c <= ucopy.remaining or (c >= ucopy.dst and c < ucopy.dst + 4) or (c >= ucopy.src and c < ucopy.src + 4) or (c >= ucopy.sel and c < ucopy.bytes + 8),
        .cdesc => c == cdesc.active,
        .cmp => c == cmp.active or (c >= cmp.epoch and c <= cmp.last) or (c >= cmp.a and c < cmp.a + 4) or (c >= cmp.b and c < cmp.b + 4),
        .jdesc => c == jdesc.active,
        .jscan => c == jscan.active or c == jscan.last or (c >= jscan.epoch and c < jscan.code + 4) or (c >= jscan.bitmap and c < jscan.bitmap + 4) or c == jscan.pending + 64,
        .jtab => false,
    };
}
pub fn previousInterFor(kind: Kind, c: usize) bool {
    return c >= 4 * slots(kind);
}
/// Largest widths over all kinds (stack buffers of the evaluators).
pub const MAX_MAIN = jscan.MAIN;
pub const MAX_INTER = blk: {
    var best: usize = 0;
    for (std.enums.values(Kind)) |k| best = @max(best, interaction(k));
    break :blk best;
};
/// Previous-row buffers hold either a MAIN or an INTER row.
pub const MAX_ROW = @max(MAX_MAIN, MAX_INTER);
pub const MAX_TOTAL = blk: {
    var best: usize = 0;
    for (std.enums.values(Kind)) |k| best = @max(best, fixedWidth(k) + main(k) + interaction(k));
    break :blk best;
};
const std = @import("std");
