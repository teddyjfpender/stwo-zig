//! Concrete epoch16/tick24/RW2 closed foundation, NOT the future time64 schema.
pub const TRANS_MAIN = 28;
pub const trans = struct {
    pub const active = 0;
    pub const write = 1;
    pub const same = 2;
    pub const owner = 3;
    pub const address = 4;
    pub const before_epoch = 8;
    pub const after_epoch = 9;
    pub const before_low = 10;
    pub const before_high = 11;
    pub const after_low = 12;
    pub const after_high = 13;
    pub const before_value = 14;
    pub const after_value = 18;
    pub const readable = 22;
    pub const writable = 23;
    pub const epoch_gap = 24;
    pub const gap_low = 25;
    pub const gap_high = 26;
    pub const carry = 27;
};
pub const T_U16 = [_]usize{ 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 16, 17, 18, 19, 20, 21, 24, 25 };
pub const T_U8 = [_]usize{ 11, 13, 26 };
pub const BOUND_MAIN = 23;
pub const boundary = struct {
    pub const active = 0;
    pub const address = 1;
    pub const value = 5;
    pub const epoch = 9;
    pub const low = 10;
    pub const high = 11;
    pub const readable = 12;
    pub const writable = 13;
    pub const delta = 14;
    pub const carry = 18;
    pub const inverse_delta = 22;
};
pub const B_U16 = [_]usize{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 15, 16, 17 };
pub const B_U8 = [_]usize{11};
pub fn pairColumns(n: usize) usize {
    return 4 * ((n + 1) / 2) + 4;
}
pub const T_RAM = 0;
pub const T_OWNER = 8;
pub const T_RANGE16 = 16;
pub const T_RANGE8 = T_RANGE16 + pairColumns(T_U16.len);
pub const TRANS_INTER = T_RANGE8 + pairColumns(T_U8.len);
pub const B_RAM = 0;
pub const B_RANGE16 = 8;
pub const B_RANGE8 = B_RANGE16 + pairColumns(B_U16.len);
pub const BOUND_INTER = B_RANGE8 + pairColumns(B_U8.len);
pub const Kind = enum { transition, initial, terminal, owner, range16, range8 };
pub fn widths(kind: Kind) [3]usize {
    return switch (kind) {
        .transition => .{ 3, TRANS_MAIN, TRANS_INTER },
        .initial, .terminal => .{ 34, BOUND_MAIN, BOUND_INTER },
        .owner => .{ 34, 14, 8 },
        .range16, .range8 => .{ 3, 1, 8 },
    };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .transition => 72,
        .initial, .terminal => 51,
        .owner => 18,
        .range16, .range8 => 3,
    };
}
pub fn previousMain(kind: Kind, c: usize) bool {
    return if (kind == .transition) c == trans.active else (kind == .initial or kind == .terminal) and c >= boundary.address and c < boundary.address + 4;
}
pub fn previousInter(kind: Kind, c: usize) bool {
    return switch (kind) {
        .transition => (c >= 4 and c < 8) or (c >= 12 and c < 16) or (c >= T_RANGE8 - 4 and c < T_RANGE8) or c >= TRANS_INTER - 4,
        .initial, .terminal => (c >= 4 and c < 8) or (c >= B_RANGE8 - 4 and c < B_RANGE8) or c >= BOUND_INTER - 4,
        .owner, .range16, .range8 => c >= 4,
    };
}
