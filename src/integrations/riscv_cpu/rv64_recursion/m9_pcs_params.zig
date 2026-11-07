//! M9 proof-params prototype policy (`STWO_RV64_M9_PCS_PARAMS`, default OFF).
//!
//! Grammar (comma separated, every key optional, each at most once):
//!   native=b<B>q<Q>p<P>   leaf=b<B>q<Q>p<P>   fold=b<B>q<Q>p<P>   leaf_cap=<C>   fold_cap=<C>
//! with B the blowup (2, 4, 8 or 16), Q queries and P PoW bits, e.g.
//!   STWO_RV64_M9_PCS_PARAMS=leaf_cap=3
//!   STWO_RV64_M9_PCS_PARAMS=native=b4q52p24,leaf=b2q104p24,fold=b2q104p24,leaf_cap=3,fold_cap=5
//!
//! Every PCS triple must reach the conjectured 128-bit target of the layer it replaces
//! (ethSTARK accounting, log2(B) * Q + P >= 128, as `om31_security_candidate.conjecturedBits` and
//! `circuit_cpu/om31/protocol.zig conjecturedBits`), P <= 32 (the CUDA grind kernel and the OM31
//! shape check refuse more), and a cap must fit the in-circuit verifier guard (`proof.zig`
//! fromNativeCappedImpl: cap_log <= 5 today). Selection is process policy, like
//! STWO_RV64_OUTER_PROFILE: proof bytes never select it. A Merkle cap changes the leaf/fold
//! circuit, hence its VK, so a receiver without the same policy rejects (fails closed). Only `leaf_cap` is wired
//! (leaf_graph.zig cpuMode, CPU-graph leaves; truth leaves and folds are integration work). PCS triples
//! are parsed and validated here but are NOT wired into any prover: changing them needs new native /
//! outer profiles with their own domains (design/riscv-proving-stack/rv64-m9-proof-params.md s7).
const std = @import("std");

pub const ENV = "STWO_RV64_M9_PCS_PARAMS";
pub const TARGET_BITS: u32 = 128;
pub const MAX_POW_BITS: u32 = 32;
/// `fromNativeCappedImpl` refuses cap_log > 5; raising it is part of the integration step.
pub const MAX_CAP_LOG: u32 = 5;
/// Leaf circuits verify native proofs; cap 3 is measured exact (m9_leaf_cap_census_test, circuit valid), cap 5 fails the
/// host cap derivation on the native FIXED tree (height 18, mixed-size preprocessed columns). Raise after that fix.
pub const MAX_LEAF_CAP_LOG: u32 = 3;

pub const Pcs = struct {
    log_blowup: u32,
    queries: u32,
    pow_bits: u32,
    pub fn conjecturedBits(self: Pcs) u32 {
        return self.log_blowup * self.queries + self.pow_bits;
    }
    /// Robustness check under the provable Johnson regime (sqrt(rho) per query), times two.
    pub fn johnsonBitsTimesTwo(self: Pcs) u32 {
        return self.log_blowup * self.queries + 2 * self.pow_bits;
    }
};

pub const Params = struct {
    native: ?Pcs = null,
    leaf: ?Pcs = null,
    fold: ?Pcs = null,
    leaf_cap: u32 = 0,
    fold_cap: ?u32 = null,
};

pub const Error = error{ InvalidM9PcsParams, M9PcsParamsBelowTarget, M9PcsParamsUnsupported, UnreadableM9PcsParams };

fn parsePcs(text: []const u8) Error!Pcs {
    if (text.len < 6 or text[0] != 'b') return error.InvalidM9PcsParams;
    const q = std.mem.indexOfScalar(u8, text, 'q') orelse return error.InvalidM9PcsParams;
    const p = std.mem.indexOfScalar(u8, text, 'p') orelse return error.InvalidM9PcsParams;
    if (!(1 < q and q + 1 < p and p + 1 < text.len)) return error.InvalidM9PcsParams;
    const blowup = std.fmt.parseInt(u32, text[1..q], 10) catch return error.InvalidM9PcsParams;
    const queries = std.fmt.parseInt(u32, text[q + 1 .. p], 10) catch return error.InvalidM9PcsParams;
    const pow = std.fmt.parseInt(u32, text[p + 1 ..], 10) catch return error.InvalidM9PcsParams;
    const log_blowup: u32 = switch (blowup) {
        2 => 1,
        4 => 2,
        8 => 3,
        16 => 4,
        else => return error.M9PcsParamsUnsupported,
    };
    if (queries == 0 or queries > 1024) return error.M9PcsParamsUnsupported;
    if (pow > MAX_POW_BITS) return error.M9PcsParamsUnsupported;
    const out = Pcs{ .log_blowup = log_blowup, .queries = queries, .pow_bits = pow };
    if (out.conjecturedBits() < TARGET_BITS) return error.M9PcsParamsBelowTarget;
    return out;
}

fn parseCap(text: []const u8) Error!u32 {
    const cap = std.fmt.parseInt(u32, text, 10) catch return error.InvalidM9PcsParams;
    if (cap > MAX_CAP_LOG) return error.M9PcsParamsUnsupported;
    return cap;
}

pub fn parse(text: []const u8) Error!Params {
    var out = Params{};
    var seen = [_]bool{false} ** 5;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |item| {
        const eq = std.mem.indexOfScalar(u8, item, '=') orelse return error.InvalidM9PcsParams;
        const key = item[0..eq];
        const value = item[eq + 1 ..];
        const slot: usize = if (std.mem.eql(u8, key, "native")) 0 else if (std.mem.eql(u8, key, "leaf")) 1 else if (std.mem.eql(u8, key, "fold")) 2 else if (std.mem.eql(u8, key, "leaf_cap")) 3 else if (std.mem.eql(u8, key, "fold_cap")) 4 else return error.InvalidM9PcsParams;
        if (seen[slot]) return error.InvalidM9PcsParams;
        seen[slot] = true;
        switch (slot) {
            0 => out.native = try parsePcs(value),
            1 => out.leaf = try parsePcs(value),
            2 => out.fold = try parsePcs(value),
            3 => {
                out.leaf_cap = try parseCap(value);
                if (out.leaf_cap > MAX_LEAF_CAP_LOG) return error.M9PcsParamsUnsupported;
            },
            else => out.fold_cap = try parseCap(value),
        }
    }
    return out;
}

/// Null when the variable is absent (default: no change anywhere). Any other lookup failure or a
/// malformed / under-target value is an error, never a silent default.
pub fn fromEnv() Error!?Params {
    var buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const text = std.process.getEnvVarOwned(fba.allocator(), ENV) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return error.UnreadableM9PcsParams,
    };
    return try parse(text);
}

/// Leaf-circuit native-proof Merkle cap selected by the policy (0 when unset).
pub fn leafCapFromEnv() Error!u32 {
    return if (try fromEnv()) |p| p.leaf_cap else 0;
}

test "m9 pcs params: production layers sit exactly at 128 conjectured bits" {
    try std.testing.expectEqual(@as(u32, 128), (try parsePcs("b4q54p20")).conjecturedBits()); // native D2
    try std.testing.expectEqual(@as(u32, 128), (try parsePcs("b2q108p20")).conjecturedBits()); // r1 leaf/fold
    try std.testing.expectEqual(@as(u32, 128), (try parsePcs("b4q52p24")).conjecturedBits());
    try std.testing.expectEqual(@as(u32, 128), (try parsePcs("b2q104p24")).conjecturedBits());
    try std.testing.expectEqual(@as(u32, 128), (try parsePcs("b8q36p20")).conjecturedBits());
    try std.testing.expectEqual(@as(u32, 148), (try parsePcs("b4q54p20")).johnsonBitsTimesTwo()); // 74 bits
}

test "m9 pcs params: under-target, oversized PoW, unknown keys and duplicates fail closed" {
    try std.testing.expectError(error.M9PcsParamsBelowTarget, parsePcs("b4q53p20"));
    try std.testing.expectError(error.M9PcsParamsBelowTarget, parsePcs("b2q100p24"));
    try std.testing.expectError(error.M9PcsParamsUnsupported, parsePcs("b4q48p33"));
    try std.testing.expectError(error.M9PcsParamsUnsupported, parsePcs("b3q54p20"));
    try std.testing.expectError(error.InvalidM9PcsParams, parse("native=b4q54p20,native=b4q54p20"));
    try std.testing.expectError(error.InvalidM9PcsParams, parse("leafcap=5"));
    try std.testing.expectError(error.M9PcsParamsUnsupported, parse("leaf_cap=6"));
    try std.testing.expectError(error.InvalidM9PcsParams, parse("leaf_cap="));
}

test "m9 pcs params: recommended sets parse" {
    const a = try parse("leaf_cap=3,fold_cap=5");
    try std.testing.expectEqual(@as(u32, 3), a.leaf_cap);
    try std.testing.expectError(error.M9PcsParamsUnsupported, parse("leaf_cap=5"));
    try std.testing.expectEqual(@as(?u32, 5), a.fold_cap);
    try std.testing.expect(a.native == null and a.leaf == null and a.fold == null);
    const b = try parse("native=b4q52p24,leaf=b2q104p24,fold=b2q104p24,leaf_cap=3");
    try std.testing.expectEqual(@as(u32, 52), b.native.?.queries);
    try std.testing.expectEqual(@as(u32, 24), b.fold.?.pow_bits);
    try std.testing.expectEqual(@as(u32, 1), b.leaf.?.log_blowup);
}
