//! Local-zero pointer recipe shared by caller arithmetic, counter extraction
//! and same-root projections. This is a source recipe, not a proof receipt.
//! Every caller keeps the original pointer/access/RW ordinals. Only the exact
//! pointer consume/emit/gap numerators receive the constrained nonzero weight.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const zero = @import("../x0_local_custody_v1.zig");
const keccak = @import("keccakf_caller.zig");
const signer = @import("secp256k1_recovery_caller.zig");
const sha = @import("sha256_memory_caller.zig");

pub const VERSION: u32 = 1;
/// Caller pointer space is statically0 and liveness is its linear column;
/// the dynamic RW/conditional native envelope needs the larger degree4 bound.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const Kind = enum(u8) { keccak, signer, sha };
pub const Pointer = struct { register: usize, previous_clock: usize, bytes: usize };
pub fn pointers(kind: Kind) []const Pointer {
    return switch (kind) {
        .keccak => &.{.{ .register = keccak.Layout.pointer_register, .previous_clock = keccak.Layout.pointer_previous_clock, .bytes = keccak.Layout.pointer_bytes }},
        .signer => &.{.{ .register = signer.Layout.pointer_register, .previous_clock = signer.Layout.pointer_previous_clock, .bytes = signer.Layout.pointer_bytes }},
        .sha => &.{
            .{ .register = sha.Layout.registers, .previous_clock = sha.Layout.register_previous, .bytes = sha.Layout.pointers },
            .{ .register = sha.Layout.registers + 1, .previous_clock = sha.Layout.register_previous + 1, .bytes = sha.Layout.pointers + 4 },
        },
    };
}
pub fn oldWidth(kind: Kind) usize {
    return switch (kind) {
        .keccak => keccak.Layout.main_columns,
        .signer => signer.Layout.main_columns,
        .sha => sha.PHYSICAL_MAIN_COLUMN_COUNT,
    };
}
pub fn mainWidth(kind: Kind) usize {
    return oldWidth(kind) + zero.HINT_COLUMNS * pointers(kind).len;
}
pub fn directCount(kind: Kind) usize {
    return zero.CONSTRAINT_COUNT * pointers(kind).len;
}
pub fn abiId(kind: Kind) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x58304350, VERSION, @intFromEnum(kind), @intCast(oldWidth(kind)), @intCast(mainWidth(kind)), @intCast(directCount(kind)), MAXIMUM_CONSTRAINT_DEGREE });
    channel.mixRoot(zero.abiId());
    for (pointers(kind)) |pointer| channel.mixU32s(&.{ @intCast(pointer.register), @intCast(pointer.previous_clock), @intCast(pointer.bytes) });
    // The shipped caller owns every original tuple. Recipe identity fixes
    // only the exact pointer offsets and added canonical hint grammar.
    return channel.digestBytes();
}

pub fn access(comptime S: type, kind: Kind, main: []const S, active: S, ordinal: usize) !zero.Algebra(S).Access {
    if (main.len != mainWidth(kind) or ordinal >= pointers(kind).len) return error.InvalidX0CallerGeometry;
    const pointer = pointers(kind)[ordinal];
    return .{
        .active = active,
        .space = S.zero(),
        .address = main[pointer.register],
        .previous_clock = main[pointer.previous_clock],
        .before = main[pointer.bytes..][0..4].*,
        .after = main[pointer.bytes..][0..4].*,
        .nonzero = main[oldWidth(kind) + 2 * ordinal],
        .inverse = main[oldWidth(kind) + 2 * ordinal + 1],
    };
}
pub fn evaluateDirect(comptime S: type, kind: Kind, main: []const S, active: S, sink: anytype) !void {
    for (0..pointers(kind).len) |ordinal| {
        for (zero.Algebra(S).constraints(try access(S, kind, main, active, ordinal))) |term| sink.add(term, MAXIMUM_CONSTRAINT_DEGREE);
    }
}
pub fn weight(comptime S: type, kind: Kind, main: []const S, active: S, ordinal: usize) !S {
    return zero.Algebra(S).custodyWeight(try access(S, kind, main, active, ordinal));
}

/// Before commitment only. Zero pointer bytes are checked in the actual source
/// cells; its exact predecessor column is normalized to zero. Receiver/OODS
/// authority comes from evaluateDirect, never from this host branch.
pub fn fillHintsAndNormalize(kind: Kind, main: []M, active: M) !void {
    if (main.len != mainWidth(kind) or (!active.isZero() and !active.eql(M.one()))) return error.InvalidX0CallerGeometry;
    for (pointers(kind), 0..) |pointer, ordinal| {
        const hint = if (active.isZero()) zero.Hint{ .nonzero = M.zero(), .inverse = M.zero() } else try zero.Hint.forAddress(0, main[pointer.register].toU32());
        if (!active.isZero() and hint.nonzero.isZero()) {
            for (main[pointer.bytes..][0..4]) |byte| if (!byte.isZero()) return error.NonzeroX0CallerPointer;
            main[pointer.previous_clock] = M.zero();
            // SHA also commits the exact gap value constrained by its original
            // equality. Recompute the value, preserving that equation even
            // though only its range20 multiplicity disappears.
            if (kind == .sha) main[sha.Layout.register_gap + ordinal] = main[sha.Layout.register_clock].sub(active);
        }
        main[oldWidth(kind) + 2 * ordinal] = hint.nonzero;
        main[oldWidth(kind) + 2 * ordinal + 1] = hint.inverse;
    }
}
pub fn InteractionScalar(comptime S: type) type {
    return if (S == M) Q else S;
}
pub fn lift(comptime S: type, value: S) InteractionScalar(S) {
    return if (S == M) Q.fromBase(value) else value;
}

test "block-v5 x0 caller pointer equations reject source clock and hint mutation for every caller" {
    const Sink = struct {
        rejected: bool = false,
        pub fn add(self: *@This(), value: Q, _: u32) void {
            self.rejected = self.rejected or !value.isZero();
        }
    };
    for ([_]Kind{ .keccak, .signer, .sha }) |kind| {
        const a = std.testing.allocator;
        const values = try a.alloc(Q, mainWidth(kind));
        defer a.free(values);
        @memset(values, Q.zero());
        for (0..pointers(kind).len) |ordinal| {
            var clean = Sink{};
            try evaluateDirect(Q, kind, values, Q.one(), &clean);
            try std.testing.expect(!clean.rejected);
            try std.testing.expect((try weight(Q, kind, values, Q.one(), ordinal)).isZero());
            const pointer = pointers(kind)[ordinal];
            values[pointer.bytes + 2] = Q.one();
            var read = Sink{};
            try evaluateDirect(Q, kind, values, Q.one(), &read);
            try std.testing.expect(read.rejected);
            values[pointer.bytes + 2] = Q.zero();
            values[pointer.previous_clock] = Q.one();
            var clock = Sink{};
            try evaluateDirect(Q, kind, values, Q.one(), &clock);
            try std.testing.expect(clock.rejected);
            values[pointer.previous_clock] = Q.zero();
            values[oldWidth(kind) + 2 * ordinal] = Q.one();
            var hint = Sink{};
            try evaluateDirect(Q, kind, values, Q.one(), &hint);
            try std.testing.expect(hint.rejected);
            values[oldWidth(kind) + 2 * ordinal] = Q.zero();
        }
    }
}
