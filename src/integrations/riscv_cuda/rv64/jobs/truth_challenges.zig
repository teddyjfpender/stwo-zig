//! Truth transcript challenges drawn on the DEVICE (GPU-native TruthJob,
//! rv64-m8-gpu-native.md §3.3). Two scripts, both exact replays of the host
//! transcript operations they replace (same words, same order):
//!
//!   local   the truth's own channel right after its FIXED and MAIN roots:
//!           classic (keccak)  truth_fractions.ChallengesFor(O).draw
//!           delegated (v3)    truth_v3_worker.drawLocal
//!   shared  a FRESH channel over the manifest digest (manifest.drawShared):
//!           ram (15 felts), kio (IoFor.draw), wire (WireFor.draw)
//!
//! A script is data (`Op`s). `run` replays it on the device channel (one
//! DeviceChannel op per `Op`; draws land contiguously in one felt buffer) and
//! `replay` on a host Om31Channel. The host replay is pinned to the legacy
//! draw functions by the tests below, so the device buffer layout is the
//! legacy value layout by construction; the device replay is the same loop
//! over DeviceChannel ops whose byte equality with Om31Channel the channel
//! parity harness covers (channel.zig header).
//!
//! The digest the shared script mixes is a device buffer (the request's seal
//! slot); every other word is a script constant staged once per class.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const api = @import("api.zig");

const S = CPU.rv64_gkr_truth_device_source;
const D = CPU.rv64_device_pcs;
pub const O = D.O;
pub const Channel = CPU.rv64_gkr_worker_protocol.Channel;
pub const Classic = @FieldType(S.Local, "classic");
pub const Shared = S.Shared;

pub const io_arity = A.crypto.keccak.layout.IO_ARITY;
pub const wire_arity = A.crypto.secp256k1.layout.WIRE_ARITY;
pub const ram_felts: u32 = 15;
pub const kio_felts: u32 = 1 + io_arity;
pub const wire_felts: u32 = 1 + wire_arity;
/// Shared felt buffer: [ram 15 | kio offset, coefficients | wire offset, coefficients].
pub const kio_first: u32 = ram_felts;
pub const wire_first: u32 = ram_felts + kio_felts;
pub const shared_felts: u32 = ram_felts + kio_felts + wire_felts;

/// Classic local felt buffer, in draw order:
///   [0] polynomial | [1] chi offset, [2..8) chi coefficients
///   | [8] xor5 offset, [9..15) xor5 coefficients | [15] byte offset
/// (the byte relation's single coefficient is the constant one, not drawn).
pub const classic_felts: u32 = 16;
pub const delegated_felts: u32 = 1;
pub fn classicOffset(relation: u32) u32 {
    return switch (relation) {
        0 => 1,
        1 => 8,
        else => 15,
    };
}
/// Felt index of coefficient `j` of `relation` (chi/xor5 only; null = byte, constant).
pub fn classicCoefficient(relation: u32, j: u32) ?u32 {
    if (relation >= 2 or j >= 6) return null;
    return classicOffset(relation) + 1 + j;
}

pub const Kind = enum { classic, delegated };

pub const Op = union(enum) {
    /// mixU32s of `len` constant words at `first` in the script's word table.
    mix: struct { first: u16, len: u16 },
    /// mixU32s of the 8 manifest digest words (device buffer).
    mix_digest,
    /// `count` sequential drawSecureFelt into the felt buffer (appended).
    draw: u32,
};

pub const Script = struct {
    words: []const u32,
    ops: []const Op,
    felts: u32,
    /// The shared script starts from a fresh channel (seed = Channel.init()),
    /// the local one continues the proof's channel.
    fresh: bool,
};

const local_classic_words = [_]u32{ 0x54474b31, 8, 3, 0x43484936, 0x584f5235, 0x42595445, 0x504f4c59, 0, 6, 1, 6, 2, 1 };
const local_classic_ops = [_]Op{
    .{ .mix = .{ .first = 0, .len = 6 } },
    .{ .mix = .{ .first = 6, .len = 1 } },
    .{ .draw = 1 },
    .{ .mix = .{ .first = 7, .len = 2 } }, // chi: index 0, arity 6
    .{ .draw = 7 },
    .{ .mix = .{ .first = 9, .len = 2 } }, // xor5: index 1, arity 6
    .{ .draw = 7 },
    .{ .mix = .{ .first = 11, .len = 2 } }, // byte: index 2, arity 1 (coefficient = one)
    .{ .draw = 1 },
};
// truth_v3_worker.drawLocal: mixU32s {0x56334259, 1, 8}, drawSecureFelt.
const local_delegated_words = [_]u32{ 0x56334259, 1, 8 };
const local_delegated_ops = [_]Op{ .{ .mix = .{ .first = 0, .len = 3 } }, .{ .draw = 1 } };
// manifest.drawShared.
const shared_words = [_]u32{ 0x53474d31, 1, 8, 0x52414d31, 14, 0x4b494f31, 11, 0x53574952, 35, 0x53575031 };
const shared_ops = [_]Op{
    .{ .mix = .{ .first = 0, .len = 3 } },
    .mix_digest,
    .{ .mix = .{ .first = 3, .len = 2 } },
    .{ .draw = ram_felts },
    .{ .mix = .{ .first = 5, .len = 2 } },
    .{ .draw = kio_felts },
    .{ .mix = .{ .first = 7, .len = 2 } },
    .{ .mix = .{ .first = 9, .len = 1 } }, // WireFor.draw prefix
    .{ .draw = wire_felts },
};

pub const local_classic = Script{ .words = &local_classic_words, .ops = &local_classic_ops, .felts = classic_felts, .fresh = false };
pub const local_delegated = Script{ .words = &local_delegated_words, .ops = &local_delegated_ops, .felts = delegated_felts, .fresh = false };
pub const shared = Script{ .words = &shared_words, .ops = &shared_ops, .felts = shared_felts, .fresh = true };

pub fn local(kind: Kind) Script {
    return if (kind == .classic) local_classic else local_delegated;
}

/// The 9-word checkpoint of a fresh Om31Channel (shared script seed).
pub fn freshSeed() [9]u32 {
    const ch = Channel.init();
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, ch.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = ch.inner.n_draws;
    return seed;
}

/// Device words a staged script needs: its constant words (+ the fresh seed).
pub fn stagedWords(script: Script) usize {
    return script.words.len + if (script.fresh) @as(usize, 9) else 0;
}

/// Host words to stage for `script` (constants, then the fresh seed).
pub fn stageWords(script: Script, out: []u32) !void {
    if (out.len < stagedWords(script)) return error.TruthScriptStageTooSmall;
    @memcpy(out[0..script.words.len], script.words);
    if (script.fresh) @memcpy(out[script.words.len..][0..9], &freshSeed());
}

pub fn validate(script: Script) !void {
    var felts: u32 = 0;
    for (script.ops) |op| switch (op) {
        .mix => |m| if (m.len == 0 or @as(usize, m.first) + m.len > script.words.len) return error.InvalidTruthScript,
        .mix_digest => if (!script.fresh) return error.InvalidTruthScript,
        .draw => |n| {
            if (n == 0) return error.InvalidTruthScript;
            felts += n;
        },
    };
    if (felts != script.felts) return error.InvalidTruthScript;
}

/// Device replay. `staged`: `stageWords` uploaded (device); `digest`: 8 device
/// words (shared script only); `out`: `script.felts * 8` device words.
/// `channel` is the proof's channel (local) or a fresh, uninitialized one
/// (shared: initialized here from the staged seed).
pub fn run(script: Script, channel: *api.DeviceChannel, staged: api.DeviceBuffer, digest: ?api.DeviceBuffer, out: api.DeviceBuffer) !void {
    try validate(script);
    if (staged.words < stagedWords(script) or out.words < @as(usize, script.felts) * 8) return error.TruthScriptBufferTooSmall;
    if (script.fresh) try channel.initFromCheckpoint(try staged.slice(script.words.len, 9));
    var at: usize = 0;
    for (script.ops) |op| switch (op) {
        .mix => |m| try channel.mixWords(try staged.slice(m.first, m.len)),
        .mix_digest => {
            const d = digest orelse return error.TruthScriptDigestRequired;
            try channel.mixWords(try d.slice(0, 8));
        },
        .draw => |n| {
            try channel.drawSecureFelts(n, try out.slice(at * 8, @as(usize, n) * 8));
            at += n;
        },
    };
}

/// Host replay into `out` (felts). `channel`: the proof channel (local) or
/// ignored and replaced by a fresh one (shared).
pub fn replay(script: Script, channel: *Channel, digest: ?[32]u8, out: []O) !void {
    try validate(script);
    if (out.len < script.felts) return error.TruthScriptBufferTooSmall;
    if (script.fresh) channel.* = Channel.init();
    var at: usize = 0;
    for (script.ops) |op| switch (op) {
        .mix => |m| channel.mixU32s(script.words[m.first..][0..m.len]),
        .mix_digest => {
            const d = digest orelse return error.TruthScriptDigestRequired;
            var dw: [8]u32 = undefined;
            for (&dw, 0..) |*w, i| w.* = std.mem.readInt(u32, d[4 * i ..][0..4], .little);
            channel.mixU32s(&dw);
        },
        .draw => |n| for (0..n) |_| {
            out[at] = channel.drawSecureFelt();
            at += 1;
        },
    };
}

/// Felt words (8 canonical M31 coordinates), the device buffer layout.
pub fn words(value: O) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, value.toM31Array()) |*w, c| w.* = c.v;
    return out;
}

/// Legacy value of the classic local challenges from a host felt buffer.
pub fn classicFrom(felts: []const O) !Classic {
    if (felts.len < classic_felts) return error.TruthScriptBufferTooSmall;
    var c: Classic = undefined;
    c.polynomial = felts[0];
    for (0..3) |r| {
        c.offsets[r] = felts[classicOffset(@intCast(r))];
        for (0..6) |j| c.coefficients[r][j] = if (classicCoefficient(@intCast(r), @intCast(j))) |i| felts[i] else if (r == 2 and j == 0) O.one() else O.zero();
    }
    return c;
}

/// Legacy value of the shared challenges from a host felt buffer.
pub fn sharedFrom(felts: []const O) !Shared {
    if (felts.len < shared_felts) return error.TruthScriptBufferTooSmall;
    var s: Shared = undefined;
    s.ram.offset = felts[0];
    for (&s.ram.coefficients, 0..) |*c, i| c.* = felts[1 + i];
    s.kio.offset = felts[kio_first];
    for (&s.kio.coefficients, 0..) |*c, i| c.* = felts[kio_first + 1 + i];
    s.wire.offset = felts[wire_first];
    for (&s.wire.coefficients, 0..) |*c, i| c.* = felts[wire_first + 1 + i];
    return s;
}

comptime {
    // The shared layout is the legacy struct's: a draw-count change upstream
    // must break the build, not the transcript.
    if (@typeInfo(@FieldType(@FieldType(Shared, "ram"), "coefficients")).array.len + 1 != ram_felts) @compileError("ram challenge count changed");
    if (@typeInfo(@FieldType(@FieldType(Shared, "kio"), "coefficients")).array.len != io_arity) @compileError("kio challenge count changed");
    if (@typeInfo(@FieldType(@FieldType(Shared, "wire"), "coefficients")).array.len != wire_arity) @compileError("wire challenge count changed");
}

fn seeded(tag: u32) Channel {
    var ch = Channel.init();
    ch.mixU32s(&.{ 0x7275_7468, tag, 3, 5 });
    return ch;
}

test "classic local script equals truth_fractions.ChallengesFor.draw" {
    var a = seeded(1);
    var b = a;
    const legacy = Classic.draw(&a);
    var felts: [classic_felts]O = undefined;
    try replay(local_classic, &b, null, &felts);
    const got = try classicFrom(&felts);
    try std.testing.expect(std.meta.eql(legacy, got));
    // The channels end in the same state (same words mixed, same draw count).
    try std.testing.expectEqualSlices(u8, &a.inner.digest, &b.inner.digest);
    try std.testing.expectEqual(a.inner.n_draws, b.inner.n_draws);
}

test "delegated local script equals truth_v3_worker.drawLocal" {
    var a = seeded(2);
    var b = a;
    a.mixU32s(&.{ 0x56334259, 1, 8 });
    const legacy = a.drawSecureFelt();
    var felts: [1]O = undefined;
    try replay(local_delegated, &b, null, &felts);
    try std.testing.expect(legacy.eql(felts[0]));
    try std.testing.expectEqualSlices(u8, &a.inner.digest, &b.inner.digest);
}

test "shared script equals manifest.drawShared" {
    var digest: [32]u8 = undefined;
    for (&digest, 0..) |*b, i| b.* = @intCast((i * 29 + 7) & 0xff);
    const legacy = CPU.rv64_gkr_manifest.drawShared(digest);
    var ch = seeded(9); // ignored: the shared script starts fresh
    var felts: [shared_felts]O = undefined;
    try replay(shared, &ch, digest, &felts);
    try std.testing.expect(std.meta.eql(legacy, try sharedFrom(&felts)));
}

test "scripts validate and stage their constants" {
    for ([_]Script{ local_classic, local_delegated, shared }) |s| {
        try validate(s);
        var buf: [32]u32 = undefined;
        try stageWords(s, &buf);
        try std.testing.expectEqualSlices(u32, s.words, buf[0..s.words.len]);
    }
    try std.testing.expectEqual(@as(usize, 19), stagedWords(shared));
    var buf: [19]u32 = undefined;
    try stageWords(shared, &buf);
    try std.testing.expectEqualSlices(u32, &freshSeed(), buf[10..19]);
    // A digest op outside a fresh script is refused (the proof channel never mixes it here).
    const bad = Script{ .words = &.{1}, .ops = &.{ .mix_digest, .{ .draw = 1 } }, .felts = 1, .fresh = false };
    try std.testing.expectError(error.InvalidTruthScript, validate(bad));
    const short = Script{ .words = &.{1}, .ops = &.{.{ .mix = .{ .first = 0, .len = 2 } }}, .felts = 0, .fresh = false };
    try std.testing.expectError(error.InvalidTruthScript, validate(short));
}

test "classic layout indices" {
    try std.testing.expectEqual(@as(?u32, 2), classicCoefficient(0, 0));
    try std.testing.expectEqual(@as(?u32, 14), classicCoefficient(1, 5));
    try std.testing.expectEqual(@as(?u32, null), classicCoefficient(2, 0));
    try std.testing.expectEqual(@as(u32, 15), classicOffset(2));
}
