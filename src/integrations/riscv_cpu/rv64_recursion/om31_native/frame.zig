//! Fixed-topology public words, worker framing and manifest challenge draws.
//! This helper authenticates no execution by itself: the root must admit the
//! topology and compare every public field with its independent authority.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = @import("common.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
const B = circuit.builder;
pub const Word = B.wrappers.U32Wrapper(C.Var);
pub const Digest = [8]Word;
pub const PublicU32 = struct { word: Word, base: C.F };
pub const Binding = struct { identity: [32]u8, root: [32]u8, profile: ?W.Candidate.Profile };
pub const Shared = struct {
    ram: A.memory.closed_ram.types.RamChallengesFor(C.F),
    kio: A.crypto.keccak.equations.IoFor(C.F),
    wire: A.crypto.secp256k1.equations.WireFor(C.F),
};
pub const Frame = struct {
    ctx: *C.Context,
    free_words: std.ArrayList(Word) = .empty,
    /// All allocations are context scratch-owned. No separate deinit.
    pub fn init(ctx: *C.Context) Frame {
        return .{ .ctx = ctx };
    }
    pub fn guessU32(self: *Frame, value: u32) !PublicU32 {
        const word = try B.wrappers.guessU32(C.Q, self.ctx, B.wrappers.u32Value(C.Q, value));
        try self.free_words.append(self.ctx.scratch(), word);
        // The root must bound public counts/ordinals independently. This is
        // exactly the raw-u32-to-canonical-M31 reduction used by native FS.
        return .{ .word = word, .base = C.base(try circuit.native_verifier.channel.wordToM31(C.Q, self.ctx, word)) };
    }
    pub fn guessDigest(self: *Frame, value: [32]u8) !Digest {
        var words: Digest = undefined;
        for (&words, 0..) |*word, i| {
            word.* = try B.wrappers.guessU32(C.Q, self.ctx, B.wrappers.u32Value(C.Q, std.mem.readInt(u32, value[4 * i ..][0..4], .little)));
            try self.free_words.append(self.ctx.scratch(), word.*);
        }
        return words;
    }
    pub fn guessOm(self: *Frame, value: C.O) !C.F {
        const result = try C.F.guess(self.ctx, value);
        const words = try B.blake.unpackQm31sToU32Words(C.Q, self.ctx, &.{ result.c0.v, result.c1.v });
        try self.free_words.appendSlice(self.ctx.scratch(), words);
        return result;
    }
    pub fn finish(self: *Frame) !C.Hash {
        return B.blake.blake2sU32s(C.Q, self.ctx, self.free_words.items, 4 * self.free_words.items.len);
    }
};
pub const constantDigest = digestConstants;
fn digestConstants(ctx: *C.Context, value: [32]u8) !Digest {
    var words: Digest = undefined;
    for (&words, 0..) |*word, i| word.* = try B.wrappers.constU32(C.Q, ctx, std.mem.readInt(u32, value[4 * i ..][0..4], .little));
    return words;
}
pub fn requireDigest(ctx: *C.Context, actual: C.Hash, expected: [32]u8) !void {
    const words = try constantDigest(ctx, expected);
    for (actual.words, words) |left, right| try ctx.eq(left.get(), right.get());
}
const Writer = struct {
    ctx: *C.Context,
    channel: *C.Channel,
    failure: ?anyerror = null,
    pub fn header(self: *Writer, prefix: []const u32, ordinal: Word) void {
        if (self.failure != null) return;
        const words = self.ctx.scratch().alloc(Word, prefix.len + 1) catch |err| {
            self.failure = err;
            return;
        };
        for (words[0..prefix.len], prefix) |*word, value| word.* = B.wrappers.constU32(C.Q, self.ctx, value) catch |err| {
            self.failure = err;
            return;
        };
        words[prefix.len] = ordinal;
        self.channel.mixU32s(self.ctx, words) catch |err| {
            self.failure = err;
        };
    }
    pub fn constantDigest(self: *Writer, value: [32]u8) void {
        if (self.failure != null) return;
        const words = @This().constants(self.ctx, value) catch |err| {
            self.failure = err;
            return;
        };
        self.publicDigest(words);
    }
    fn constants(ctx: *C.Context, value: [32]u8) !Digest {
        return digestConstants(ctx, value);
    }
    pub fn publicDigest(self: *Writer, value: Digest) void {
        if (self.failure != null) return;
        self.channel.mixU32s(self.ctx, &value) catch |err| {
            self.failure = err;
        };
    }
};
pub fn beginWorker(ctx: *C.Context, config: core.pcs.PcsConfig, kind: M.Kind, ordinal: Word, statement: Digest, binding: ?Binding) !C.Channel {
    var channel = try C.Channel.init(ctx);
    try channel.mixConfig(ctx, config);
    var writer = Writer{ .ctx = ctx, .channel = &channel };
    W.emitBegin(.{ .kind = kind, .ordinal = ordinal, .statement = statement }, &writer);
    if (binding) |authority| Fixed.emitBindingBegin(authority.profile, authority.identity, authority.root, &writer);
    if (writer.failure) |err| return err;
    return channel;
}
/// Generic native draw authorities retain their exact tags and order; builder
/// failures latch because their channel signatures are intentionally infallible.
pub const Draw = struct {
    ctx: *C.Context,
    channel: *C.Channel,
    failure: ?anyerror = null,
    pub fn mixU32s(self: *Draw, words: []const u32) void {
        if (self.failure != null) return;
        self.channel.mixConstU32s(self.ctx, words) catch |err| {
            self.failure = err;
        };
    }
    pub fn drawSecureFelt(self: *Draw) C.F {
        if (self.failure != null) return C.F.zero();
        return self.channel.draw(self.ctx) catch |err| {
            self.failure = err;
            return C.F.zero();
        };
    }
    pub fn finish(self: *const Draw) !void {
        if (self.failure) |err| return err;
        try C.lane.check();
    }
};
pub fn drawShared(ctx: *C.Context, manifest: Digest) !Shared {
    var channel = try C.Channel.init(ctx);
    try channel.mixConstU32s(ctx, &.{ 0x53474d31, 1, 8 });
    try channel.mixU32s(ctx, &manifest);
    var draw = Draw{ .ctx = ctx, .channel = &channel };
    draw.mixU32s(&.{ 0x52414d31, 14 });
    var ram: @FieldType(Shared, "ram") = undefined;
    ram.offset = draw.drawSecureFelt();
    for (&ram.coefficients) |*coefficient| coefficient.* = draw.drawSecureFelt();
    draw.mixU32s(&.{ 0x4b494f31, 11 });
    const kio = @FieldType(Shared, "kio").draw(&draw);
    draw.mixU32s(&.{ 0x53574952, 35 });
    const wire = @FieldType(Shared, "wire").draw(&draw);
    try draw.finish();
    return .{ .ram = ram, .kio = kio, .wire = wire };
}
