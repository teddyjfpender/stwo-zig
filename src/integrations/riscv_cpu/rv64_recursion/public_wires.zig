//! The circuit side of the transcript walkers: layout words become
//! constants, free words become guessed wires that are mixed into the
//! channel and hashed into the leaf's output digest. Register and pc values
//! are guessed as bytes (range-checked to 8 bits) and recombined into the
//! u32 words the channel mixes, so the claim closure can read the bytes the
//! boundary tuples need. Value mode only (`Context(QM31)`); the gate list is
//! value-independent, so a topology is this build with any values.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
const A = @import("../rv64_authenticated_execution.zig");
const walk = @import("transcript_walk.zig");

const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const builder = circuit.builder;
const Context = builder.Context(Q);
const Var = builder.Var;
const U32 = builder.wrappers.U32Wrapper(Var);
const M31W = builder.wrappers.M31Wrapper(Var);
const Error = builder.context.Error;

/// A u32 word as the channel mixes it, with its 16-bit limbs.
pub const Word = struct {
    lo: Var,
    hi: Var,
    word: U32,
    /// `lo + hi · 2^16` in the field: the M31 value of a word below P.
    pub fn m31(self: Word, ctx: *Context) Error!Var {
        const shift = try ctx.constant(Q.fromBase(M31.fromCanonical(1 << 16)));
        return ctx.add(self.lo, try ctx.mul(self.hi, shift));
    }
};

/// A u64 as eight little-endian byte wires and its two channel words.
pub const U64Wires = struct {
    bytes: [8]Var,
    words: [2]Word,
};

/// Builds the circuit statement's transcript prefix through `Channel`,
/// which must expose `mixU32s([]const U32)`, `mixFelts([]const Var)`,
/// `drawSecureFelt() !Var` and `drawSecureFelts(n) ![]Var`.
pub fn CircuitSink(comptime Channel: type) type {
    return struct {
        const Self = @This();
        ctx: *Context,
        channel: *Channel,
        arena: std.mem.Allocator,
        /// Every free word in mix order: the output digest preimage.
        free: std.ArrayListUnmanaged(U32) = .empty,
        /// pc (initial, final), then 32 initial and 32 final registers.
        u64s: std.ArrayListUnmanaged(U64Wires) = .empty,
        /// before, then after RAM root (nine M31 words each).
        digests: std.ArrayListUnmanaged([9]Word) = .empty,
        clocks: std.ArrayListUnmanaged(Word) = .empty,
        /// Every drawn challenge in draw order.
        drawn: std.ArrayListUnmanaged(Var) = .empty,
        /// Every claim felt in mix order.
        claim_wires: std.ArrayListUnmanaged(Var) = .empty,
        /// Pending bytes awaiting one shared 8-bit range check.
        pending_bytes: std.ArrayListUnmanaged(M31W) = .empty,
        /// The named public scalars, by walker kind.
        roles: std.EnumArray(walk.Kind, ?Word) = .initFill(null),

        pub fn init(ctx: *Context, channel: *Channel, arena: std.mem.Allocator) Self {
            return .{ .ctx = ctx, .channel = channel, .arena = arena };
        }

        fn guessWord(self: *Self, value: u32) Error!Word {
            const lo = try self.ctx.guessU16(Q.fromU32Unchecked(value & 0xFFFF, 0, 0, 0));
            const hi = try self.ctx.guessU16(Q.fromU32Unchecked(value >> 16, 0, 0, 0));
            const i = try self.ctx.constant(Q.fromU32Unchecked(0, 1, 0, 0));
            const word = try self.ctx.add(lo, try self.ctx.mul(hi, i));
            return .{ .lo = lo, .hi = hi, .word = .newUnsafe(word) };
        }
        fn freeWord(self: *Self, value: u32) Error!Word {
            const word = try self.guessWord(value);
            try self.free.append(self.arena, word.word);
            return word;
        }

        pub fn words(self: *Self, kinds: []const walk.Kind, values: []const u32) Error!void {
            std.debug.assert(kinds.len == values.len);
            const wires = try self.arena.alloc(U32, values.len);
            for (wires, kinds, values) |*wire, kind, value| wire.* = switch (kind) {
                .layout => try builder.wrappers.constU32(Q, self.ctx, value),
                .free => (try self.freeWord(value)).word,
                else => blk: {
                    const word = try self.freeWord(value);
                    self.roles.set(kind, word);
                    break :blk word.word;
                },
            };
            try self.channel.mixU32s(wires);
        }
        pub fn u64Free(self: *Self, value: u64) Error!void {
            var bytes: [8]Var = undefined;
            for (&bytes, 0..) |*byte, i| {
                const b: u32 = @intCast((value >> @intCast(8 * i)) & 255);
                byte.* = try self.ctx.guessM31(Q.fromU32Unchecked(b, 0, 0, 0));
                try self.pending_bytes.append(self.arena, .newUnsafe(byte.*));
            }
            const c256 = try self.ctx.constant(Q.fromBase(M31.fromCanonical(256)));
            const i = try self.ctx.constant(Q.fromU32Unchecked(0, 1, 0, 0));
            var out: [2]Word = undefined;
            for (&out, 0..) |*word, w| {
                const lo = try self.ctx.add(bytes[4 * w], try self.ctx.mul(bytes[4 * w + 1], c256));
                const hi = try self.ctx.add(bytes[4 * w + 2], try self.ctx.mul(bytes[4 * w + 3], c256));
                word.* = .{ .lo = lo, .hi = hi, .word = .newUnsafe(try self.ctx.add(lo, try self.ctx.mul(hi, i))) };
                try self.free.append(self.arena, word.word);
            }
            try self.u64s.append(self.arena, .{ .bytes = bytes, .words = out });
            try self.channel.mixU32s(&.{ out[0].word, out[1].word });
        }
        pub fn digestFree(self: *Self, digest: [9]u32) Error!void {
            var out: [9]Word = undefined;
            var wires: [9]U32 = undefined;
            for (&out, &wires, digest) |*word, *wire, value| {
                word.* = try self.freeWord(value);
                wire.* = word.word;
            }
            try self.digests.append(self.arena, out);
            try self.channel.mixU32s(&wires);
        }
        pub fn clockFree(self: *Self, clock: u32) Error!void {
            const word = try self.freeWord(clock);
            try self.clocks.append(self.arena, word);
            try self.channel.mixU32s(&.{word.word});
        }
        pub fn configFelt(self: *Self) Error!void {
            const config = A.P.config();
            const felt = Q.fromU32Unchecked(config.pow_bits, config.fri_config.log_blowup_factor, @intCast(config.fri_config.n_queries), config.fri_config.log_last_layer_degree_bound);
            try self.channel.mixFelts(&.{try self.ctx.constant(felt)});
        }
        pub fn tag(self: *Self, values: []const u32) Error!void {
            const wires = try self.arena.alloc(U32, values.len);
            for (wires, values) |*wire, value| wire.* = try builder.wrappers.constU32(Q, self.ctx, value);
            try self.channel.mixU32s(wires);
        }
        pub fn draws(self: *Self, n: usize) Error!void {
            for (0..n) |_| try self.drawn.append(self.arena, try self.channel.drawSecureFelt());
        }
        pub fn drawBulk(self: *Self, n: usize) Error!void {
            try self.drawn.appendSlice(self.arena, try self.channel.drawSecureFelts(n));
        }
        pub fn claims(self: *Self, values: []const Q) Error!void {
            const wires = try self.arena.alloc(Var, values.len);
            for (wires, values) |*wire, value| wire.* = try self.ctx.guess(value);
            try self.claim_wires.appendSlice(self.arena, wires);
            try self.channel.mixFelts(wires);
        }

        /// The M31 value of a named public scalar (clocks and counts are
        /// below 2^31, so `lo + hi * 2^16` is exact).
        pub fn role(self: *const Self, kind: walk.Kind) Error!Var {
            const word = self.roles.get(kind) orelse return error.OutOfMemory;
            return word.m31(self.ctx);
        }

        /// Range-checks every guessed byte to 8 bits in packed lanes.
        pub fn rangeCheckBytes(self: *Self) Error!void {
            if (self.pending_bytes.items.len == 0) return;
            const packed_bytes = try builder.simd.pack(Q, self.ctx, self.pending_bytes.items);
            _ = try builder.extract_bits.extractBits(Q, self.ctx, packed_bytes, 8);
            self.pending_bytes.clearRetainingCapacity();
        }

        /// Blake2s of the free words: the leaf's output digest, set as the
        /// context's eight reserved outputs.
        pub fn bindOutputDigest(self: *Self) Error!builder.blake.HashValue(Var) {
            const hash = try builder.blake.blake2sU32s(Q, self.ctx, self.free.items, 4 * self.free.items.len);
            var outputs: [8]Var = undefined;
            for (&outputs, hash.words) |*out, word| out.* = word.get();
            self.ctx.setOutputs(&outputs) catch |err| switch (err) {
                error.OutputCountMismatch => unreachable,
                else => |e| return e,
            };
            return hash;
        }
    };
}

// The PCS configuration felt the native `PcsConfig.mixInto` mixes.
test "public wires: config felt matches the native mix" {
    var native = A.P.Channel{};
    A.P.config().mixInto(&native);
    var expected = A.P.Channel{};
    const config = A.P.config();
    expected.mixFelts(&.{Q.fromU32Unchecked(config.pow_bits, config.fri_config.log_blowup_factor, @intCast(config.fri_config.n_queries), config.fri_config.log_last_layer_degree_bound)});
    try std.testing.expectEqualSlices(u8, &native.digest, &expected.digest);
}
