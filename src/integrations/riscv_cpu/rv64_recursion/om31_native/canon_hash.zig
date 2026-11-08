//! Circuit encodings of the native chi-chain. These consume the SAME words
//! used by a leaf's verifier; they confer no authority on unbound witnesses.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const Public = @import("frame.zig");
const Canon = @import("../../word16_global_execution/ethereum/canon_native.zig");
const Types = @import("../../word16_global_execution/services/types.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const FixedSet = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig");
const Worker = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const B = circuit.builder;
pub const Word = Public.Word;
pub const Digest = Public.Digest;
pub const U64 = [2]Word;
pub const Mass = struct { ram: U64, kio: U64, wire: U64 };
pub const CpuStatement = struct {
    ordinal: Word,
    cpu_ordinal: Word,
    steps_in: U64,
    steps: Word,
    ls_count: Word,
    ls_dword: Word,
    calls: [Types.FAMILIES]Word,
    first_ids: [Types.FAMILIES]Word,
    sponge: [3]Word,
    bulk: [8]Word,
    mass: Mass,
    relations: Word,
    legacy: Digest,
};
pub const TruthStatement = struct {
    ordinal: Word,
    family: Word,
    first_id: Word,
    calls: Word,
    logs: [2]Word,
    mass: Mass,
    relations: Word,
    legacy: Digest,
};
pub const Segment = struct { k: Word, family: Word, rung: Word, vkhash: Digest, stmt: Digest, s_in: Digest, s_out: Digest, rho: Digest };
pub const CompactHeader = struct { domain: Digest, class_key: Digest, program: Digest, config_identity: Digest, fixed_identity: Digest, fixed_root: Digest };
pub const SignedMass = struct { positive: U64, negative: U64 };
pub const SignedGlobals = struct { ram: SignedMass, kio: SignedMass, wire: SignedMass };
pub const CompactCpuMetadata = struct {
    ordinal: Word,
    execution: Digest,
    mass: SignedGlobals,
    relations: Word,
    cpu_ordinal: Word,
    steps_in: U64,
    ls_count: Word,
    ls_dword: Word,
    calls: [Types.FAMILIES]Word,
    first_ids: [Types.FAMILIES]Word,
    sponge: [3]Word,
    bulk: [8]Word,
};
pub const CompactTruthMetadata = struct { ordinal: Word, execution: Digest, mass: SignedGlobals, relations: Word, family: Word, first_id: Word, calls: Word, logs: [2]Word };
/// Witness assignment only. compactCpu/Truth and all admission constraints must
/// consume these SAME handles; these constructors do not authenticate a proof.
pub fn guessCompactCpuMetadata(ctx: *C.Context, native: @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig").Metadata) !CompactCpuMetadata {
    return mirror(CompactCpuMetadata, ctx, native);
}
pub fn guessCompactTruthMetadata(ctx: *C.Context, native: @import("../../word16_global_execution/services/native_gkr/truth_statement.zig").Metadata) !CompactTruthMetadata {
    return mirror(CompactTruthMetadata, ctx, native);
}
pub fn guessCompactCpuInputs(ctx: *C.Context, native: @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig").Inputs) !@import("cpu_leaf.zig").Statement.ChainInputs {
    return mirror(@import("cpu_leaf.zig").Statement.ChainInputs, ctx, native);
}
/// Immutable class header from the RECEIVER'S source key. Never call with an
/// unchecked producer header; this embeds its fields in the circuit topology.
pub fn constantCompactHeader(ctx: *C.Context, source: @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig").Header) !CompactHeader {
    var out: CompactHeader = undefined;
    inline for (std.meta.fields(CompactHeader)) |field| @field(out, field.name) = try Public.constantDigest(ctx, @field(source, field.name));
    return out;
}
pub const Expected = struct {
    program_identity: Digest,
    admission: struct { image_identity: Digest, max_prefix_steps: U64, initial_pc: U64, initial_registers: [32]U64 },
    total_steps: U64,
    max_total_steps: U64,
    final_pc: U64,
    final_registers: [32]U64,
};
/// Witness assignment only; the typed leaf hashes these handles and the root
/// independently compares that digest with its receiver-owned expected state.
pub fn guessExpected(ctx: *C.Context, native: @import("../../word16_global_execution/services/protocol.zig").Expected) !Expected {
    return mirror(Expected, ctx, native);
}

const IdentityWriter = struct {
    ctx: *C.Context,
    channel: C.Channel,
    failure: ?anyerror = null,
    pub fn header(self: *@This(), values: []const u32) void {
        if (self.failure != null) return;
        self.channel.mixConstU32s(self.ctx, values) catch |err| {
            self.failure = err;
        };
    }
    pub fn configuration(self: *@This(), config: Worker.PcsConfig) void {
        if (self.failure != null) return;
        self.channel.mixConfig(self.ctx, config) catch |err| {
            self.failure = err;
        };
    }
    pub fn constantDigest(self: *@This(), value: Canon.Digest) void {
        if (self.failure != null) return;
        const words = Public.constantDigest(self.ctx, value) catch |err| {
            self.failure = err;
            return;
        };
        self.publicDigest(words);
    }
    pub fn publicDigest(self: *@This(), value: Digest) void {
        if (self.failure != null) return;
        self.channel.mixU32s(self.ctx, &value) catch |err| {
            self.failure = err;
        };
    }
    pub fn int64(self: *@This(), value: U64) void {
        if (self.failure != null) return;
        self.channel.mixU64(self.ctx, value[0], value[1]) catch |err| {
            self.failure = err;
        };
    }
    fn final(self: *@This()) !Digest {
        if (self.failure) |err| return err;
        try C.lane.check();
        return self.channel.raw.inner.digest.words;
    }
};
pub fn executionIdentity(ctx: *C.Context, config: Worker.PcsConfig, expected: Expected) !Digest {
    var writer = IdentityWriter{ .ctx = ctx, .channel = try C.Channel.init(ctx) };
    Execution.emitExecutionIdentity(config, expected, &writer);
    return writer.final();
}
pub fn gkrExecutionIdentity(ctx: *C.Context, config: Worker.PcsConfig, base: Digest) !Digest {
    var writer = IdentityWriter{ .ctx = ctx, .channel = try C.Channel.init(ctx) };
    try FixedSet.emitGkrExecutionIdentity(base, config, &writer);
    return writer.final();
}

/// Infallible writer signatures match Canon's native Hasher. Allocation
/// failures latch and are propagated before the hash is returned.
const Writer = struct {
    ctx: *C.Context,
    values: std.ArrayList(Word) = .empty,
    failure: ?anyerror = null,
    fn init(ctx: *C.Context, tag: Canon.Tag) Writer {
        var self = Writer{ .ctx = ctx };
        const prefix = Public.constantDigest(ctx, tag.digest()) catch |err| {
            self.failure = err;
            return self;
        };
        self.digest(prefix);
        return self;
    }
    pub fn word(self: *Writer, value: Word) void {
        if (self.failure != null) return;
        self.values.append(self.ctx.scratch(), value) catch |err| {
            self.failure = err;
        };
    }
    pub fn words(self: *Writer, values: []const Word) void {
        for (values) |value| self.word(value);
    }
    pub fn constantWord(self: *Writer, value: u32) void {
        if (self.failure != null) return;
        const converted = B.wrappers.constU32(C.Q, self.ctx, value) catch |err| {
            self.failure = err;
            return;
        };
        self.word(converted);
    }
    pub fn constantDigest(self: *Writer, value: [32]u8) void {
        if (self.failure != null) return;
        const converted = Public.constantDigest(self.ctx, value) catch |err| {
            self.failure = err;
            return;
        };
        self.digest(converted);
    }
    pub fn int64(self: *Writer, value: U64) void {
        self.words(&value);
    }
    pub fn digest(self: *Writer, value: Digest) void {
        self.words(&value);
    }
    fn final(self: *Writer) !Digest {
        if (self.failure) |err| return err;
        return (try B.blake.blake2sU32s(C.Q, self.ctx, self.values.items, 4 * self.values.items.len)).words;
    }
};
pub fn cpuStatement(ctx: *C.Context, value: CpuStatement) !Digest {
    var writer = Writer.init(ctx, .stmt);
    Canon.emitCpuStatement(try B.wrappers.constU32(C.Q, ctx, @intFromEnum(Canon.Kind.cpu)), value, &writer);
    return writer.final();
}
pub fn truthStatement(ctx: *C.Context, value: TruthStatement) !Digest {
    var writer = Writer.init(ctx, .stmt);
    Canon.emitTruthStatement(try B.wrappers.constU32(C.Q, ctx, @intFromEnum(Canon.Kind.truth)), value, &writer);
    return writer.final();
}
pub fn compactCpu(ctx: *C.Context, header: anytype, inputs: anytype, metadata: anytype) !Digest {
    const Native = @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig");
    try require(ctx, header.domain, Native.domainDigest());
    var writer = Writer.init(ctx, .stmt);
    Native.emit(header, inputs, metadata, &writer);
    return writer.final();
}
pub fn compactTruth(ctx: *C.Context, header: anytype, metadata: anytype) !Digest {
    const Native = @import("../../word16_global_execution/services/native_gkr/truth_statement.zig");
    try require(ctx, header.domain, Native.domainDigest());
    var writer = Writer.init(ctx, .stmt);
    Native.emit(header, metadata, &writer);
    return writer.final();
}
pub fn chainStep(ctx: *C.Context, previous: Digest, segment: Segment) !Digest {
    var writer = Writer.init(ctx, .seg);
    Canon.emitChainStep(previous, segment, &writer);
    return writer.final();
}
pub fn mainOnlyRho(ctx: *C.Context, main: Digest) !Digest {
    var writer = Writer.init(ctx, .rho);
    Canon.emitMainOnlyRho(main, &writer);
    return writer.final();
}
pub fn chi(ctx: *C.Context, statement: Digest, final_chain: Digest) !Digest {
    var writer = Writer.init(ctx, .chi);
    writer.digest(statement);
    writer.digest(final_chain);
    return writer.final();
}
/// State limbs are the native AIR's public u16 limbs. Explicit checks are
/// necessary: reducing an arbitrary raw u32 into M31 would allow aliases.
fn fromLimbs(ctx: *C.Context, limbs: [4]Word) !U64 {
    for (limbs) |limb| {
        // A typed u32 is (low_u16, high_u16, 0, 0). Requiring its high
        // limb to be zero makes it a u16, including in trace-only plans.
        const encoded = [1]C.Var{limb.get()};
        const lanes = B.simd.Simd.fromPacked(&encoded, 2);
        const high = try B.simd.unpackIdx(C.Q, ctx, lanes, 1);
        try ctx.eq(high, ctx.zero());
    }
    const imaginary = try ctx.constant(C.Q.fromU32Unchecked(0, 1, 0, 0));
    var result: U64 = undefined;
    for (&result, 0..) |*out, i| out.* = .newUnsafe(try ctx.add(limbs[2 * i].get(), try ctx.mul(limbs[2 * i + 1].get(), imaginary)));
    return result;
}
pub fn state(ctx: *C.Context, pc: [4]Word, registers: [32][4]Word, halted: Word) !Digest {
    try ctx.eq(try ctx.mul(halted.get(), halted.get()), halted.get());
    const pc_words = try fromLimbs(ctx, pc);
    var register_words: [32]U64 = undefined;
    for (&register_words, registers) |*out, limbs| out.* = try fromLimbs(ctx, limbs);
    var writer = Writer.init(ctx, .state);
    Canon.emitState(pc_words, register_words, halted, &writer);
    return writer.final();
}

fn guessWord(ctx: *C.Context, value: u32) !Word {
    return B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, value));
}
fn guessLimbs(ctx: *C.Context, value: u64) ![4]Word {
    var result: [4]Word = undefined;
    for (&result, 0..) |*out, i| out.* = try guessWord(ctx, @as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
    return result;
}
fn require(ctx: *C.Context, actual: Digest, expected: [32]u8) !void {
    const constants = try Public.constantDigest(ctx, expected);
    for (actual, constants) |left, right| try ctx.eq(left.get(), right.get());
}
test "fold-v3 canonical state hash binds every AIR limb and refuses u32 aliases" {
    const pc: u64 = 0xfedcba9876543210;
    var registers: [32]u64 = undefined;
    for (&registers, 0..) |*out, i| out.* = (0x123456789abcdef0 *% @as(u64, i + 1));
    for (0..3) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        var pc_limbs = try guessLimbs(&ctx, pc);
        if (mutation == 1) pc_limbs[0] = try guessWord(&ctx, @as(u32, @truncate(pc)) & 0xffff ^ 1);
        if (mutation == 2) pc_limbs[0] = try guessWord(&ctx, 65536);
        var regs: [32][4]Word = undefined;
        for (&regs, registers) |*out, value| out.* = try guessLimbs(&ctx, value);
        const output = try state(&ctx, pc_limbs, regs, try guessWord(&ctx, 1));
        try require(&ctx, output, Canon.stateDigest(pc, registers, true));
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}

fn mirror(comptime Wire: type, ctx: *C.Context, native: anytype) !Wire {
    if (Wire == Word) return guessWord(ctx, native);
    if (Wire == U64 and @typeInfo(@TypeOf(native)) == .int) {
        const value: u64 = native;
        return .{ try guessWord(ctx, @truncate(value)), try guessWord(ctx, @truncate(value >> 32)) };
    }
    if (Wire == Digest and @TypeOf(native) == Canon.Digest) {
        var out: Digest = undefined;
        for (&out, 0..) |*word, i| word.* = try guessWord(ctx, std.mem.readInt(u32, native[4 * i ..][0..4], .little));
        return out;
    }
    var out: Wire = undefined;
    switch (@typeInfo(Wire)) {
        .array => |array| for (0..array.len) |i| {
            out[i] = try mirror(array.child, ctx, native[i]);
        },
        .pointer => |pointer| {
            if (pointer.size != .slice) @compileError("canonical witness supports slices only");
            const values = try ctx.scratch().alloc(pointer.child, native.len);
            for (values, native) |*value, item| value.* = try mirror(pointer.child, ctx, item);
            out = values;
        },
        .@"struct" => |structure| inline for (structure.fields) |field| {
            @field(out, field.name) = try mirror(field.type, ctx, @field(native, field.name));
        },
        else => @compileError("unsupported canonical hash witness"),
    }
    return out;
}
test "compact native-GKR CPU and truth circuit hashes share the source visitor" {
    const CPU = @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig");
    const Truth = @import("../../word16_global_execution/services/native_gkr/truth_statement.zig");
    const Inputs = @import("cpu_leaf.zig").Statement.ChainInputs;
    const header = CPU.Header{ .domain = CPU.domainDigest(), .class_key = @splat(1), .program = @splat(2), .config_identity = @splat(3), .fixed_identity = @splat(4), .fixed_root = @splat(5) };
    var rows = [_]u32{ 0, 3 };
    var calls = [_]u32{ 0, 5 };
    var first = [_]u32{ 1, 9 };
    const input = CPU.Inputs{ .steps = 9, .epoch = 2, .initial_pc = @splat(0), .final_pc = @splat(1), .initial_registers = @splat(@splat(0)), .final_registers = @splat(@splat(1)), .register_clocks = @splat(3), .sponge_first = 1, .rows = &rows, .calls = &calls, .first_ids = &first };
    const metadata = CPU.Metadata{ .ordinal = 7, .execution = @splat(8), .mass = .{ .ram = .{ .positive = 13, .negative = 11 } }, .relations = 1, .cpu_ordinal = 2, .steps_in = 111, .ls_count = 3, .ls_dword = 5, .calls = @splat(2), .first_ids = @splat(1), .sponge = .{ 1, 3, 5 }, .bulk = @splat(7) };
    var truth_header = header;
    truth_header.domain = Truth.domainDigest();
    const truth = Truth.Metadata{ .ordinal = 8, .execution = @splat(8), .mass = .{ .wire = .{ .positive = 12, .negative = 4 } }, .relations = 4, .family = 19, .first_id = 1, .calls = 3, .logs = .{ 10, 0 } };
    for (0..3) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        var wired_cpu = try mirror(CompactCpuMetadata, &ctx, metadata);
        var wired_truth = try mirror(CompactTruthMetadata, &ctx, truth);
        if (mutation == 1) wired_cpu.calls[0] = try guessWord(&ctx, 3);
        if (mutation == 2) wired_truth.mass.wire.negative[1] = try guessWord(&ctx, 1);
        const cpu_digest = try compactCpu(&ctx, try mirror(CompactHeader, &ctx, header), try mirror(Inputs, &ctx, input), wired_cpu);
        const truth_digest = try compactTruth(&ctx, try mirror(CompactHeader, &ctx, truth_header), wired_truth);
        try require(&ctx, cpu_digest, try CPU.digest(header, input, metadata));
        try require(&ctx, truth_digest, try Truth.digest(truth_header, truth));
        try C.lane.check();
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
test "fold-v3 circuit CPU truth segment and chi hashes reproduce native authority" {
    const native = Canon.CpuStatement{
        .ordinal = 17,
        .cpu_ordinal = 4,
        .steps_in = 0x123456789abcdef0,
        .steps = 89123,
        .ls_count = 741,
        .ls_dword = 9,
        .calls = @splat(17),
        .first_ids = @splat(32),
        .sponge = .{ 13, 27, 42 },
        .bulk = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .mass = .{ .ram = 729, .kio = 831, .wire = 391 },
        .relations = 7,
        .legacy = @splat(9),
    };
    const truth = Canon.TruthStatement{ .ordinal = 23, .family = 16, .first_id = 1, .calls = 871, .logs = .{ 19, 0 }, .mass = .{ .ram = 0, .kio = 87100, .wire = 0 }, .relations = 2, .legacy = @splat(39) };
    const segment = Canon.Segment{ .k = 17, .family = 1, .rung = 3, .vkhash = @splat(7), .stmt = native.digest(), .s_in = @splat(4), .s_out = @splat(5), .rho = @splat(2) };
    const previous: Canon.Digest = @splat(71);
    for (0..2) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        const cpu_hash = try cpuStatement(&ctx, try mirror(CpuStatement, &ctx, native));
        const truth_hash = try truthStatement(&ctx, try mirror(TruthStatement, &ctx, truth));
        try require(&ctx, cpu_hash, native.digest());
        try require(&ctx, truth_hash, truth.digest());
        var wired_segment = try mirror(Segment, &ctx, segment);
        wired_segment.stmt = cpu_hash;
        if (mutation == 1) wired_segment.rho[0] = try guessWord(&ctx, 0);
        const next = try chainStep(&ctx, try mirror(Digest, &ctx, previous), wired_segment);
        try require(&ctx, next, Canon.chainStep(previous, segment));
        const actual_chi = try chi(&ctx, truth_hash, next);
        try require(&ctx, actual_chi, Canon.chi(truth.digest(), Canon.chainStep(previous, segment)));
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
test "fold-v3 semantic execution scope matches native and binds public E and GKR domain" {
    const Fixture = @import("../../word16_global_execution/services/fixture.zig");
    const expected = Fixture.expectedFor(@splat(41));
    const config = Worker.Candidate.configFor(.conjectured128_b2_q108_p20_fold4);
    const native_base = Execution.executionIdentity(config, expected);
    const native_gkr = try FixedSet.gkrExecutionIdentity(native_base, config);
    try std.testing.expect(!std.mem.eql(u8, &native_base, &native_gkr));
    for (0..2) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        var fields = try mirror(Expected, &ctx, expected);
        if (mutation == 1) fields.max_total_steps[0] = try guessWord(&ctx, 9);
        const base = try executionIdentity(&ctx, config, fields);
        const gkr = try gkrExecutionIdentity(&ctx, config, base);
        try require(&ctx, base, native_base);
        try require(&ctx, gkr, native_gkr);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
