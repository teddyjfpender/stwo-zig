//! INACTIVE two-phase RAM protocol prototype. Typed roots are actual PCS roots.
//! Coverage descriptors are receiver expectations, never proof of CPU execution.
//! Full execution activation is deliberately rejected until joined-chip gates.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const P = A.protocol;
pub const Q = core.fields.qm31.QM31;
pub const Scheme = engine.pcs.CommitmentSchemeProver(@import("stwo_cpu_backend").CpuBackend, P.Hasher, P.MerkleChannel);
pub const Digest = [32]u8;
pub const Stage1Root = struct { bytes: [32]u8 };
pub const Scope = enum(u32) { boundary_diagnostic = 1, full_execution_unqualified = 2 };
pub const Role = enum(u32) { initial = 1, terminal = 2, execution = 3 };
pub const Context = struct { scope: Scope = .boundary_diagnostic, execution: Digest, program: Digest, image: Digest, policy: Digest, opcode_map: Digest, total_steps: u64 };
pub const Coverage = struct { first_step: u64, steps: u32, epoch: u16, initial_pc: u64, final_pc: u64, initial_registers: Digest, final_registers: Digest };
pub const Spec = struct { ordinal: u32, role: Role, coverage: Coverage, schema: Digest, statement: Digest, fixed: Stage1Root, fixed_logs: []const u32, main_logs: []const u32, positive_mass: [3]u64 };
pub const Receipt = struct { ordinal: u32, spec_digest: Digest, fixed: Stage1Root, main: Stage1Root };
pub const Expected = struct { context: Context, specs: []const Spec };
pub const Shared = struct { ram: A.memory.closed_ram.types.RamChallenges, owner: A.memory.load_store_v2.types.OwnerChallenges, function: A.word16_v1.function_bus.Challenges };
const CoreProtocol = @import("../protocol.zig");
pub const PhysicalClaims = [CoreProtocol.CLAIM_COUNT]Q;
const MAX_WORKERS = 4096;
const MAX_COLUMNS = 65536;

pub fn mixDigest(ch: *P.Channel, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
fn mixContext(ch: *P.Channel, ctx: Context) void {
    ch.mixU32s(&.{ 0x474d5631, 1, @intFromEnum(ctx.scope), 14, 19, 13, CoreProtocol.CLAIM_COUNT });
    P.config().mixInto(ch);
    for ([_]Digest{ ctx.execution, ctx.program, ctx.image, ctx.policy, ctx.opcode_map }) |d| mixDigest(ch, d);
    ch.mixU64(ctx.total_steps);
}
fn mixSpec(ch: *P.Channel, spec: Spec) void {
    ch.mixU32s(&.{ spec.ordinal, @intFromEnum(spec.role), spec.coverage.steps, spec.coverage.epoch });
    ch.mixU64(spec.coverage.first_step);
    ch.mixU64(spec.coverage.initial_pc);
    ch.mixU64(spec.coverage.final_pc);
    for ([_]Digest{ spec.schema, spec.statement, spec.fixed.bytes, spec.coverage.initial_registers, spec.coverage.final_registers }) |d| mixDigest(ch, d);
    ch.mixU64(spec.fixed_logs.len);
    ch.mixU32s(spec.fixed_logs);
    ch.mixU64(spec.main_logs.len);
    ch.mixU32s(spec.main_logs);
    for (spec.positive_mass) |mass| ch.mixU64(mass);
}
pub fn specDigest(spec: Spec) Digest {
    var ch = P.Channel{};
    ch.mixU32s(&.{ 0x474d5350, 1 });
    mixSpec(&ch, spec);
    return ch.digestBytes();
}
/// All geometry/mass/coverage admission happens before allocation and draws.
pub fn validateExpected(expected: Expected) !void {
    if (expected.context.scope != .boundary_diagnostic) return error.UnqualifiedGlobalExecution;
    if (expected.specs.len != 2 or expected.specs.len > MAX_WORKERS or expected.specs[0].role != .initial or expected.specs[1].role != .terminal) return error.InvalidGlobalRoster;
    var masses: [3]u64 = @splat(0);
    var end: u64 = 0;
    for (expected.specs, 0..) |s, index| {
        if (s.ordinal != index or s.coverage.epoch != index + 1 or s.coverage.first_step != end) return error.InvalidGlobalCoverage;
        end = std.math.add(u64, end, s.coverage.steps) catch return error.InvalidGlobalCoverage;
        if (s.fixed_logs.len == 0 or s.main_logs.len == 0 or s.fixed_logs.len > MAX_COLUMNS or s.main_logs.len > MAX_COLUMNS) return error.InvalidGlobalGeometry;
        for (s.fixed_logs) |log| if (log < 5 or log > 22) return error.InvalidGlobalGeometry;
        for (s.main_logs) |log| if (log < 5 or log > 22) return error.InvalidGlobalGeometry;
        for (&masses, s.positive_mass) |*sum, mass| {
            sum.* = std.math.add(u64, sum.*, mass) catch return error.GlobalCharacteristicBound;
            if (sum.* >= core.fields.m31.Modulus) return error.GlobalCharacteristicBound;
        }
        if (index != 0) {
            const prev = expected.specs[index - 1];
            if (prev.coverage.final_pc != s.coverage.initial_pc or !std.mem.eql(u8, &prev.coverage.final_registers, &s.coverage.initial_registers)) return error.InvalidGlobalAdjacency;
        }
    }
    if (end != expected.context.total_steps) return error.InvalidGlobalCoverage;
}
pub fn beginStage1(ctx: Context, spec: Spec, ch: *P.Channel) void {
    mixContext(ch, ctx);
    mixSpec(ch, spec);
}
pub fn fromCommitted(a: std.mem.Allocator, scheme: *Scheme, spec: Spec) !Receipt {
    if (!std.meta.eql(scheme.config, P.config()) or scheme.revision_config != null) return error.GlobalSuiteMismatch;
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2) return error.InvalidGlobalStage1;
    for ([_][]const u32{ spec.fixed_logs, spec.main_logs }, 0..) |logs, tree| {
        if (scheme.trees.items[tree].columns.len != logs.len) return error.GlobalGeometryMismatch;
        for (scheme.trees.items[tree].columns, logs) |column, log| if (column.log_size != log + P.config().fri_config.log_blowup_factor) return error.GlobalGeometryMismatch;
    }
    if (!std.mem.eql(u8, &roots.items[0], &spec.fixed.bytes)) return error.GlobalFixedMismatch;
    return .{ .ordinal = spec.ordinal, .spec_digest = specDigest(spec), .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
}
pub const Manifest = struct {
    allocator: std.mem.Allocator,
    context: Context,
    specs: []Spec,
    receipts: []Receipt,
    digest: Digest,
    pub fn init(a: std.mem.Allocator, expected: Expected, receipts: []const Receipt) !Manifest {
        try validateExpected(expected);
        try validateReceipts(expected.specs, receipts);
        const specs = try a.alloc(Spec, expected.specs.len);
        errdefer a.free(specs);
        var initialized: usize = 0;
        errdefer for (specs[0..initialized]) |s| {
            a.free(s.fixed_logs);
            a.free(s.main_logs);
        };
        for (specs, expected.specs) |*dest, src| {
            const fixed = try a.dupe(u32, src.fixed_logs);
            errdefer a.free(fixed);
            const main = try a.dupe(u32, src.main_logs);
            dest.* = src;
            dest.fixed_logs = fixed;
            dest.main_logs = main;
            initialized += 1;
        }
        const copies = try a.dupe(Receipt, receipts);
        return .{ .allocator = a, .context = expected.context, .specs = specs, .receipts = copies, .digest = seal(expected, receipts) };
    }
    pub fn deinit(self: *Manifest) void {
        for (self.specs) |s| {
            self.allocator.free(s.fixed_logs);
            self.allocator.free(s.main_logs);
        }
        self.allocator.free(self.specs);
        self.allocator.free(self.receipts);
        self.* = undefined;
    }
    pub fn check(self: *const Manifest, expected: Expected) !void {
        try validateExpected(expected);
        if (!std.meta.eql(self.context, expected.context) or self.specs.len != expected.specs.len) return error.GlobalExpectedMismatch;
        for (self.specs, expected.specs) |actual, wanted| if (!std.mem.eql(u8, &specDigest(actual), &specDigest(wanted))) return error.GlobalExpectedMismatch;
        try self.unchanged();
    }
    pub fn unchanged(self: *const Manifest) !void {
        const expected = Expected{ .context = self.context, .specs = self.specs };
        try validateExpected(expected);
        try validateReceipts(self.specs, self.receipts);
        if (!std.mem.eql(u8, &self.digest, &seal(expected, self.receipts))) return error.GlobalManifestChanged;
    }
    pub fn derive(self: *const Manifest) !Shared {
        try self.unchanged();
        var ch = P.Channel{};
        ch.mixU32s(&.{ 0x474d414c, 1 });
        mixDigest(&ch, self.digest);
        return .{ .ram = draw(A.memory.closed_ram.types.RamChallenges, &ch, 14), .owner = draw(A.memory.load_store_v2.types.OwnerChallenges, &ch, 19), .function = draw(A.word16_v1.function_bus.Challenges, &ch, 13) };
    }
    fn resumeStage2(self: *const Manifest, ordinal: usize, ch: *P.Channel) !Shared {
        try self.unchanged();
        if (ordinal >= self.specs.len) return error.InvalidGlobalRoster;
        var expected = P.Channel{};
        beginStage1(self.context, self.specs[ordinal], &expected);
        P.MerkleChannel.mixRoot(&expected, self.receipts[ordinal].fixed.bytes);
        P.MerkleChannel.mixRoot(&expected, self.receipts[ordinal].main.bytes);
        if (ch.n_draws != 0 or !std.mem.eql(u8, &ch.digestBytes(), &expected.digestBytes())) return error.GlobalStage1TranscriptMismatch;
        ch.mixU32s(&.{ 0x474d5332, 1, @intCast(ordinal) });
        mixDigest(ch, self.digest);
        return self.derive();
    }
    pub fn resumeWorker(self: *const Manifest, a: std.mem.Allocator, ordinal: usize, scheme: *Scheme, ch: *P.Channel) !Shared {
        if (ordinal >= self.specs.len) return error.InvalidGlobalRoster;
        const actual = try fromCommitted(a, scheme, self.specs[ordinal]);
        if (!std.meta.eql(actual, self.receipts[ordinal])) return error.GlobalStage1RootMismatch;
        return self.resumeStage2(ordinal, ch);
    }
    pub fn resumeReceiver(self: *const Manifest, ordinal: usize, proof: *const P.Proof, ch: *P.Channel) !Shared {
        try self.unchanged();
        if (ordinal >= self.specs.len) return error.InvalidGlobalRoster;
        const pcs = &proof.commitment_scheme_proof;
        if (!std.meta.eql(pcs.config, P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.GlobalSuiteMismatch;
        if (!std.mem.eql(u8, &pcs.commitments.items[0], &self.receipts[ordinal].fixed.bytes) or !std.mem.eql(u8, &pcs.commitments.items[1], &self.receipts[ordinal].main.bytes)) return error.GlobalStage1RootMismatch;
        return self.resumeStage2(ordinal, ch);
    }
};
fn draw(comptime R: type, ch: *P.Channel, tag: u32) R {
    ch.mixU32s(&.{ 0x474d524c, tag });
    var r: R = undefined;
    r.offset = ch.drawSecureFelt();
    for (&r.coefficients) |*v| v.* = ch.drawSecureFelt();
    return r;
}
fn validateReceipts(specs: []const Spec, receipts: []const Receipt) !void {
    if (specs.len != receipts.len) return error.IncompleteGlobalManifest;
    for (specs, receipts) |s, r| if (r.ordinal != s.ordinal or !std.mem.eql(u8, &r.spec_digest, &specDigest(s)) or !std.mem.eql(u8, &r.fixed.bytes, &s.fixed.bytes)) return error.GlobalInventoryMismatch;
}
fn seal(expected: Expected, receipts: []const Receipt) Digest {
    var ch = P.Channel{};
    mixContext(&ch, expected.context);
    ch.mixU64(expected.specs.len);
    for (expected.specs, receipts) |s, r| {
        mixSpec(&ch, s);
        mixDigest(&ch, r.main.bytes);
    }
    return ch.digestBytes();
}
pub fn validateClaims(claims: PhysicalClaims) !void {
    // Diagnostic scope has no physical tail LS component.
    for (claims[CoreProtocol.CLAIM_LS_TAIL..]) |q| if (!q.isZero()) return error.NonzeroOmittedGlobalClaim;
    for (claims) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalGlobalClaim;
    for ([_]usize{ 23, 26, 28, 31 }) |i| if (!claims[i].isZero()) return error.NonzeroOmittedGlobalClaim;
}
pub fn mixClaims(ch: *P.Channel, claims: PhysicalClaims) !void {
    try validateClaims(claims);
    ch.mixU32s(&.{ 0x474d434c, 1, CoreProtocol.CLAIM_COUNT });
    ch.mixFelts(&claims);
}
/// Must be called ONLY after EVERY physical verifier has succeeded. This sum
/// cannot authenticate roots, coverage, boundary values or any proof by itself.
pub fn closeVerified(claims: []const PhysicalClaims) !void {
    var total = Q.zero();
    for (claims) |worker| {
        try validateClaims(worker);
        for (worker) |q| total = total.add(q);
    }
    if (!total.isZero()) return error.UnclosedGlobalPhysicalClaims;
}
