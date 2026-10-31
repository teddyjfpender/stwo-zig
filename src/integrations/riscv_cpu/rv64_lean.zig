//! Separately versioned one-PCS CPU+ROM+range+DIV service coordinator.
//! Legacy full statements/claims/transcripts retain their original meaning.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const Full = @import("rv64_full.zig");
const S = Full.Support;
const B = S.Backend;
const P = rv.protocol;
const D = rv.arithmetic.division;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const Public = struct {
    statement: Full.Statement,
    division_requests: u32,
    pub fn validate(self: Public) !void {
        try self.statement.validate();
        const admitted = try rv.program.opcode_policy.derive(self.statement.program, .rv64im);
        if (!std.mem.eql(bool, &admitted, &self.statement.opcodes)) return error.InvalidRv64LeanOpcodePolicy;
        if (self.division_requests > self.statement.steps) return error.InvalidRv64LeanPublic;
        if (try self.byteQueryBudget() >= core.fields.m31.Modulus) return error.InvalidRv64LeanLookupBudget;
    }
    /// Counts padding requests too. This profile has only the CPU as a byte
    /// consumer; the DIV service uses Boolean reconstruction, not this bus.
    pub fn byteQueryBudget(self: Public) !u64 {
        if (self.statement.steps == 0 or self.statement.steps >= 1 << 22) return error.InvalidRv64LeanPublic;
        var opcodes: [65]rv.evaluation.O = undefined;
        var count: usize = 0;
        for (self.statement.opcodes, 0..) |enabled, op| if (enabled) {
            opcodes[count] = @enumFromInt(op);
            count += 1;
        };
        const plan = rv.encoding.Plan.fromOpcodesWithPolicy(opcodes[0..count], .division_service_v2);
        return (@as(u64, 1) << @intCast(self.statement.logSize())) * @as(u64, plan.range_count);
    }
};
pub const Claims = struct { cpu: Full.Claims, division: Q };
pub const Bundle = struct {
    claims: Claims,
    proof: P.Proof,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};
pub const PreparedSetup = struct {
    base: Full.PreparedMaterials,
    division_log: u32,
    division_fixed: []M,
    root: [32]u8,
    pub fn init(a: std.mem.Allocator, public: Public) !PreparedSetup {
        try public.validate();
        var base = try Full.PreparedMaterials.initWithPolicy(a, public.statement, .division_service_v2);
        errdefer base.deinit();
        const log = @max(5, std.math.log2_int_ceil(u32, @max(1, public.division_requests)));
        const fixed = try D.trace.fixedColumns(a, public.division_requests, log);
        errdefer a.free(fixed);
        var result = PreparedSetup{ .base = base, .division_log = log, .division_fixed = fixed, .root = undefined };
        const columns = try result.fixedColumns(a);
        defer a.free(columns);
        var scheme = try Scheme.init(a, P.config());
        defer scheme.deinit(a);
        var channel = P.Channel{};
        try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        result.root = roots.items[0];
        return result;
    }
    pub fn deinit(self: *PreparedSetup) void {
        self.base.allocator.free(self.division_fixed);
        self.base.deinit();
        self.* = undefined;
    }
    /// Cache hint only, never producer authority. Immutable program/profile,
    /// admitted opcode policy and geometry enter; exact counts/state/path do not.
    pub fn cacheIdentity(self: *const PreparedSetup) [32]u8 {
        const H = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
        var hash = H.init(.{});
        hash.update("stwo-zig/rv64/lean-setup/v2\x00");
        hash.update(&self.base.program.identity);
        hash.update(&self.root);
        for ([_]u32{ self.base.log_size, self.division_log, @intFromEnum(self.base.plan.arithmetic_policy) }) |value| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, value, .little);
            hash.update(&bytes);
        }
        var opcodes: [65]u8 = undefined;
        for (self.base.plan.allowed_opcodes, &opcodes) |allowed, *byte| byte.* = @intFromBool(allowed);
        hash.update(&opcodes);
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
    fn validate(self: *const PreparedSetup, public: Public) !void {
        try public.validate();
        try S.validateSetup(&self.base, public.statement);
        if (self.base.plan.state_policy != .inverse_v1 or self.base.plan.execution_profile != .rv64im or self.base.plan.arithmetic_policy != .division_service_v2 or self.division_log != @max(5, std.math.log2_int_ceil(u32, @max(1, public.division_requests)))) return error.InvalidRv64LeanSetup;
    }
    fn fixedColumns(self: *const PreparedSetup, a: std.mem.Allocator) ![]Column {
        const base = try self.base.fixedColumns(a);
        defer a.free(base);
        const columns = try a.alloc(Column, base.len + D.layout.FIXED);
        @memcpy(columns[0..base.len], base);
        S.append(columns[base.len..], self.division_fixed, self.division_log);
        return columns;
    }
    pub fn verifyOwned(self: *const PreparedSetup, a: std.mem.Allocator, public: Public, claims: Claims, proof_value: P.Proof) !void {
        var proof = proof_value;
        var owns = true;
        defer if (owns) proof.deinit(a);
        try self.validate(public);
        if (!std.meta.eql(proof.commitment_scheme_proof.config, P.config()) or proof.commitment_scheme_proof.revision_config != null) return error.InvalidRv64LeanConfig;
        const roots = proof.commitment_scheme_proof.commitments.items;
        if (roots.len != 4 or !std.mem.eql(u8, &roots[0], &self.root)) return error.Rv64LeanFixedRootMismatch;
        var verifier = try Verifier.init(a, P.config());
        defer verifier.deinit(a);
        var channel = P.Channel{};
        try mixPublic(&channel, self, public);
        const fixed = try self.fixedColumns(a);
        defer a.free(fixed);
        const fixed_logs = try a.alloc(u32, fixed.len);
        defer a.free(fixed_logs);
        for (fixed, fixed_logs) |column, *log| log.* = column.log_size;
        const main_count = self.base.plan.main_count + rv.full.frame.WIDTH;
        const providers = self.base.providerCount();
        const main_logs = try a.alloc(u32, main_count + providers + D.layout.MAIN);
        defer a.free(main_logs);
        @memset(main_logs[0..main_count], self.base.log_size);
        fillProviderLogs(main_logs[main_count..][0..providers], &self.base);
        @memset(main_logs[main_count + providers ..], self.division_log);
        try verifier.commit(a, roots[0], fixed_logs, &channel);
        try verifier.commit(a, roots[1], main_logs, &channel);
        const base_challenges = S.challenges(&channel, &self.base);
        const challenges = D.provider.Challenges.draw(&channel);
        try S.validate(public.statement, &self.base, claims.cpu, base_challenges);
        try validateDivisionClaim(claims.division);
        var components = try S.SharedComponents.initWithDivision(&self.base, public.statement, base_challenges, claims.cpu, .{ .challenges = challenges, .claim = claims.division });
        const division = self.component(&components, public, challenges, claims.division.neg());
        const inter_logs = try a.alloc(u32, components.cpu.interactionCount() + providers * 8 + 8);
        defer a.free(inter_logs);
        @memset(inter_logs[0..components.cpu.interactionCount()], self.base.log_size);
        var cursor = components.cpu.interactionCount();
        for (main_logs[main_count..][0..providers]) |log| {
            @memset(inter_logs[cursor..][0..8], log);
            cursor += 8;
        }
        @memset(inter_logs[cursor..], self.division_log);
        mixClaims(&channel, claims);
        try verifier.commit(a, roots[2], inter_logs, &channel);
        var handles: [6]core.air.components.Component = undefined;
        const count = components.verifierHandles(handles[0..5]);
        handles[count] = division.asVerifierComponent();
        owns = false;
        try core.verifier.verify(P.Hasher, P.MerkleChannel, a, handles[0 .. count + 1], &channel, &verifier, proof);
    }
    fn component(self: *const PreparedSetup, base: *const S.SharedComponents, public: Public, challenges: D.provider.Challenges, claim: Q) D.component.Component {
        return .{ .log_size = self.division_log, .count = public.division_requests, .fixed_offset = self.base.fixedCount(), .main_offset = base.cpu.mainCount() + self.base.providerCount(), .interaction_offset = base.cpu.interactionCount() + self.base.providerCount() * 8, .challenges = challenges, .claim = claim };
    }
};
pub const Trace = struct {
    cpu: Full.Trace,
    division: D.trace.Trace,
    indexed: []D.cpu_bus.IndexedRequest,
    pub fn init(a: std.mem.Allocator, records: []const @import("stwo_riscv_frontend").rv64.machine.Retirement, public: Public, setup: *const PreparedSetup) !Trace {
        try setup.validate(public);
        var cpu = try Full.Trace.init(a, records, public.statement, &setup.base.program, &setup.base.plan);
        errdefer cpu.deinit();
        const indexed = try cpu.divisionRequests(a);
        errdefer a.free(indexed);
        if (indexed.len != public.division_requests) return error.InvalidRv64LeanRequestCount;
        const plain = try a.alloc(D.trace.Request, indexed.len);
        defer a.free(plain);
        for (indexed, plain) |request, *output| output.* = request.request;
        const division = try D.trace.Trace.init(a, plain);
        return .{ .cpu = cpu, .division = division, .indexed = indexed };
    }
    pub fn takeMainForCommit(self: *Trace, a: std.mem.Allocator, providers: []const Column) !@import("rv64_full_trace.zig").MainCommit {
        try self.cpu.validateCommitAllocator(a);
        if (!rv.memory.ownership.same(self.division.allocator, a)) return error.Rv64FullCommitAllocatorMismatch;
        return takeMain(a, self, providers);
    }
    pub fn deinit(self: *Trace) void {
        self.cpu.allocator.free(self.indexed);
        self.division.deinit();
        self.cpu.deinit();
        self.* = undefined;
    }
};
pub fn proveTrace(a: std.mem.Allocator, setup: *const PreparedSetup, public: Public, trace: *Trace) !Bundle {
    try setup.validate(public);
    try trace.cpu.validateCommitAllocator(a);
    if (!rv.memory.ownership.same(trace.division.allocator, a)) return error.Rv64FullCommitAllocatorMismatch;
    if (trace.division.count != public.division_requests or trace.cpu.plan.arithmetic_policy != .division_service_v2) return error.InvalidRv64LeanTrace;
    var channel = P.Channel{};
    try mixPublic(&channel, setup, public);
    var scheme = try Scheme.init(a, P.config());
    scheme.setCompactPolynomialStorage(5);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
    var rom = try S.rom(a, &setup.base.program, trace.cpu.rom_counts);
    defer rom.deinit();
    var bytes = try rv.range.provider.Trace.init(a, &trace.cpu.byte_counts);
    defer bytes.deinit();
    var bitwise: ?rv.providers.tables.Request = if (setup.base.and_table) |*table| try rv.providers.tables.Request.init(a, table, trace.cpu.and_counts) else null;
    defer if (bitwise) |*request| request.deinit();
    var shifts: ?rv.providers.tables.Request = if (setup.base.shift_table) |*table| try rv.providers.tables.Request.init(a, table, trace.cpu.shift_counts) else null;
    defer if (shifts) |*request| request.deinit();
    var providers: [4]Column = undefined;
    S.append(providers[0..1], rom.multiplicities, setup.base.program.log_size);
    S.append(providers[1..2], bytes.main, 8);
    var n_providers: usize = 2;
    if (bitwise) |request| {
        S.append(providers[n_providers..][0..1], request.main, 16);
        n_providers += 1;
    }
    if (shifts) |request| {
        S.append(providers[n_providers..][0..1], request.main, 11);
        n_providers += 1;
    }
    var main = try trace.takeMainForCommit(a, providers[0..n_providers]);
    var owns_main = true;
    defer if (owns_main) main.deinit(a);
    owns_main = false; // PCS consumes complete source ownership on every path.
    try scheme.commitOwnedWithRecorderAndBacking(a, main.columns, main.backing, null, &channel);
    const base_challenges = S.challenges(&channel, &setup.base);
    const challenges = D.provider.Challenges.draw(&channel);
    const base_claims = try trace.cpu.generateInteraction(base_challenges);
    var bus = try D.cpu_bus.build(a, public.statement.steps, setup.base.log_size, trace.indexed, challenges);
    defer bus.deinit();
    const negative = try trace.division.generateInteraction(challenges);
    if (!bus.claim.add(negative).isZero()) return error.Rv64LeanDivisionClosure;
    const claims = Claims{ .cpu = base_claims, .division = bus.claim };
    try S.validate(public.statement, &setup.base, claims.cpu, base_challenges);
    if (!(try rom.generateInteraction(&setup.base.program, base_challenges.rom)).add(claims.cpu.rom).isZero()) return error.Rv64FullRomClosure;
    if (!(try bytes.generateInteraction(base_challenges.bytes)).add(claims.cpu.bytes).isZero()) return error.Rv64FullByteClosure;
    if (bitwise) |*request| if (!(try request.generateInteraction(base_challenges.bitwise)).add(claims.cpu.bitwise).isZero()) return error.Rv64FullAndClosure;
    if (shifts) |*request| if (!(try request.generateInteraction(base_challenges.shifts)).add(claims.cpu.shifts).isZero()) return error.Rv64FullShiftClosure;
    var components = try S.SharedComponents.initWithDivision(&setup.base, public.statement, base_challenges, claims.cpu, .{ .challenges = challenges, .claim = claims.division });
    const division = setup.component(&components, public, challenges, negative);
    const columns = try a.alloc(Column, components.cpu.interactionCount() + n_providers * 8 + 8);
    defer a.free(columns);
    var cursor = trace.cpu.interactionCount();
    S.append(columns[0..cursor], trace.cpu.interaction, setup.base.log_size);
    S.append(columns[cursor..][0..8], bus.storage, setup.base.log_size);
    cursor += 8;
    S.append(columns[cursor..][0..8], rom.interaction, setup.base.program.log_size);
    cursor += 8;
    S.append(columns[cursor..][0..8], bytes.interaction, 8);
    cursor += 8;
    if (bitwise) |request| {
        S.append(columns[cursor..][0..8], request.interaction, 16);
        cursor += 8;
    }
    if (shifts) |request| {
        S.append(columns[cursor..][0..8], request.interaction, 11);
        cursor += 8;
    }
    S.append(columns[cursor..][0..8], trace.division.interaction, setup.division_log);
    mixClaims(&channel, claims);
    try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    trace.cpu.allocator.free(trace.cpu.interaction);
    trace.cpu.interaction = &.{};
    var handles: [6]engine.air.component_prover.ComponentProver = undefined;
    const count = components.proverHandles(handles[0..5]);
    handles[count] = division.asProverComponent();
    owns_scheme = false;
    const proof = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, handles[0 .. count + 1], &channel, scheme);
    return .{ .claims = claims, .proof = proof };
}
fn takeMain(a: std.mem.Allocator, trace: *Trace, providers: []const Column) !@import("rv64_full_trace.zig").MainCommit {
    var base = try trace.cpu.takeMainForCommit(a, providers);
    var owns = true;
    defer if (owns) base.deinit(a);
    const columns = try a.alloc(Column, base.columns.len + D.layout.MAIN);
    errdefer a.free(columns);
    const backing = try a.alloc([]M, 2);
    @memcpy(columns[0..base.columns.len], base.columns);
    S.append(columns[base.columns.len..], trace.division.main, trace.division.log_size);
    backing[0] = base.backing[0];
    backing[1] = trace.division.main;
    a.free(base.columns);
    a.free(base.backing);
    trace.division.main = &.{};
    owns = false;
    return .{ .columns = columns, .backing = backing };
}
fn fillProviderLogs(logs: []u32, base: *const Full.PreparedMaterials) void {
    logs[0] = base.program.log_size;
    logs[1] = 8;
    var cursor: usize = 2;
    if (base.and_table != null) {
        logs[cursor] = 16;
        cursor += 1;
    }
    if (base.shift_table != null) logs[cursor] = 11;
}
fn mixPublic(channel: *P.Channel, setup: *const PreparedSetup, public: Public) !void {
    channel.mixU32s(&.{ 0x52564c4e, 2, @intFromEnum(D.policy.Policy.division_service_v2), public.division_requests, setup.division_log });
    try public.statement.mix(channel, setup.base.program.identity);
}
fn validateDivisionClaim(claim: Q) !void {
    for (claim.toM31Array()) |part| if (part.v >= core.fields.m31.Modulus) return error.InvalidRv64LeanClaim;
}
fn mixClaims(channel: *P.Channel, claims: Claims) void {
    S.mix(channel, claims.cpu);
    channel.mixU32s(&.{ 0x44495643, 1 });
    channel.mixFelts(&.{claims.division});
}
