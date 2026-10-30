//! One full execution, one shared commitment/composition/FRI transaction.
//! Immutable setup comes from the receiver's program, opcode policy and domain.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
// Existing CPU ownership/preparation policy admits one backing arena uniformly
// for all column counts; frontend code never selects backend size thresholds.
const B = @import("stwo_cpu_backend").configured(.{ .wide_preparation = true, .source_trace_arena = true });
const P = rv.protocol;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const stage = @import("stwo_prover_api").stage_profile;
const Cpu = rv.full.component;
const Tables = rv.providers.tables;
const Rom = rv.program;
const Bytes = rv.range;
const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const Statement = @import("rv64_full_statement.zig").Statement;
pub const Trace = @import("rv64_full_trace.zig").Trace;
pub const Capture = @import("rv64_full_capture.zig").Capture;
pub const Claims = Cpu.Claims;
pub const Proof = P.Proof;
pub const Bundle = struct {
    claims: Claims,
    proof: Proof,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};
pub fn planForStatement(public: Statement) !rv.encoding.Plan {
    try public.validate();
    var opcodes: [65]rv.evaluation.O = undefined;
    var count: usize = 0;
    for (public.opcodes, 0..) |enabled, opcode| if (enabled) {
        opcodes[count] = @enumFromInt(opcode);
        count += 1;
    };
    return rv.encoding.Plan.fromOpcodes(opcodes[0..count]);
}
pub const PreparedSetup = struct {
    allocator: std.mem.Allocator,
    program: Rom.setup.Setup,
    plan: rv.encoding.Plan,
    log_size: u32,
    cpu_fixed: []M,
    rom_fixed: []M,
    byte_table: Bytes.provider.Trace,
    and_table: ?Tables.Setup,
    shift_table: ?Tables.Setup,
    root: [32]u8,
    pub fn init(a: std.mem.Allocator, public: Statement) !PreparedSetup {
        const plan = try planForStatement(public);
        var program = try Rom.setup.Setup.init(a, public.program);
        errdefer program.deinit();
        const cpu_fixed = try rv.full.frame.fixedColumns(a, public.logSize());
        errdefer a.free(cpu_fixed);
        const rom_fixed = try program.compactFixedColumns(a);
        errdefer a.free(rom_fixed);
        const zero_counts: [256]u64 = @splat(0);
        var byte_table = try Bytes.provider.Trace.init(a, &zero_counts);
        errdefer byte_table.deinit();
        var and_table: ?Tables.Setup = if (Bytes.table_cpu.requests(&plan, .byte_and) > 0) try Tables.Setup.init(a, .byte_and) else null;
        errdefer if (and_table) |*table| table.deinit();
        var shift_table: ?Tables.Setup = if (Bytes.table_cpu.requests(&plan, .byte_shift) > 0) try Tables.Setup.init(a, .byte_shift) else null;
        errdefer if (shift_table) |*table| table.deinit();
        var setup = PreparedSetup{ .allocator = a, .program = program, .plan = plan, .log_size = public.logSize(), .cpu_fixed = cpu_fixed, .rom_fixed = rom_fixed, .byte_table = byte_table, .and_table = and_table, .shift_table = shift_table, .root = undefined };
        const fixed = try setup.fixedColumns(a);
        defer a.free(fixed);
        var scheme = try Scheme.init(a, P.config());
        defer scheme.deinit(a);
        var channel = P.Channel{};
        try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        setup.root = roots.items[0];
        return setup;
    }
    pub fn deinit(self: *PreparedSetup) void {
        self.program.deinit();
        self.allocator.free(self.cpu_fixed);
        self.allocator.free(self.rom_fixed);
        self.byte_table.deinit();
        if (self.and_table) |*table| table.deinit();
        if (self.shift_table) |*table| table.deinit();
        self.* = undefined;
    }
    fn validate(self: *const PreparedSetup, public: Statement) !void {
        try public.validate();
        if (public.logSize() != self.log_size or !std.mem.eql(bool, &public.opcodes, &self.plan.allowed_opcodes) or public.program.words.len != self.program.rows.len) return error.Rv64FullSetupMismatch;
        for (public.program.words, 0..) |word, i| {
            if (public.program.pc(i) != self.program.addresses[i]) return error.Rv64FullSetupMismatch;
            const row = self.program.rows[i];
            for (0..4) |b| if (row[Rom.setup.field.raw + b].v != ((word >> @as(u5, @intCast(b * 8))) & 255)) return error.Rv64FullSetupMismatch;
        }
    }
    pub fn fixedCount(self: *const PreparedSetup) usize {
        return 3 + Rom.compact.COUNT + 2 + 3 + (if (self.and_table != null) @as(usize, 5) else 0) + (if (self.shift_table != null) @as(usize, 8) else 0);
    }
    pub fn providerCount(self: *const PreparedSetup) usize {
        return 2 + @as(usize, @intFromBool(self.and_table != null)) + @as(usize, @intFromBool(self.shift_table != null));
    }
    pub fn fixedColumns(self: *const PreparedSetup, a: std.mem.Allocator) ![]Column {
        const result = try a.alloc(Column, self.fixedCount());
        var cursor: usize = 0;
        appendColumns(result[cursor..][0..3], self.cpu_fixed, self.log_size);
        cursor += 3;
        appendColumns(result[cursor..][0 .. Rom.compact.COUNT + 2], self.rom_fixed, self.program.log_size);
        cursor += Rom.compact.COUNT + 2;
        appendColumns(result[cursor..][0..3], self.byte_table.fixed, 8);
        cursor += 3;
        if (self.and_table) |table| {
            appendColumns(result[cursor..][0..5], table.fixed, 16);
            cursor += 5;
        }
        if (self.shift_table) |table| {
            appendColumns(result[cursor..][0..8], table.fixed, 11);
            cursor += 8;
        }
        std.debug.assert(cursor == result.len);
        return result;
    }
    /// Consumes proof on every path. Public state and clocks come independently
    /// from the receiving caller; only the typed rational claims accompany it.
    pub fn verifyOwned(self: *const PreparedSetup, a: std.mem.Allocator, public: Statement, claims: Claims, proof_value: Proof) !void {
        var proof = proof_value;
        var owns_proof = true;
        defer if (owns_proof) proof.deinit(a);
        try self.validate(public);
        if (!std.meta.eql(proof.commitment_scheme_proof.config, P.config())) return error.InvalidRv64FullConfig;
        var channel = P.Channel{};
        try public.mix(&channel, self.program.identity);
        var verifier = try Verifier.init(a, P.config());
        defer verifier.deinit(a);
        const fixed = try self.fixedColumns(a);
        defer a.free(fixed);
        const main_count = self.plan.main_count + rv.full.frame.WIDTH;
        const fixed_logs = try a.alloc(u32, fixed.len);
        defer a.free(fixed_logs);
        for (fixed, fixed_logs) |column, *log| log.* = column.log_size;
        const main_logs = try a.alloc(u32, main_count + self.providerCount());
        defer a.free(main_logs);
        @memset(main_logs[0..main_count], self.log_size);
        main_logs[main_count] = self.program.log_size;
        main_logs[main_count + 1] = 8;
        var cursor = main_count + 2;
        if (self.and_table != null) {
            main_logs[cursor] = 16;
            cursor += 1;
        }
        if (self.shift_table != null) {
            main_logs[cursor] = 11;
            cursor += 1;
        }
        const pcs = &proof.commitment_scheme_proof;
        if (pcs.commitments.items.len != 4 or pcs.sampled_values.items.len != 4 or pcs.queried_values.items.len != 4 or pcs.decommitments.items.len != 4) return error.InvalidRv64FullProofShape;
        if (!std.mem.eql(u8, &self.root, &pcs.commitments.items[0])) return error.UntrustedRv64FullPreprocessing;
        try verifier.commit(a, pcs.commitments.items[0], fixed_logs, &channel);
        try verifier.commit(a, pcs.commitments.items[1], main_logs, &channel);
        const challenges = drawChallenges(&channel, self);
        try validateClaims(public, self, claims, challenges);
        const components = try Components.init(self, public, challenges, claims);
        try validateProofShape(self, &components, &proof);
        mixClaims(&channel, claims);
        const interaction_logs = try a.alloc(u32, components.cpu.interactionCount() + self.providerCount() * 8);
        defer a.free(interaction_logs);
        @memset(interaction_logs[0..components.cpu.interactionCount()], self.log_size);
        cursor = components.cpu.interactionCount();
        @memset(interaction_logs[cursor..][0..8], self.program.log_size);
        cursor += 8;
        @memset(interaction_logs[cursor..][0..8], 8);
        cursor += 8;
        if (self.and_table != null) {
            @memset(interaction_logs[cursor..][0..8], 16);
            cursor += 8;
        }
        if (self.shift_table != null) {
            @memset(interaction_logs[cursor..][0..8], 11);
            cursor += 8;
        }
        try verifier.commit(a, pcs.commitments.items[2], interaction_logs, &channel);
        var handles: [5]core.air.components.Component = undefined;
        const count = components.verifierHandles(&handles);
        owns_proof = false;
        try core.verifier.verify(P.Hasher, P.MerkleChannel, a, handles[0..count], &channel, &verifier, proof);
    }
};
pub fn provePrepared(a: std.mem.Allocator, public: Statement, records: []const @import("stwo_riscv_frontend").rv64.machine.Retirement) !Bundle {
    var setup = try PreparedSetup.init(a, public);
    defer setup.deinit();
    var trace = try Trace.init(a, records, public, &setup.program, &setup.plan);
    defer trace.deinit();
    return proveTrace(a, &setup, public, &trace);
}
/// Main source ownership transfers into PCS; narrow metadata preserves relation
/// obligations until interaction closure. `a` must be the trace allocator.
/// A later failure can leave main consumed; the trace always remains deinit-safe.
/// Callers can release capture records before this function.
pub fn proveTrace(a: std.mem.Allocator, setup: *const PreparedSetup, public: Statement, trace: *Trace) !Bundle {
    return proveTraceProfiled(a, setup, public, trace, null);
}

/// Optional coordinator stage telemetry; the proof/transcript path is identical.
pub fn proveTraceProfiled(a: std.mem.Allocator, setup: *const PreparedSetup, public: Statement, trace: *Trace, recorder: ?*stage.Recorder) !Bundle {
    try trace.validateCommitAllocator(a);
    try setup.validate(public);
    var channel = P.Channel{};
    try public.mix(&channel, setup.program.identity);
    var scheme = try Scheme.init(a, P.config());
    scheme.setCompactPolynomialStorage(5);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    try commitProfiled(&scheme, a, fixed, &channel, recorder, "fixed_commit");
    var rom_request = try romRequest(a, &setup.program, trace.rom_counts);
    defer rom_request.deinit();
    var byte_request = try Bytes.provider.Trace.init(a, &trace.byte_counts);
    defer byte_request.deinit();
    var and_request: ?Tables.Request = if (setup.and_table) |*table| try Tables.Request.init(a, table, trace.and_counts) else null;
    defer if (and_request) |*request| request.deinit();
    var shift_request: ?Tables.Request = if (setup.shift_table) |*table| try Tables.Request.init(a, table, trace.shift_counts) else null;
    defer if (shift_request) |*request| request.deinit();
    var provider_columns: [4]Column = undefined;
    appendColumns(provider_columns[0..1], rom_request.multiplicities, setup.program.log_size);
    appendColumns(provider_columns[1..2], byte_request.main, 8);
    var cursor: usize = 2;
    if (and_request) |request| {
        appendColumns(provider_columns[cursor..][0..1], request.main, 16);
        cursor += 1;
    }
    if (shift_request) |request| {
        appendColumns(provider_columns[cursor..][0..1], request.main, 11);
        cursor += 1;
    }
    // Every provider multiplicity is sealed with the CPU main before any
    // lookup denominator can be selected from transcript randomness.
    var main_transfer = try trace.takeMainForCommit(a, provider_columns[0..cursor]);
    var owns_main_transfer = true;
    defer if (owns_main_transfer) main_transfer.deinit(a);
    {
        var main_stage = try stage.StageScope.begin(recorder, "main_commit", "Main commitment with source ownership");
        defer main_stage.end();
        // This API consumes descriptors and the complete backing allocation on
        // both success and failure. No source matrix alias remains in Trace.
        owns_main_transfer = false;
        try scheme.commitOwnedWithRecorderAndBacking(a, main_transfer.columns, main_transfer.backing, recorder, &channel);
    }
    const challenges = drawChallenges(&channel, setup);
    var interaction_stage = try stage.StageScope.begin(recorder, "interaction_generation", "CPU interaction generation");
    defer interaction_stage.end();
    const claims = try trace.generateInteraction(challenges);
    interaction_stage.end();
    var provider_stage = try stage.StageScope.begin(recorder, "provider_interaction_generation", "Provider interaction generation");
    defer provider_stage.end();
    try validateClaims(public, setup, claims, challenges);
    if (!(try rom_request.generateInteraction(&setup.program, challenges.rom)).add(claims.rom).isZero()) return error.Rv64FullRomClosure;
    if (!(try byte_request.generateInteraction(challenges.bytes)).add(claims.bytes).isZero()) return error.Rv64FullByteClosure;
    if (and_request) |*request| if (!(try request.generateInteraction(challenges.bitwise)).add(claims.bitwise).isZero()) return error.Rv64FullAndClosure;
    if (shift_request) |*request| if (!(try request.generateInteraction(challenges.shifts)).add(claims.shifts).isZero()) return error.Rv64FullShiftClosure;
    provider_stage.end();
    var components = try Components.init(setup, public, challenges, claims);
    components.cpu.stage_recorder = recorder;
    const interaction_columns = try a.alloc(Column, components.cpu.interactionCount() + setup.providerCount() * 8);
    defer a.free(interaction_columns);
    appendColumns(interaction_columns[0..components.cpu.interactionCount()], trace.interaction, setup.log_size);
    cursor = components.cpu.interactionCount();
    appendColumns(interaction_columns[cursor..][0..8], rom_request.interaction, setup.program.log_size);
    cursor += 8;
    appendColumns(interaction_columns[cursor..][0..8], byte_request.interaction, 8);
    cursor += 8;
    if (and_request) |request| {
        appendColumns(interaction_columns[cursor..][0..8], request.interaction, 16);
        cursor += 8;
    }
    if (shift_request) |request| {
        appendColumns(interaction_columns[cursor..][0..8], request.interaction, 11);
        cursor += 8;
    }
    mixClaims(&channel, claims);
    try commitProfiled(&scheme, a, interaction_columns, &channel, recorder, "interaction_commit");
    // Source descriptors are no longer dereferenced once commitments finish.
    trace.allocator.free(trace.interaction);
    trace.interaction = &.{};
    var handles: [5]engine.air.component_prover.ComponentProver = undefined;
    const count = components.proverHandles(&handles);
    owns_scheme = false;
    var extended = try engine.prove.proveExWithRecorder(B, P.Hasher, P.MerkleChannel, a, handles[0..count], &channel, scheme, false, recorder);
    extended.aux.deinit(a);
    return .{ .claims = claims, .proof = extended.proof };
}

fn commitProfiled(scheme: *Scheme, a: std.mem.Allocator, columns: []const Column, channel: *P.Channel, recorder: ?*stage.Recorder, id: []const u8) !void {
    var scope = try stage.StageScope.begin(recorder, id, id);
    defer scope.end();
    try scheme.commitBorrowedStreamingWithRecorder(a, columns, 8, recorder, channel);
}

const Components = struct {
    cpu: Cpu.Component,
    program: Rom.component.Component,
    bytes: rv.providers.byte.Component,
    bitwise: ?rv.providers.table_component.Component,
    shifts: ?rv.providers.table_component.Component,
    fn init(setup: *const PreparedSetup, public: Statement, challenges: Cpu.Challenges, claims: Claims) !Components {
        const cpu = try Cpu.Component.init(setup.log_size, &setup.plan, .{ .steps = public.steps, .initial_pc = public.initial_pc, .final_pc = public.final_pc }, challenges, claims, .{});
        var result = Components{ .cpu = cpu, .program = .{ .log_size = setup.program.log_size, .encoding = .compact41, .fixed_offset = 3, .main_offset = cpu.mainCount(), .interaction_offset = cpu.interactionCount(), .challenges = challenges.rom, .claim = claims.rom.neg() }, .bytes = .{ .fixed_offset = 3 + Rom.compact.COUNT + 2, .main_offset = cpu.mainCount() + 1, .interaction_offset = cpu.interactionCount() + 8, .alpha = challenges.bytes, .claim = claims.bytes.neg() }, .bitwise = null, .shifts = null };
        var fixed_cursor: usize = 3 + Rom.compact.COUNT + 2 + 3;
        var main_cursor = cpu.mainCount() + 2;
        var inter_cursor = cpu.interactionCount() + 16;
        if (setup.and_table != null) {
            result.bitwise = .{ .kind = .byte_and, .fixed_offset = fixed_cursor, .main_offset = main_cursor, .interaction_offset = inter_cursor, .challenges = challenges.bitwise, .claim = claims.bitwise.neg() };
            fixed_cursor += 5;
            main_cursor += 1;
            inter_cursor += 8;
        }
        if (setup.shift_table != null) {
            result.shifts = .{ .kind = .byte_shift, .fixed_offset = fixed_cursor, .main_offset = main_cursor, .interaction_offset = inter_cursor, .challenges = challenges.shifts, .claim = claims.shifts.neg() };
        }
        return result;
    }
    fn proverHandles(self: *const Components, out: *[5]engine.air.component_prover.ComponentProver) usize {
        out[0] = self.cpu.asProverComponent();
        out[1] = self.program.asProverComponent();
        out[2] = self.bytes.asProverComponent();
        var count: usize = 3;
        if (self.bitwise) |*component| {
            out[count] = component.asProverComponent();
            count += 1;
        }
        if (self.shifts) |*component| {
            out[count] = component.asProverComponent();
            count += 1;
        }
        return count;
    }
    fn verifierHandles(self: *const Components, out: *[5]core.air.components.Component) usize {
        out[0] = self.cpu.asVerifierComponent();
        out[1] = self.program.asVerifierComponent();
        out[2] = self.bytes.asVerifierComponent();
        var count: usize = 3;
        if (self.bitwise) |*component| {
            out[count] = component.asVerifierComponent();
            count += 1;
        }
        if (self.shifts) |*component| {
            out[count] = component.asVerifierComponent();
            count += 1;
        }
        return count;
    }
};
fn appendColumns(output: []Column, storage: []const M, log: u32) void {
    const size = @as(usize, 1) << @intCast(log);
    std.debug.assert(output.len * size == storage.len);
    for (output, 0..) |*column, c| column.* = .{ .log_size = log, .values = storage[c * size ..][0..size] };
}
fn drawChallenges(channel: *P.Channel, setup: *const PreparedSetup) Cpu.Challenges {
    var result: Cpu.Challenges = undefined;
    result.state = rv.relations.Challenges.draw(channel);
    result.rom = Rom.compact.draw(channel);
    channel.mixU32s(&.{ 0x52563634, 0x42595445, 1 });
    result.bytes = channel.drawSecureFelt();
    const absent = Tables.Challenges{ .offset = Q.one(), .coefficients = @splat(Q.zero()) };
    result.bitwise = absent;
    result.shifts = absent;
    if (setup.and_table != null) {
        channel.mixU32s(&.{ 0x52563634, 0x414e4438, 1 });
        result.bitwise = Tables.Challenges.draw(channel);
    }
    if (setup.shift_table != null) {
        channel.mixU32s(&.{ 0x52563634, 0x53484638, 1 });
        result.shifts = Tables.Challenges.draw(channel);
    }
    return result;
}
fn mixClaims(channel: *P.Channel, claims: Claims) void {
    channel.mixU32s(&.{ 0x52563634, 0x434c414d, 1, 5 });
    channel.mixFelts(&.{ claims.state, claims.rom, claims.bytes, claims.bitwise, claims.shifts });
}
fn validateClaims(public: Statement, setup: *const PreparedSetup, claims: Claims, challenges: Cpu.Challenges) !void {
    // Claims may arrive through JSON rather than the canonical proof decoder.
    for ([_]Q{ claims.state, claims.rom, claims.bytes, claims.bitwise, claims.shifts }) |claim| {
        if (claim.c0.a.v >= core.fields.m31.Modulus or claim.c0.b.v >= core.fields.m31.Modulus or
            claim.c1.a.v >= core.fields.m31.Modulus or claim.c1.b.v >= core.fields.m31.Modulus) return error.InvalidRv64FullClaimEncoding;
    }
    if (!claims.state.eql(try public.expectedState(challenges.state))) return error.Rv64FullStateClosure;
    if (setup.and_table == null and !claims.bitwise.isZero()) return error.Rv64FullAndClosure;
    if (setup.shift_table == null and !claims.shifts.isZero()) return error.Rv64FullShiftClosure;
}
fn romRequest(a: std.mem.Allocator, program: *const Rom.setup.Setup, counts: []const u64) !Rom.provider.Request {
    if (counts.len != program.domainSize()) return error.InvalidRv64FullRomCounts;
    var total: u64 = 0;
    for (counts, 0..) |count, i| {
        total = try std.math.add(u64, total, count);
        if (total > Rom.provider.MAX_REQUESTS or (count != 0 and (i >= program.rows.len or program.rows[i][Rom.setup.field.valid].isZero()))) return error.InvalidRv64FullRomCounts;
    }
    const multiplicities = try a.alloc(M, counts.len);
    for (counts, 0..) |count, i| multiplicities[@import("stwo_riscv_frontend").rv64_air.witness.physical(i, program.log_size)] = M.fromCanonical(@intCast(count));
    return .{ .allocator = a, .log_size = program.log_size, .multiplicities = multiplicities, .count = @intCast(total) };
}
fn validateProofShape(setup: *const PreparedSetup, components: *const Components, proof: *const Proof) !void {
    const pcs = &proof.commitment_scheme_proof;
    const counts = [_]usize{ setup.fixedCount(), components.cpu.mainCount() + setup.providerCount(), components.cpu.interactionCount() + 8 * setup.providerCount(), 16 };
    for (counts, 0..) |count, tree| {
        if (pcs.sampled_values.items[tree].len != count or pcs.queried_values.items[tree].len != count) return error.InvalidRv64FullProofShape;
        for (pcs.sampled_values.items[tree], 0..) |column, c| {
            const shifted = if (tree == 1 and c < components.cpu.mainCount()) components.cpu.needsPreviousMain(c) else if (tree == 2) (if (c < components.cpu.interactionCount()) components.cpu.needsPreviousInteraction(c) else (c - components.cpu.interactionCount()) % 8 >= 4) else false;
            if (column.len != @as(usize, if (shifted) 2 else 1)) return error.InvalidRv64FullProofShape;
        }
        for (pcs.queried_values.items[tree]) |column| if (column.len == 0 or column.len > P.config().fri_config.n_queries) return error.InvalidRv64FullProofShape;
    }
}
