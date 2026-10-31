//! One full execution, one shared commitment/composition/FRI transaction.
//! Immutable setup comes from the receiver's program, opcode policy and domain.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const ExecutionProfile = @import("stwo_riscv_frontend").rv64.execution_profile.Profile;
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
pub const ProgramAuthority = @import("rv64_program_authority.zig").Authority;
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
    return planForStatementWithProfiles(public, .inline_v4, .rv64im);
}
pub fn planForStatementWithProfiles(public: Statement, policy: rv.arithmetic.division.policy.Policy, profile: ExecutionProfile) !rv.encoding.Plan {
    return planForStatementWithControl(public, policy, profile, .bytes_v1);
}
pub fn planForStatementWithControl(public: Statement, policy: rv.arithmetic.division.policy.Policy, profile: ExecutionProfile, control: rv.control_policy.Policy) !rv.encoding.Plan {
    try public.validateWithProfile(profile);
    var opcodes: [65]rv.evaluation.O = undefined;
    var count: usize = 0;
    for (public.opcodes, 0..) |enabled, opcode| if (enabled) {
        opcodes[count] = @enumFromInt(opcode);
        count += 1;
    };
    var plan = try rv.encoding.Plan.fromOpcodesWithProfiles(opcodes[0..count], policy, profile);
    plan.control_policy = control;
    return plan;
}
/// Evaluation metadata only. The Plan pointer belongs to a live materials/key
/// owner; this view never owns or stands in for preprocessing matrices.
pub const VerificationView = struct {
    plan: *const rv.encoding.Plan,
    log_size: u32,
    program: struct { log_size: u32, identity: [32]u8 },
    has_and: bool,
    has_shift: bool,
    pub fn fixedCount(self: VerificationView) usize {
        return 3 + romTupleCount(self.plan.control_policy) + 2 + 3 + (if (self.has_and) @as(usize, 5) else 0) + (if (self.has_shift) @as(usize, 8) else 0);
    }
    pub fn providerCount(self: VerificationView) usize {
        return 2 + @as(usize, @intFromBool(self.has_and)) + @as(usize, @intFromBool(self.has_shift));
    }
};
pub const PreparedMaterials = struct {
    allocator: std.mem.Allocator,
    program: Rom.setup.Setup,
    /// Borrowed immutable objects are owned by an independently derived authority.
    borrows_immutable: bool = false,
    plan: rv.encoding.Plan,
    log_size: u32,
    cpu_fixed: []M,
    rom_fixed: []M,
    byte_table: Bytes.provider.Trace,
    and_table: ?Tables.Setup,
    shift_table: ?Tables.Setup,
    pub fn init(a: std.mem.Allocator, public: Statement) !PreparedMaterials {
        return initWithPolicy(a, public, .inline_v4);
    }
    pub fn initWithPolicy(a: std.mem.Allocator, public: Statement, policy: rv.arithmetic.division.policy.Policy) !PreparedMaterials {
        return initWithProfiles(a, public, policy, .rv64im);
    }
    pub fn initWithProfiles(a: std.mem.Allocator, public: Statement, policy: rv.arithmetic.division.policy.Policy, profile: ExecutionProfile) !PreparedMaterials {
        return initWithStatePolicy(a, public, policy, profile, .inverse_v1);
    }
    pub fn initWithStatePolicy(a: std.mem.Allocator, public: Statement, policy: rv.arithmetic.division.policy.Policy, profile: ExecutionProfile, state_policy: rv.state_policy.Policy) !PreparedMaterials {
        return initWithControl(a, public, policy, profile, state_policy, .bytes_v1);
    }
    pub fn initWithControl(a: std.mem.Allocator, public: Statement, policy: rv.arithmetic.division.policy.Policy, profile: ExecutionProfile, state_policy: rv.state_policy.Policy, control: rv.control_policy.Policy) !PreparedMaterials {
        var plan = try planForStatementWithControl(public, policy, profile, control);
        plan.setStatePolicy(state_policy);
        var program = try Rom.setup.Setup.initWithProfile(a, public.program, profile);
        errdefer program.deinit();
        const cpu_fixed = try rv.full.frame.fixedColumns(a, public.logSize());
        errdefer a.free(cpu_fixed);
        const rom_fixed = try program.controlFixedColumns(a, control);
        errdefer a.free(rom_fixed);
        const zero_counts: [256]u64 = @splat(0);
        var byte_table = try Bytes.provider.Trace.init(a, &zero_counts);
        errdefer byte_table.deinit();
        var and_table: ?Tables.Setup = if (Bytes.table_cpu.requests(&plan, .byte_and) > 0) try Tables.Setup.init(a, .byte_and) else null;
        errdefer if (and_table) |*table| table.deinit();
        var shift_table: ?Tables.Setup = if (Bytes.table_cpu.requests(&plan, .byte_shift) > 0) try Tables.Setup.init(a, .byte_shift) else null;
        errdefer if (shift_table) |*table| table.deinit();
        return PreparedMaterials{ .allocator = a, .program = program, .plan = plan, .log_size = public.logSize(), .cpu_fixed = cpu_fixed, .rom_fixed = rom_fixed, .byte_table = byte_table, .and_table = and_table, .shift_table = shift_table };
    }
    /// Borrows receiver-derived immutable setup. Only CPU domain columns are
    /// allocated per geometry; caller retains authority through proof/verify.
    pub fn initWithAuthority(a: std.mem.Allocator, public: Statement, policy: rv.arithmetic.division.policy.Policy, state_policy: rv.state_policy.Policy, authority: *const ProgramAuthority) !PreparedMaterials {
        var plan = try planForStatementWithControl(public, policy, authority.profile, authority.control_policy);
        plan.setStatePolicy(state_policy);
        if (!std.mem.eql(bool, &public.opcodes, &authority.opcodes) or
            (Bytes.table_cpu.requests(&plan, .byte_and) != 0) != (authority.and_table != null) or
            (Bytes.table_cpu.requests(&plan, .byte_shift) != 0) != (authority.shift_table != null)) return error.Rv64FullSetupMismatch;
        const cpu_fixed = try rv.full.frame.fixedColumns(a, public.logSize());
        errdefer a.free(cpu_fixed);
        const result = PreparedMaterials{ .allocator = a, .program = authority.program, .borrows_immutable = true, .plan = plan, .log_size = public.logSize(), .cpu_fixed = cpu_fixed, .rom_fixed = authority.rom_fixed, .byte_table = authority.byte_table, .and_table = authority.and_table, .shift_table = authority.shift_table };
        try result.validate(public);
        return result;
    }
    pub fn deinit(self: *PreparedMaterials) void {
        self.allocator.free(self.cpu_fixed);
        if (!self.borrows_immutable) {
            self.program.deinit();
            self.allocator.free(self.rom_fixed);
            self.byte_table.deinit();
            if (self.and_table) |*table| table.deinit();
            if (self.shift_table) |*table| table.deinit();
        }
        self.* = undefined;
    }
    fn validate(self: *const PreparedMaterials, public: Statement) !void {
        try public.validateWithProfile(self.plan.execution_profile);
        if (public.logSize() != self.log_size or !std.mem.eql(bool, &public.opcodes, &self.plan.allowed_opcodes) or public.program.words.len != self.program.rows.len) return error.Rv64FullSetupMismatch;
        for (public.program.words, 0..) |word, i| {
            if (public.program.pc(i) != self.program.addresses[i]) return error.Rv64FullSetupMismatch;
            const row = self.program.rows[i];
            for (0..4) |b| if (row[Rom.setup.field.raw + b].v != ((word >> @as(u5, @intCast(b * 8))) & 255)) return error.Rv64FullSetupMismatch;
        }
    }
    pub fn verificationView(self: *const PreparedMaterials) VerificationView {
        return .{ .plan = &self.plan, .log_size = self.log_size, .program = .{ .log_size = self.program.log_size, .identity = self.program.identity }, .has_and = self.and_table != null, .has_shift = self.shift_table != null };
    }
    pub fn fixedCount(self: *const PreparedMaterials) usize {
        return self.verificationView().fixedCount();
    }
    pub fn providerCount(self: *const PreparedMaterials) usize {
        return self.verificationView().providerCount();
    }
    pub fn fixedColumns(self: *const PreparedMaterials, a: std.mem.Allocator) ![]Column {
        const result = try a.alloc(Column, self.fixedCount());
        var cursor: usize = 0;
        appendColumns(result[cursor..][0..3], self.cpu_fixed, self.log_size);
        cursor += 3;
        appendColumns(result[cursor..][0 .. romTupleCount(self.plan.control_policy) + 2], self.rom_fixed, self.program.log_size);
        cursor += romTupleCount(self.plan.control_policy) + 2;
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
};

/// A standalone authority root is present only after immutable materials have
/// been committed. Composed coordinators own PreparedMaterials directly and
/// commit their complete fixed roster once, without an unused intermediate key.
pub const PreparedSetup = struct {
    materials: PreparedMaterials,
    root: [32]u8,
    pub fn init(a: std.mem.Allocator, public: Statement) !PreparedSetup {
        return initWithPolicy(a, public, .inline_v4);
    }
    pub fn initWithPolicy(a: std.mem.Allocator, public: Statement, policy: rv.arithmetic.division.policy.Policy) !PreparedSetup {
        return initWithProfiles(a, public, policy, .rv64im);
    }
    pub fn initWithProfiles(a: std.mem.Allocator, public: Statement, policy: rv.arithmetic.division.policy.Policy, profile: ExecutionProfile) !PreparedSetup {
        return finishMaterials(a, try PreparedMaterials.initWithProfiles(a, public, policy, profile));
    }
    /// Explicit standalone inline/inverse profile; the receiving caller chooses
    /// the control representation independently of proof-provided claims.
    pub fn initWithControl(a: std.mem.Allocator, public: Statement, control: rv.control_policy.Policy) !PreparedSetup {
        return finishMaterials(a, try PreparedMaterials.initWithControl(a, public, .inline_v4, .rv64im, .inverse_v1, control));
    }
    fn finishMaterials(a: std.mem.Allocator, owned: PreparedMaterials) !PreparedSetup {
        var materials = owned;
        errdefer materials.deinit();
        const fixed = try materials.fixedColumns(a);
        defer a.free(fixed);
        var scheme = try Scheme.init(a, P.config());
        defer scheme.deinit(a);
        var channel = P.Channel{};
        try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        return .{ .materials = materials, .root = roots.items[0] };
    }
    pub fn deinit(self: *PreparedSetup) void {
        self.materials.deinit();
        self.* = undefined;
    }
    fn validate(self: *const PreparedSetup, public: Statement) !void {
        try self.materials.validate(public);
    }
    pub fn fixedCount(self: *const PreparedSetup) usize {
        return self.materials.fixedCount();
    }
    pub fn providerCount(self: *const PreparedSetup) usize {
        return self.materials.providerCount();
    }
    pub fn fixedColumns(self: *const PreparedSetup, a: std.mem.Allocator) ![]Column {
        return self.materials.fixedColumns(a);
    }
    /// Consumes proof on every path. Public state and clocks come independently
    /// from the receiving caller; only the typed rational claims accompany it.
    pub fn verifyOwned(self: *const PreparedSetup, a: std.mem.Allocator, public: Statement, claims: Claims, proof_value: Proof) !void {
        var proof = proof_value;
        var owns_proof = true;
        defer if (owns_proof) proof.deinit(a);
        if (self.materials.plan.state_policy != .inverse_v1 or self.materials.plan.execution_profile != .rv64im or self.materials.plan.arithmetic_policy != .inline_v4) return error.InvalidRv64FullPlan;
        try self.validate(public);
        if (!std.meta.eql(proof.commitment_scheme_proof.config, P.config())) return error.InvalidRv64FullConfig;
        var channel = P.Channel{};
        try mixStandalonePublic(&channel, public, self.materials.program.identity, self.materials.plan.control_policy);
        var verifier = try Verifier.init(a, P.config());
        defer verifier.deinit(a);
        const fixed = try self.fixedColumns(a);
        defer a.free(fixed);
        const main_count = self.materials.plan.main_count + rv.full.frame.widthWithControl(.rv64im, self.materials.plan.control_policy);
        const fixed_logs = try a.alloc(u32, fixed.len);
        defer a.free(fixed_logs);
        for (fixed, fixed_logs) |column, *log| log.* = column.log_size;
        const main_logs = try a.alloc(u32, main_count + self.providerCount());
        defer a.free(main_logs);
        @memset(main_logs[0..main_count], self.materials.log_size);
        main_logs[main_count] = self.materials.program.log_size;
        main_logs[main_count + 1] = 8;
        var cursor = main_count + 2;
        if (self.materials.and_table != null) {
            main_logs[cursor] = 16;
            cursor += 1;
        }
        if (self.materials.shift_table != null) {
            main_logs[cursor] = 11;
            cursor += 1;
        }
        const pcs = &proof.commitment_scheme_proof;
        if (pcs.commitments.items.len != 4 or pcs.sampled_values.items.len != 4 or pcs.queried_values.items.len != 4 or pcs.decommitments.items.len != 4) return error.InvalidRv64FullProofShape;
        if (!std.mem.eql(u8, &self.root, &pcs.commitments.items[0])) return error.UntrustedRv64FullPreprocessing;
        try verifier.commit(a, pcs.commitments.items[0], fixed_logs, &channel);
        try verifier.commit(a, pcs.commitments.items[1], main_logs, &channel);
        const challenges = drawChallenges(&channel, &self.materials);
        try validateClaims(public, &self.materials, claims, challenges);
        const components = try Components.init(&self.materials, public, challenges, claims);
        try validateProofShape(&self.materials, &components, &proof);
        mixClaims(&channel, claims);
        const interaction_logs = try a.alloc(u32, components.cpu.interactionCount() + self.providerCount() * 8);
        defer a.free(interaction_logs);
        @memset(interaction_logs[0..components.cpu.interactionCount()], self.materials.log_size);
        cursor = components.cpu.interactionCount();
        @memset(interaction_logs[cursor..][0..8], self.materials.program.log_size);
        cursor += 8;
        @memset(interaction_logs[cursor..][0..8], 8);
        cursor += 8;
        if (self.materials.and_table != null) {
            @memset(interaction_logs[cursor..][0..8], 16);
            cursor += 8;
        }
        if (self.materials.shift_table != null) {
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
    var trace = try Trace.init(a, records, public, &setup.materials.program, &setup.materials.plan);
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
    if (setup.materials.plan.control_policy != trace.plan.control_policy or setup.materials.plan.state_policy != .inverse_v1 or trace.plan.state_policy != .inverse_v1 or setup.materials.plan.execution_profile != .rv64im or trace.plan.execution_profile != .rv64im or setup.materials.plan.arithmetic_policy != .inline_v4 or trace.plan.arithmetic_policy != .inline_v4) return error.InvalidRv64FullPlan;
    try setup.validate(public);
    var channel = P.Channel{};
    try mixStandalonePublic(&channel, public, setup.materials.program.identity, setup.materials.plan.control_policy);
    var scheme = try Scheme.init(a, P.config());
    scheme.setCompactPolynomialStorage(5);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    try commitProfiled(&scheme, a, fixed, &channel, recorder, "fixed_commit");
    var rom_request = try romRequest(a, &setup.materials.program, trace.rom_counts);
    defer rom_request.deinit();
    var byte_request = try Bytes.provider.Trace.init(a, &trace.byte_counts);
    defer byte_request.deinit();
    var and_request: ?Tables.Request = if (setup.materials.and_table) |*table| try Tables.Request.init(a, table, trace.and_counts) else null;
    defer if (and_request) |*request| request.deinit();
    var shift_request: ?Tables.Request = if (setup.materials.shift_table) |*table| try Tables.Request.init(a, table, trace.shift_counts) else null;
    defer if (shift_request) |*request| request.deinit();
    var provider_columns: [4]Column = undefined;
    appendColumns(provider_columns[0..1], rom_request.multiplicities, setup.materials.program.log_size);
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
    const challenges = drawChallenges(&channel, &setup.materials);
    var interaction_stage = try stage.StageScope.begin(recorder, "interaction_generation", "CPU interaction generation");
    defer interaction_stage.end();
    const claims = try trace.generateInteraction(challenges);
    interaction_stage.end();
    var provider_stage = try stage.StageScope.begin(recorder, "provider_interaction_generation", "Provider interaction generation");
    defer provider_stage.end();
    try validateClaims(public, &setup.materials, claims, challenges);
    if (!(try rom_request.generateInteraction(&setup.materials.program, challenges.rom)).add(claims.rom).isZero()) return error.Rv64FullRomClosure;
    if (!(try byte_request.generateInteraction(challenges.bytes)).add(claims.bytes).isZero()) return error.Rv64FullByteClosure;
    if (and_request) |*request| if (!(try request.generateInteraction(challenges.bitwise)).add(claims.bitwise).isZero()) return error.Rv64FullAndClosure;
    if (shift_request) |*request| if (!(try request.generateInteraction(challenges.shifts)).add(claims.shifts).isZero()) return error.Rv64FullShiftClosure;
    provider_stage.end();
    var components = try Components.init(&setup.materials, public, challenges, claims);
    components.cpu.stage_recorder = recorder;
    const interaction_columns = try a.alloc(Column, components.cpu.interactionCount() + setup.providerCount() * 8);
    defer a.free(interaction_columns);
    appendColumns(interaction_columns[0..components.cpu.interactionCount()], trace.interaction, setup.materials.log_size);
    cursor = components.cpu.interactionCount();
    appendColumns(interaction_columns[cursor..][0..8], rom_request.interaction, setup.materials.program.log_size);
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
    fn init(setup: *const PreparedMaterials, public: Statement, challenges: Cpu.Challenges, claims: Claims) !Components {
        return initWithDivision(setup, public, challenges, claims, null);
    }
    pub fn initWithDivision(setup: *const PreparedMaterials, public: Statement, challenges: Cpu.Challenges, claims: Claims, bus: ?rv.arithmetic.division.cpu_bus.Bus) !Components {
        return initWithServices(setup, public, challenges, claims, bus, null);
    }
    pub fn initWithServices(setup: *const PreparedMaterials, public: Statement, challenges: Cpu.Challenges, claims: Claims, bus: ?rv.arithmetic.division.cpu_bus.Bus, service: ?rv.crypto.keccak.cpu_bus.Bus) !Components {
        return initWithArithmeticServices(setup, public, challenges, claims, bus, service, null);
    }
    pub fn initWithArithmeticServices(setup: *const PreparedMaterials, public: Statement, challenges: Cpu.Challenges, claims: Claims, bus: ?rv.arithmetic.division.cpu_bus.Bus, service: ?rv.crypto.keccak.cpu_bus.Bus, mul: ?rv.arithmetic.multiplication.cpu_bus.Bus) !Components {
        return initWithAllServices(setup, public, challenges, claims, bus, service, mul, null);
    }
    pub fn initWithAllServices(setup: *const PreparedMaterials, public: Statement, challenges: Cpu.Challenges, claims: Claims, bus: ?rv.arithmetic.division.cpu_bus.Bus, service: ?rv.crypto.keccak.cpu_bus.Bus, mul: ?rv.arithmetic.multiplication.cpu_bus.Bus, elliptic: ?rv.crypto.secp256k1.cpu_bus.Bus) !Components {
        return initWithAllServicesView(setup.verificationView(), public, challenges, claims, bus, service, mul, elliptic);
    }
    pub fn initWithAllServicesView(setup: VerificationView, public: Statement, challenges: Cpu.Challenges, claims: Claims, bus: ?rv.arithmetic.division.cpu_bus.Bus, service: ?rv.crypto.keccak.cpu_bus.Bus, mul: ?rv.arithmetic.multiplication.cpu_bus.Bus, elliptic: ?rv.crypto.secp256k1.cpu_bus.Bus) !Components {
        const boundary = rv.full.frame.Public{ .steps = public.steps, .initial_pc = public.initial_pc, .final_pc = public.final_pc };
        const cpu = if (elliptic) |value| try Cpu.Component.initWithEthereum(setup.log_size, setup.plan, boundary, challenges, claims, .{}, bus orelse return error.InvalidRv64FullPlan, service orelse return error.InvalidRv64FullPlan, mul, value) else if (mul) |value| try Cpu.Component.initWithKeccakAndMultiplication(setup.log_size, setup.plan, boundary, challenges, claims, .{}, bus orelse return error.InvalidRv64FullPlan, service orelse return error.InvalidRv64FullPlan, value) else if (service) |value| try Cpu.Component.initWithKeccak(setup.log_size, setup.plan, boundary, challenges, claims, .{}, bus orelse return error.InvalidRv64FullPlan, value) else if (bus) |value| try Cpu.Component.initWithDivision(setup.log_size, setup.plan, boundary, challenges, claims, .{}, value) else try Cpu.Component.init(setup.log_size, setup.plan, .{ .steps = public.steps, .initial_pc = public.initial_pc, .final_pc = public.final_pc }, challenges, claims, .{});
        var result = Components{ .cpu = cpu, .program = .{ .log_size = setup.program.log_size, .encoding = if (setup.plan.control_policy == .bytes_v1) .compact41 else .packed26, .fixed_offset = 3, .main_offset = cpu.mainCount(), .interaction_offset = cpu.interactionCount(), .challenges = challenges.rom, .claim = claims.rom.neg() }, .bytes = .{ .fixed_offset = 3 + romTupleCount(setup.plan.control_policy) + 2, .main_offset = cpu.mainCount() + 1, .interaction_offset = cpu.interactionCount() + 8, .alpha = challenges.bytes, .claim = claims.bytes.neg() }, .bitwise = null, .shifts = null };
        var fixed_cursor: usize = 3 + romTupleCount(setup.plan.control_policy) + 2 + 3;
        var main_cursor = cpu.mainCount() + 2;
        var inter_cursor = cpu.interactionCount() + 16;
        if (setup.has_and) {
            result.bitwise = .{ .kind = .byte_and, .fixed_offset = fixed_cursor, .main_offset = main_cursor, .interaction_offset = inter_cursor, .challenges = challenges.bitwise, .claim = claims.bitwise.neg() };
            fixed_cursor += 5;
            main_cursor += 1;
            inter_cursor += 8;
        }
        if (setup.has_shift) {
            result.shifts = .{ .kind = .byte_shift, .fixed_offset = fixed_cursor, .main_offset = main_cursor, .interaction_offset = inter_cursor, .challenges = challenges.shifts, .claim = claims.shifts.neg() };
        }
        return result;
    }
    pub fn proverHandles(self: *const Components, out: *[5]engine.air.component_prover.ComponentProver) usize {
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
    pub fn verifierHandles(self: *const Components, out: *[5]core.air.components.Component) usize {
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
fn drawChallenges(channel: *P.Channel, setup: *const PreparedMaterials) Cpu.Challenges {
    return drawChallengesView(channel, setup.verificationView());
}
fn drawChallengesView(channel: *P.Channel, setup: VerificationView) Cpu.Challenges {
    var result: Cpu.Challenges = undefined;
    result.state = if (rv.state_policy.isCyclic(setup.plan.state_policy)) rv.state_cyclic.drawWithPolicy(channel, setup.plan.state_policy) else rv.relations.Challenges.draw(channel);
    result.rom = if (setup.plan.control_policy == .bytes_v1) Rom.compact.draw(channel) else Rom.packed_control.draw(channel);
    channel.mixU32s(&.{ 0x52563634, 0x42595445, 1 });
    result.bytes = channel.drawSecureFelt();
    const absent = Tables.Challenges{ .offset = Q.one(), .coefficients = @splat(Q.zero()) };
    result.bitwise = absent;
    result.shifts = absent;
    if (setup.has_and) {
        channel.mixU32s(&.{ 0x52563634, 0x414e4438, 1 });
        result.bitwise = Tables.Challenges.draw(channel);
    }
    if (setup.has_shift) {
        channel.mixU32s(&.{ 0x52563634, 0x53484638, 1 });
        result.shifts = Tables.Challenges.draw(channel);
    }
    return result;
}
fn mixClaims(channel: *P.Channel, claims: Claims) void {
    channel.mixU32s(&.{ 0x52563634, 0x434c414d, 1, 5 });
    channel.mixFelts(&.{ claims.state, claims.rom, claims.bytes, claims.bitwise, claims.shifts });
}
fn validateClaimEncoding(setup: *const PreparedMaterials, claims: Claims) !void {
    return validateClaimEncodingView(setup.verificationView(), claims);
}
fn validateClaimEncodingView(setup: VerificationView, claims: Claims) !void {
    // Claims may arrive through JSON rather than the canonical proof decoder.
    for ([_]Q{ claims.state, claims.rom, claims.bytes, claims.bitwise, claims.shifts }) |claim| {
        if (claim.c0.a.v >= core.fields.m31.Modulus or claim.c0.b.v >= core.fields.m31.Modulus or
            claim.c1.a.v >= core.fields.m31.Modulus or claim.c1.b.v >= core.fields.m31.Modulus) return error.InvalidRv64FullClaimEncoding;
    }
    if (!setup.has_and and !claims.bitwise.isZero()) return error.Rv64FullAndClosure;
    if (!setup.has_shift and !claims.shifts.isZero()) return error.Rv64FullShiftClosure;
}
fn validateClaims(public: Statement, setup: *const PreparedMaterials, claims: Claims, challenges: Cpu.Challenges) !void {
    try validateClaimEncoding(setup, claims);
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
fn validateProofShape(setup: *const PreparedMaterials, components: *const Components, proof: *const Proof) !void {
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

/// Concrete plumbing reused by the separately versioned arithmetic-service
/// coordinator. Authority remains in the same statement/provider components.
pub const Support = struct {
    pub const Backend = B;
    pub const SharedComponents = Components;
    pub const validateSetup = PreparedMaterials.validate;
    pub const append = appendColumns;
    pub const rom = romRequest;
    pub const challenges = drawChallenges;
    pub const challengesView = drawChallengesView;
    pub const mix = mixClaims;
    pub const validate = validateClaims;
    pub const validateEncoding = validateClaimEncoding;
    pub const validateEncodingView = validateClaimEncodingView;
};

fn romTupleCount(control: rv.control_policy.Policy) usize {
    return if (control == .bytes_v1) Rom.compact.COUNT else Rom.packed_control.COUNT;
}

/// Legacy bytes_v1 has no additional transcript material. Packed standalone
/// Full is a distinct protocol from both legacy Full and the service coordinator.
fn mixStandalonePublic(channel: *P.Channel, public: Statement, program_identity: [32]u8, control: rv.control_policy.Policy) !void {
    if (control == .limbs24_v2) channel.mixU32s(&.{ 0x52563634, 0x46554c4c, 0x4354524c, 2, @intFromEnum(control) });
    try public.mix(channel, program_identity);
}

/// Expected-owner headers admit an O(1) binding check after receipt rebinding.
/// Cloned arrays still receive complete canonical content/address comparison.
pub fn validateAuthorityProgram(authority: *const ProgramAuthority, public: Rom.setup.Program) !void {
    try public.validate();
    const expected = authority.expectedProgram();
    if (public.base != expected.base or public.words.len != expected.words.len) return error.Rv64FullSetupMismatch;
    if (public.words.ptr == expected.words.ptr and public.addresses.len == expected.addresses.len and (public.addresses.len == 0 or public.addresses.ptr == expected.addresses.ptr)) return;
    if (!std.mem.eql(u32, public.words, expected.words)) return error.Rv64FullSetupMismatch;
    for (0..public.words.len) |i| if (public.pc(i) != expected.pc(i)) return error.Rv64FullSetupMismatch;
}
