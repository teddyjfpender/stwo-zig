//! Joined genesis execution prefix. This is deliberately not a cross-batch
//! or service receiver: those obligations require their own admitted roster.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const Mat = @import("setup.zig");
const P = @import("protocol.zig");
const S = @import("sources.zig");
const Components = @import("components.zig").Components;
const Memory = @import("memory/statement.zig");
const Bound = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.boundary_source;
const T = P.T;
const Recorder = @import("stwo_prover_api").stage_profile;
pub const Admission = struct {
    image: Memory.Image,
    image_identity: [32]u8,
    initial_pc: u64,
    initial_registers: [32]u64,
    max_prefix_steps: u32 = (1 << 22) - 1,
    pub fn validateCpu(self: Admission, geometry: Mat.Geometry, public: @import("stwo_riscv_frontend").rv64_air.word16_execution.types.Boundary) !void {
        if (self.max_prefix_steps == 0 or self.max_prefix_steps >= 1 << 22) return error.InvalidExecutionBudget;
        if (public.steps > self.max_prefix_steps) return error.ExecutionPrefixBudgetExceeded;
        try geometry.validate();
        try public.validate(geometry.cpu_log);
        if (public.initial_pc != self.initial_pc or !std.mem.eql(u64, &public.initial_registers, &self.initial_registers)) return error.UntrustedWord16InitialCpu;
    }
    pub fn validateCounts(geometry: Mat.Geometry, steps: u32, ls_count: u32, words: usize) !void {
        try geometry.validate();
        // This admitted path has one word event per ordinary memory opcode,
        // no services, and exactly the touched set from those events.
        if (ls_count > steps or words > ls_count or ls_count >= @as(u64, 1) << @intCast(geometry.ls_log) or words >= @as(u64, 1) << @intCast(geometry.boundary_log)) return error.InvalidExecutionMemoryCount;
    }
    pub fn validate(self: Admission, setup: *const Mat.Setup, request: P.Request) !void {
        try self.validateGeometry(setup.materials.geometry, request);
    }
    /// Cheap public admission precedes statement-specific fixed-key allocation.
    pub fn validateGeometry(self: Admission, geometry: Mat.Geometry, request: P.Request) !void {
        try self.validateCpu(geometry, request.cpu);
        try validateCounts(geometry, request.cpu.steps, request.memory.ls_count, request.memory.initial.len);
        if (request.epoch != 1 or request.memory.epoch != request.epoch) return error.UnqualifiedCrossBatchMemoryScope;
        if (request.cpu.initial_pc != self.initial_pc or !std.mem.eql(u64, &request.cpu.initial_registers, &self.initial_registers)) return error.UntrustedWord16InitialCpu;
        try request.memory.validate(self.image);
        if (request.division_requests > @as(u32, 1) << @intCast(geometry.division_log) or request.multiplication_requests > @as(u32, 1) << @intCast(geometry.multiplication_log)) return error.ArithmeticRequestCapacity;
    }
};
pub const Encoded = struct {
    bytes: []u8,
    claims: P.Claims,
    request: P.Request,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.request.memory.initial);
        a.free(self.request.memory.terminal);
        a.free(self.bytes);
        self.* = undefined;
    }
};
fn mixClaims(ch: *T.P.Channel, claims: P.Claims) void {
    ch.mixFelts(&claims.values());
}
fn validateBoundary(request: P.Request, claims: P.Claims, draw: P.Draw) !void {
    if (!claims.initial.ram.eql(try Bound.expectedClaim(request.memory.initial, true, draw.memory.ram)) or !claims.terminal.ram.eql(try Bound.expectedClaim(request.memory.terminal, false, draw.memory.ram))) return error.UntrustedWord16MemoryBoundaryClaim;
}
pub fn prove(a: std.mem.Allocator, setup: *const Mat.Setup, admission: Admission, public: @import("stwo_riscv_frontend").rv64_air.word16_execution.types.Boundary, tape: *const @import("stwo_riscv_frontend").rv64.compact_tape.Tape, recorder: ?*Recorder.Recorder) !Encoded {
    var source_stage = try Recorder.StageScope.begin(recorder, "source_construction", "One CPU and provider witness construction");
    defer source_stage.end();
    const source = try S.Source.init(a, &setup.materials, admission.image, public, 1, tape);
    source_stage.end();
    return provePrepared(a, setup, admission, source, recorder);
}
/// Consumes the prepared Source on success AND failure. Setup must stay at its
/// final stable address and outlive the entire proof; no CPU/program rebuild.
pub fn provePrepared(a: std.mem.Allocator, setup: *const Mat.Setup, admission: Admission, owned_source: S.Source, recorder: ?*Recorder.Recorder) !Encoded {
    var source = owned_source;
    defer source.deinit();
    if (source.materials != &setup.materials or source.cpu.program != &setup.materials.program) return error.PreparedSetupMismatch;
    var request = source.request();
    try admission.validate(setup, request);
    var scheme = try T.Scheme.init(a, T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = T.P.Channel{};
    try P.mix(&channel, setup, request, admission.image_identity);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    var main_stage = try Recorder.StageScope.begin(recorder, "main_commit", "Joined main streaming commitment");
    defer main_stage.end();
    try scheme.commitBorrowedStreamingWithRecorder(a, main, 8, recorder, &channel);
    main_stage.end();
    try source.releaseMain();
    const draw = P.draw(&channel);
    var generation_stage = try Recorder.StageScope.begin(recorder, "interaction_generation", "Close all seventeen component obligations");
    defer generation_stage.end();
    const claims = try source.generateProfiled(draw, recorder);
    generation_stage.end();
    // Source.memory.generate already compared both expected boundary claims.
    mixClaims(&channel, claims);
    const interaction = try source.columns(a, 2);
    defer a.free(interaction);
    var interaction_stage = try Recorder.StageScope.begin(recorder, "interaction_commit", "Joined interaction streaming commitment");
    defer interaction_stage.end();
    try scheme.commitBorrowedStreamingWithRecorder(a, interaction, 8, recorder, &channel);
    interaction_stage.end();
    source.releaseCommittedInteraction();
    var components = try Components.init(&setup.materials, request, draw, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var extended = try engine.prove.proveExWithRecorder(Backend, T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, scheme, false, recorder);
    extended.aux.deinit(a);
    var proof = extended.proof;
    defer proof.deinit(a);
    const bytes = try wire.encodeProofBytesBinary(a, proof);
    errdefer a.free(bytes);
    request.memory.initial = try a.dupe(Memory.Cell, request.memory.initial);
    errdefer a.free(request.memory.initial);
    request.memory.terminal = try a.dupe(Memory.Cell, request.memory.terminal);
    return .{ .bytes = bytes, .claims = claims, .request = request };
}
pub fn verify(a: std.mem.Allocator, setup: *const Mat.Setup, admission: Admission, encoded: Encoded) !void {
    try admission.validate(setup, encoded.request);
    try encoded.claims.validate();
    if (encoded.bytes.len > 64 * 1024 * 1024) return error.Word16ExecutionProofResourceLimit;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.InvalidWord16ExecutionProof;
    if (!std.mem.eql(u8, &pcs.commitments.items[0], &setup.fixed_root.value)) return error.UnexpectedWord16ExecutionFixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(T.P.Hasher, T.P.MerkleChannel).init(a, T.P.config());
    defer verifier.deinit(a);
    var channel = T.P.Channel{};
    try P.mix(&channel, setup, encoded.request, admission.image_identity);
    for ([_]usize{ 0, 1 }) |tree| {
        const logs = try setup.materials.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, pcs.commitments.items[tree], logs, &channel);
    }
    const draw = P.draw(&channel);
    try validateBoundary(encoded.request, encoded.claims, draw);
    mixClaims(&channel, encoded.claims);
    const logs = try setup.materials.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, pcs.commitments.items[2], logs, &channel);
    var components = try Components.init(&setup.materials, encoded.request, draw, encoded.claims);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
}
