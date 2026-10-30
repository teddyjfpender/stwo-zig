//! One original over native execution, actual precompile arithmetic and both
//! RAM projections. Only endpoint-global RAM remains open. No WORD sidecar,
//! duplicated native companion proof, or host success receipt is accepted.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const Scope = @import("block_v8_endpoint_mixed_scope_v1.zig");
const Ctx = @import("block_v8_endpoint_mixed_context_v1.zig");
const Ledger = @import("block_v8_endpoint_mixed_ledger_v1.zig");
const Base = @import("block_v8_endpoint_local_proof_v1.zig");
const Wire = @import("block_v7_union_claim_wire_v1.zig");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Retained = @import("block_v8_endpoint_local_retained_v1.zig");
pub const production_active = false;
pub const Limits = struct { scope: Scope.Limits = .{}, context: Ctx.Limits = .{}, max_claim_bytes: usize = 32 << 20, max_claim_items: usize = 1 << 21 };
pub const Timings = struct { fixed_ns: u64 = 0, guards_ns: u64 = 0, first_commits_ns: u64 = 0, admission_ns: u64 = 0, interactions_ns: u64 = 0, preflight_ns: u64 = 0, interaction_commits_ns: u64 = 0, claim_copy_ns: u64 = 0, core_ns: u64 = 0, whole_ns: u64 = 0 };
pub const Options = struct { batch_native_projections: bool = false, program: ?*const Image.Owned = null, retain_endpoint: bool = true, max_retained_endpoint_bytes: usize = 2 << 30, timings: ?*Timings = null, recorder: ?*engine.stage_profile.Recorder = null };
pub const Proof = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    stark: S.Proof,
    claims: Ledger.Claims,
    native_roots: [4][32]u8,
    caller_roots: [2][32]u8,
    summary: Ledger.Summary,
    endpoint_lease: ?*Retained.Owned = null,
    pub fn deinit(self: *Proof) void {
        const a = self.allocator;
        if (self.endpoint_lease) |lease| lease.deinit();
        self.stark.deinit(a);
        self.arena.deinit();
        a.destroy(self);
    }
};
fn commonInput(input: Scope.Input) @import("block_v8_endpoint_local_scope_v1.zig").Input {
    return .{ .rom_flavor = input.rom_flavor, .sparse_support = input.sparse_support, .shape = input.shape, .frame = input.frame, .cohort_ordinal = input.cohort_ordinal, .endpoint_count = input.endpoint_count, .native_roots = input.native_roots, .program_plan = input.program_plan, .program_roots = input.program_roots, .lookup_plan = input.lookup_plan, .lookup_layout = input.lookup_layout, .lookup_roots = input.lookup_roots };
}
const FirstFixed = struct {
    a: std.mem.Allocator,
    shared: Base.StageFixed,
    columns: []Column,
    fn deinit(self: *FirstFixed) void {
        self.a.free(self.columns);
        self.shared.deinit();
    }
};
fn fixedForStages(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, native: []const Column, stages: Ctx.Stages, image: *const Image.Owned) !FirstFixed {
    var shared = try Base.fixedForStages(a, trusted, commonInput(input), native, .{ .native_main = stages.native_main, .endpoints = stages.endpoints, .endpoint_range = stages.endpoint_range, .program = stages.program, .program_allocator = stages.program_allocator, .lookup = stages.lookup }, image);
    errdefer shared.deinit();
    const columns = try std.mem.concat(a, Column, &.{ shared.columns, stages.caller.fixed });
    return .{ .a = a, .shared = shared, .columns = columns };
}
pub fn produce(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, native_fixed: []const Column, stages: Ctx.Stages, limits: Limits) !*Proof {
    return produceWithOptions(a, trusted, input, native_fixed, stages, limits, .{});
}
pub fn produceWithOptions(a: std.mem.Allocator, trusted: Scope.Trusted, input_value: Scope.Input, native_fixed: []const Column, stages: Ctx.Stages, limits: Limits, options: Options) !*Proof {
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var timing: Timings = .{};
    defer if (options.timings) |out| {
        timing.whole_ns = whole.read();
        out.* = timing;
    };
    var owned_image: ?Image.Owned = if (options.program == null) try Image.Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.scope.local.initial) else null;
    defer if (owned_image) |*image| image.deinit();
    const image = options.program orelse &owned_image.?;
    var scheme = try Scheme.init(a, trusted.config);
    var scheme_live = true;
    defer if (scheme_live) scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.always);
    var ignored = S.Channel{};
    var fixed = try fixedForStages(a, trusted, input_value, native_fixed, stages, image);
    defer fixed.deinit();
    try scheme.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
    timing.fixed_ns = phase.lap();
    const halt = try @import("block_v8_endpoint_local_scope_v1.zig").haltFor(trusted, input_value.shape, input_value.frame, image.info.halt_flag);
    const external = @import("blake3_ethereum_sha_profile.zig").externalCount(input_value.caller_statement);
    var native = try @import("block_v8_native_halt_policy_v1.zig").prepareWithExternal(a, input_value.shape, stages.native_main, halt, external);
    defer native.deinit();
    var caller = try @import("block_v8_caller_halt_component_v1.zig").prepare(a, &stages.caller.plan, stages.caller.fixed, stages.caller.main, .{ .halt_address = halt.halt_address });
    defer caller.deinit();
    var guarded = stages;
    guarded.batch_native_projections = options.batch_native_projections;
    guarded.native_main = native.columns;
    guarded.caller_main = caller.columns;
    timing.guards_ns = phase.lap();
    try scheme.commitBorrowedStreaming(a, guarded.native_main, 8, &ignored);
    try scheme.commitBorrowedStreaming(a, stages.endpoints.matrix.columns[2..], 8, &ignored);
    try scheme.commitBorrowedStreaming(a, stages.endpoint_range.range16.columns[2..], 8, &ignored);
    const Adopt = @import("block_v7_complete_union_proof_v1.zig");
    try Adopt.appendPrivate(a, stages.program_allocator, &scheme, &stages.program.scheme, &input_value.program_roots, &ignored);
    try Adopt.appendPrivate(a, stages.lookup.a, &scheme, &stages.lookup.scheme, &input_value.lookup_roots, &ignored);
    try scheme.commitBorrowedStreaming(a, guarded.caller_main, 8, &ignored);
    if (scheme.trees.items.len != 7) return error.InvalidMixedFirstTreeCount;
    var input = input_value;
    const roots = [4][32]u8{ scheme.trees.items[0].root(), scheme.trees.items[1].root(), scheme.trees.items[2].root(), scheme.trees.items[3].root() };
    const caller_roots = [2][32]u8{ roots[0], scheme.trees.items[6].root() };
    if (!std.mem.allEqual(u8, std.mem.asBytes(&input.native_roots), 0) and !std.meta.eql(input.native_roots, roots)) return error.UntrustedMixedNativeRoots;
    if (!std.mem.allEqual(u8, std.mem.asBytes(&input.caller_roots), 0) and !std.meta.eql(input.caller_roots, caller_roots)) return error.UntrustedMixedCallerRoots;
    input.native_roots = roots;
    input.caller_roots = caller_roots;
    timing.first_commits_ns = phase.lap();
    const scope = try Scope.Owned.initWithProgram(a, trusted, input, image, limits.scope);
    defer scope.deinit();
    timing.admission_ns = phase.lap();
    const context = try Ctx.For(true).create(a, scope, input, guarded, null, limits.context);
    defer context.deinit();
    timing.interactions_ns = phase.lap();
    const summary = try context.close();
    var channel = try context.channel();
    timing.preflight_ns = phase.lap();
    for (try context.interactionColumns()) |columns| try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    if (scheme.trees.items.len != Ctx.TRACE_TREES) return error.InvalidMixedTraceTreeCount;
    timing.interaction_commits_ns = phase.lap();
    const result = try a.create(Proof);
    errdefer a.destroy(result);
    result.allocator = a;
    result.arena = std.heap.ArenaAllocator.init(a);
    errdefer result.arena.deinit();
    var encoded = @import("bounded_artifact_writer_v1.zig").Writer.init(a, limits.max_claim_bytes);
    defer encoded.deinit();
    var count = limits.max_claim_items;
    try Wire.encode(Ledger.Claims, &encoded, context.claims, &count);
    var cursor = @import("guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = encoded.bytes.items };
    count = limits.max_claim_items;
    result.claims = try Wire.decode(Ledger.Claims, result.arena.allocator(), &cursor, &count);
    if (cursor.position != encoded.bytes.items.len) return error.InvalidMixedClaimsEncoding;
    result.native_roots = roots;
    result.caller_roots = caller_roots;
    result.summary = summary;
    result.endpoint_lease = if (options.retain_endpoint) try Retained.Owned.acquire(a, &scheme, roots[2], try @import("block_v8_native_endpoint_local_source_v1.zig").endpointLog(input.endpoint_count), options.max_retained_endpoint_bytes) else null;
    errdefer if (result.endpoint_lease) |lease| lease.deinit();
    timing.claim_copy_ns = phase.lap();
    scheme_live = false;
    if (options.recorder) |recorder| {
        var proved = try engine.prove.proveExWithRecorder(Cpu, S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, scheme, false, recorder);
        proved.aux.deinit(a);
        result.stark = proved.proof;
    } else result.stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, scheme);
    timing.core_ns = phase.lap();
    return result;
}
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(S.Hasher),
    final_channel: S.Channel,
    summary: Ledger.Summary,
    pub fn deinit(self: *@This()) void {
        self.proof.deinit(self.allocator);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, stark: *const S.Proof, claims: Ledger.Claims, limits: Limits) !Ledger.Summary {
    var capture = try verifyAndCapture(a, trusted, input, stark, claims, limits);
    defer capture.deinit();
    return capture.summary;
}
pub fn verifyAndCapture(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, stark: *const S.Proof, claims: Ledger.Claims, limits: Limits) !VerifiedCapture {
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (roots.len != Ctx.TRACE_TREES + 1 or !std.meta.eql(stark.commitment_scheme_proof.config, trusted.config) or !std.meta.eql(roots[0..4].*, input.native_roots) or !std.meta.eql(roots[4], input.program_roots[1]) or !std.meta.eql(roots[5], input.lookup_roots[1]) or !std.meta.eql(roots[6], input.caller_roots[1])) return error.UntrustedMixedOriginalRoots;
    const scope = try Scope.Owned.init(a, trusted, input, limits.scope);
    defer scope.deinit();
    const context = try Ctx.For(false).create(a, scope, input, null, claims, limits.context);
    defer context.deinit();
    var fixed = try context.fixedColumns();
    defer fixed.deinit();
    var key = try Scheme.init(a, trusted.config);
    defer key.deinit(a);
    var ignored = S.Channel{};
    try key.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
    if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedMixedFixedRoot;
    var channel = try context.channel();
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, trusted.config);
    defer verifier.deinit(a);
    const fixed_logs = try a.alloc(u32, fixed.columns.len);
    defer a.free(fixed_logs);
    for (fixed.columns, fixed_logs) |column, *log| log.* = column.log_size;
    const native = context.native.?;
    const endpoint_log = try @import("block_v8_native_endpoint_local_source_v1.zig").endpointLog(input.endpoint_count);
    const ep_main = [_]u32{endpoint_log} ** @import("block_v8_ram_endpoint_component_v1.zig").Spec.MAIN_COUNT;
    const ep_i = [_]u32{endpoint_log} ** @import("block_v8_ram_endpoint_component_v1.zig").Spec.INTERACTION_COUNT;
    const range_main = [_]u32{16} ** @import("block_v8_endpoint_range_provider_v1.zig").Spec.MAIN_COUNT;
    const range_i = [_]u32{16} ** @import("block_v8_endpoint_range_provider_v1.zig").Spec.INTERACTION_COUNT;
    const caller_logs = try @import("block_v8_caller_halt_component_v1.zig").mainLogs(a, &scope.caller_plan);
    defer a.free(caller_logs);
    const logs = [Ctx.TRACE_TREES][]const u32{ fixed_logs, native.main, &ep_main, &range_main, context.program.?.logs[1], context.lookup.?.logs[1], caller_logs, native.interactions, &ep_i, &range_i, context.program.?.logs[2], context.lookup.?.logs[2], context.caller.?.arithmetic_logs, context.caller.?.ram_logs };
    for (logs, 0..) |tree_logs, tree| try verifier.commit(a, roots[tree], tree_logs, if (tree < 7) &ignored else &channel);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, &verifier, stark, &capture);
    errdefer capture.deinit(a);
    return .{ .allocator = a, .proof = capture, .final_channel = channel, .summary = try context.close() };
}
