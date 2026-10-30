//! Source-local native execution original: endpoint/range/ROM/lookup close;
//! global RAM and endpoint snapshots do NOT. Exact endpoint MAIN is retained
//! for a later independently challenged narrow bridge. This cannot publish a
//! block or complete window proof without that bridge and global RAM closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Ctx = @import("block_v8_endpoint_local_context_v1.zig");
const Ledger = @import("block_v8_endpoint_local_ledger_v1.zig");
const Placement = @import("block_v8_endpoint_local_placement_v1.zig");
const Adopt = @import("block_v7_complete_union_proof_v1.zig");
const Wire = @import("block_v7_union_claim_wire_v1.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
pub const production_active = false;
pub const Limits = struct { scope: Scope.Limits = .{}, context: Ctx.Limits = .{}, max_claim_bytes: usize = 16 << 20, max_claim_items: usize = 1 << 20 };
pub const Proof = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    stark: S.Proof,
    claims: Ledger.Claims,
    native_roots: [4][32]u8,
    summary: Ledger.Summary,
    endpoint_lease: ?*@import("block_v8_endpoint_local_retained_v1.zig").Owned = null,
    pub fn deinit(self: *Proof) void {
        const a = self.allocator;
        if (self.endpoint_lease) |lease| lease.deinit();
        self.stark.deinit(a);
        self.arena.deinit();
        a.destroy(self);
    }
};
pub const ProveTimings = struct {
    fixed_reconstruction_ns: u64 = 0,
    fixed_commitment_ns: u64 = 0,
    native_guard_preparation_ns: u64 = 0,
    native_commitment_ns: u64 = 0,
    endpoint_commitment_ns: u64 = 0,
    range_commitment_ns: u64 = 0,
    admission_ns: u64 = 0,
    private_adoption_ns: u64 = 0,
    interaction_preparation_ns: u64 = 0,
    relation_preflight_ns: u64 = 0,
    interaction_commitment_ns: u64 = 0,
    claim_copy_ns: u64 = 0,
    core_proof_ns: u64 = 0,
    cleanup_ns: u64 = 0,
    whole_ns: u64 = 0,
};
pub const ProveOptions = struct { batch_native_projections: bool = false, native_batch_options: @import("block_v8_native_projection_domain_batch_v1.zig").Options = .{}, program: ?*const @import("block_v8_endpoint_local_program_v1.zig").Owned = null, retain_endpoint: bool = true, max_retained_endpoint_bytes: usize = 2 << 30, timings: ?*ProveTimings = null, recorder: ?*engine.stage_profile.Recorder = null };
const PhaseClock = struct {
    timer: ?std.time.Timer,
    whole: ?std.time.Timer,
    output: ?*ProveTimings,
    fn init(output: ?*ProveTimings) !PhaseClock {
        if (output) |stats| stats.* = .{};
        const timer: ?std.time.Timer = if (output != null) try std.time.Timer.start() else null;
        return .{ .timer = timer, .whole = timer, .output = output };
    }
    fn mark(self: *PhaseClock, comptime field: []const u8) void {
        if (self.timer) |*timer| @field(self.output.?.*, field) = timer.lap();
    }
    fn finish(self: *PhaseClock) void {
        if (self.whole) |*timer| {
            const output = self.output.?;
            output.whole_ns = timer.read();
            var stages: u64 = 0;
            inline for (@typeInfo(ProveTimings).@"struct".fields) |field| {
                if (comptime !std.mem.eql(u8, field.name, "whole_ns") and !std.mem.eql(u8, field.name, "cleanup_ns")) stages += @field(output.*, field.name);
            }
            output.cleanup_ns = output.whole_ns - stages;
        }
    }
};
/// `input.native_roots` is an output of this first-round construction, not
/// caller authority. A nonzero proposal must match the actual committed roots.
pub fn produce(a: std.mem.Allocator, trusted: Scope.Trusted, input_value: Scope.Input, native_fixed: []const Column, stages: Ctx.Stages, limits: Limits) !*Proof {
    return produceWithOptions(a, trusted, input_value, native_fixed, stages, limits, .{});
}
pub fn produceWithOptions(a: std.mem.Allocator, trusted: Scope.Trusted, input_value: Scope.Input, native_fixed: []const Column, stages: Ctx.Stages, limits: Limits, options: ProveOptions) !*Proof {
    var clock = try PhaseClock.init(options.timings);
    defer clock.finish();
    var scheme = try Scheme.init(a, trusted.config);
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.always);
    var ignored = S.Channel{};
    var fixed = try fixedForStages(a, trusted, input_value, native_fixed, stages, options.program);
    defer fixed.deinit();
    clock.mark("fixed_reconstruction_ns");
    try scheme.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
    clock.mark("fixed_commitment_ns");
    // This policy is independently derived from the admitted ELF/window.
    // Endpoint equality alone cannot exclude an intermediate halt write.
    // Scope has not been built until first roots exist. Independently derive
    // this immutable ELF policy now, rather than accepting a caller halt word.
    var owned_program: ?@import("block_v8_endpoint_local_program_v1.zig").Owned = if (options.program == null) try @import("block_v8_endpoint_local_program_v1.zig").Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.scope.initial) else null;
    defer if (owned_program) |*image| image.deinit();
    const program_image = options.program orelse &owned_program.?;
    var guarded_native = try @import("block_v8_native_halt_policy_v1.zig").prepare(a, input_value.shape, stages.native_main, try Scope.haltFor(trusted, input_value.shape, input_value.frame, program_image.info.halt_flag));
    defer guarded_native.deinit();
    var guarded_stages = stages;
    guarded_stages.batch_native_projections = options.batch_native_projections;
    guarded_stages.native_batch_options = options.native_batch_options;
    guarded_stages.native_main = guarded_native.columns;
    var gap_stage: ?@import("block_v8_ram_clock_v3_stage.zig").Owned = null;
    defer if (gap_stage) |*value| value.deinit();
    var gap_ranges: ?@import("block_v8_ram_clock_v3_range.zig").Owned = null;
    defer if (gap_ranges) |*value| value.deinit();
    if (input_value.native_profile.isDirect()) {
        gap_stage = try @import("block_v8_ram_clock_v3_stage.zig").prepare(a, input_value.shape, guarded_native.columns);
        guarded_stages.native_main = gap_stage.?.columns;
        gap_ranges = try @import("block_v8_ram_clock_v3_range.zig").prepare(a, input_value.shape, stages.endpoint_range, guarded_stages.native_main);
        guarded_stages.endpoint_range = &gap_ranges.?.provider;
    }
    clock.mark("native_guard_preparation_ns");
    try scheme.commitBorrowedStreaming(a, guarded_stages.native_main, 8, &ignored);
    clock.mark("native_commitment_ns");
    try scheme.commitBorrowedStreaming(a, stages.endpoints.matrix.columns[2..], 8, &ignored);
    clock.mark("endpoint_commitment_ns");
    try scheme.commitBorrowedStreaming(a, guarded_stages.endpoint_range.range16.columns[2..], 8, &ignored);
    clock.mark("range_commitment_ns");
    const native_roots = [4][32]u8{ scheme.trees.items[0].root(), scheme.trees.items[1].root(), scheme.trees.items[2].root(), scheme.trees.items[3].root() };
    var input = input_value;
    const zero_proposal = std.mem.allEqual(u8, std.mem.asBytes(&input.native_roots), 0);
    if (!zero_proposal and !std.meta.eql(input.native_roots, native_roots)) return error.UntrustedEndpointFirstRoots;
    input.native_roots = native_roots;
    const scope = try Scope.Owned.initWithProgram(a, trusted, input, program_image, limits.scope);
    defer scope.deinit();
    clock.mark("admission_ns");
    // The old providers' private trees are adopted, not rebuilt. Their fixed
    // data are independently checked by the receiver's complete merged key.
    try Adopt.appendPrivate(a, stages.program_allocator, &scheme, &stages.program.scheme, &input.program_roots, &ignored);
    try Adopt.appendPrivate(a, stages.lookup.a, &scheme, &stages.lookup.scheme, &input.lookup_roots, &ignored);
    clock.mark("private_adoption_ns");
    const context = try Ctx.For(true).create(a, scope, input, guarded_stages, null, limits.context);
    defer context.deinit();
    clock.mark("interaction_preparation_ns");
    const summary = try context.close();
    var channel = try context.channel();
    clock.mark("relation_preflight_ns");
    for (try context.interactionColumns()) |columns| try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    clock.mark("interaction_commitment_ns");
    if (scheme.trees.items.len != Placement.TRACE_TREES) return error.InvalidEndpointLocalTreeCount;
    const result = try a.create(Proof);
    errdefer a.destroy(result);
    result.allocator = a;
    result.arena = std.heap.ArenaAllocator.init(a);
    errdefer result.arena.deinit();
    var encoded = Writer.init(a, limits.max_claim_bytes);
    defer encoded.deinit();
    var count = limits.max_claim_items;
    try Wire.encode(Ledger.Claims, &encoded, context.claims, &count);
    var cursor = @import("guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = encoded.bytes.items };
    count = limits.max_claim_items;
    result.claims = try Wire.decode(Ledger.Claims, result.arena.allocator(), &cursor, &count);
    if (cursor.position != encoded.bytes.items.len) return error.InvalidEndpointClaimEncoding;
    result.native_roots = native_roots;
    result.summary = summary;
    result.endpoint_lease = if (options.retain_endpoint) try @import("block_v8_endpoint_local_retained_v1.zig").Owned.acquire(a, &scheme, input.native_roots[2], try @import("block_v8_native_endpoint_local_source_v1.zig").endpointLog(input.endpoint_count), options.max_retained_endpoint_bytes) else null;
    errdefer if (result.endpoint_lease) |lease| lease.deinit();
    clock.mark("claim_copy_ns");
    owns_scheme = false;
    if (options.recorder) |recorder| {
        var proved = try engine.prove.proveExWithRecorder(Cpu, S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, scheme, false, recorder);
        proved.aux.deinit(a);
        result.stark = proved.proof;
    } else result.stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, scheme);
    clock.mark("core_proof_ns");
    return result;
}
/// Receives only proof, public metadata and external verifier policy. It
/// reconstructs every fixed column/key, verifies the original STARK, then
/// closes all authenticated local/global equations. No producer receipt used.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(S.Hasher),
    final_channel: S.Channel,
    summary: Ledger.Summary,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, stark: *const S.Proof, claims: Ledger.Claims, limits: Limits) !Ledger.Summary {
    var captured = try verifyAndCapture(a, trusted, input, stark, claims, limits);
    defer captured.deinit();
    return captured.summary;
}
/// The original is freshly verified exactly once. Recursive preparation may
/// retain this independently owned capture; it does not retain source rows or
/// accept a producer receipt as authority. Claims/metadata remain caller-owned.
pub fn verifyAndCapture(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, stark: *const S.Proof, claims: Ledger.Claims, limits: Limits) !VerifiedCapture {
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (roots.len != Placement.TRACE_TREES + 1 or !std.meta.eql(stark.commitment_scheme_proof.config, trusted.config) or
        !std.meta.eql(roots[0..4].*, input.native_roots) or !std.meta.eql(roots[4], input.program_roots[1]) or
        !std.meta.eql(roots[5], input.lookup_roots[1]))
        return error.UntrustedEndpointLocalProofRoots;
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
    if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedEndpointLocalFixedRoot;
    var channel = try context.channel();
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, trusted.config);
    defer verifier.deinit(a);
    const fixed_logs = try a.alloc(u32, fixed.columns.len);
    defer a.free(fixed_logs);
    for (fixed.columns, fixed_logs) |column, *log| log.* = column.log_size;
    const local = context.local.?;
    const logs = [Placement.TRACE_TREES][]const u32{ fixed_logs, local.native.main, &local.endpoint_main_logs, &local.range_main_logs, context.program.?.logs[1], context.lookup.?.logs[1], local.native.interactions, &local.endpoint_interaction_logs, &local.range_interaction_logs, context.program.?.logs[2], context.lookup.?.logs[2] };
    for (logs, 0..) |tree_logs, tree| try verifier.commit(a, roots[tree], tree_logs, if (tree < 6) &ignored else &channel);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, &verifier, stark, &capture);
    errdefer capture.deinit(a);
    const summary = try context.close();
    return .{ .allocator = a, .proof = capture, .final_channel = channel, .summary = summary };
}
pub const StageFixed = struct {
    a: std.mem.Allocator,
    columns: []Column,
    rom: []Column,
    pub fn deinit(self: *StageFixed) void {
        for (self.rom) |column| self.a.free(column.values);
        self.a.free(self.rom);
        self.a.free(self.columns);
    }
};
pub fn fixedForStages(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, native: []const Column, stages: Ctx.Stages, image: ?*const @import("block_v8_endpoint_local_program_v1.zig").Owned) !StageFixed {
    var columns: std.ArrayList(Column) = .empty;
    errdefer columns.deinit(a);
    try columns.appendSlice(a, native);
    try columns.appendSlice(a, stages.endpoints.matrix.columns[0..2]);
    try columns.appendSlice(a, stages.endpoint_range.range16.columns[0..2]);
    const rom_values = if (input.rom_flavor == .legacy_complete) try input.program_plan.fixedColumns(a) else blk: {
        const Sparse = @import("block_v8_sparse_rom_v1.zig");
        const policy = Sparse.Trusted{ .elf = trusted.elf, .elf_sha256 = trusted.elf_sha256, .profile = trusted.profile, .program_root = input.program_plan.program_root, .expected_fetches = input.program_plan.expected_fetches };
        var plan = if (image) |owned| try Sparse.Owned.fromImage(a, policy, input.sparse_support, owned, .{}) else try Sparse.Owned.derive(a, policy, input.sparse_support, .{});
        defer plan.deinit();
        if (plan.log_size != input.program_plan.log_size or input.program_plan.leaves.len != 0 or input.program_plan.multiplicities.len != 0) return error.UntrustedSparseLocalDescriptor;
        const columns_fixed = try plan.fixedColumns(a);
        var values: [6][]@import("stwo_core").fields.m31.M31 = undefined;
        for (columns_fixed, &values) |column, *value| value.* = @constCast(column.values);
        break :blk values;
    };
    errdefer for (rom_values) |values| a.free(values);
    const rom = try a.alloc(Column, rom_values.len);
    errdefer a.free(rom);
    for (rom, rom_values) |*column, values| column.* = .{ .log_size = input.program_plan.log_size, .values = values };
    try columns.appendSlice(a, rom);
    for (stages.lookup.fixed) |matrix| try columns.appendSlice(a, matrix.columns);
    return .{ .a = a, .columns = try columns.toOwnedSlice(a), .rom = rom };
}
