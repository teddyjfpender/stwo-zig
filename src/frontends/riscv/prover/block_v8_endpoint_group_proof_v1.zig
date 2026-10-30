//! ONE bounded-group original. Wide member witnesses are committed once;
//! endpoint main roots remain individually retained for the late global bus.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Ctx = @import("block_v8_endpoint_group_context_v1.zig");
const Ledger = @import("block_v8_endpoint_group_ledger_v1.zig");
const Layout = @import("block_v8_endpoint_group_layout_v1.zig");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Base = @import("block_v8_endpoint_local_proof_v1.zig");
const Retained = @import("block_v8_endpoint_local_retained_v1.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const CallerHalt = @import("block_v8_caller_halt_component_v1.zig");
const Wire = @import("block_v7_union_claim_wire_v1.zig");
pub const production_active = false;
pub const Limits = struct { scope: Scope.Limits = .{}, context: Ctx.Limits = .{}, max_claim_bytes: usize = 64 << 20, max_claim_items: usize = 1 << 22 };
pub const Timings = struct { fixed_ns: u64 = 0, guards_ns: u64 = 0, first_commits_ns: u64 = 0, admission_ns: u64 = 0, interactions_ns: u64 = 0, preflight_ns: u64 = 0, interaction_commits_ns: u64 = 0, claim_copy_ns: u64 = 0, core_ns: u64 = 0, whole_ns: u64 = 0 };
pub const Options = struct { batch_native_projections: bool = false, program: ?*const Image.Owned = null, retain_endpoints: bool = true, max_retained_endpoint_bytes: usize = 2 << 30, timings: ?*Timings = null };
pub const Proof = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    stark: S.Proof,
    claims: Ledger.Claims,
    fixed_root: [32]u8,
    range_main_root: [32]u8,
    members: []Scope.MemberInput,
    summary: Ledger.Summary,
    endpoint_leases: []?*Retained.Owned,
    pub fn deinit(self: *Proof) void {
        const a = self.a;
        for (self.endpoint_leases) |lease| if (lease) |v| v.deinit();
        self.stark.deinit(a);
        self.arena.deinit();
        a.destroy(self);
    }
};
fn common(input: Scope.Input) @import("block_v8_endpoint_local_scope_v1.zig").Input {
    const first = input.members[0];
    return .{ .rom_flavor = input.rom_flavor, .sparse_support = input.sparse_support, .shape = first.shape, .frame = first.frame, .cohort_ordinal = first.cohort_ordinal, .endpoint_count = first.endpoint_count, .native_roots = @splat(@splat(0)), .program_plan = input.program_plan, .program_roots = input.program_roots, .lookup_plan = input.lookup_plan, .lookup_layout = input.lookup_layout, .lookup_roots = input.lookup_roots };
}
const Fixed = struct {
    a: std.mem.Allocator,
    shared: Base.StageFixed,
    columns: []Column,
    fn deinit(self: *Fixed) void {
        self.a.free(self.columns);
        self.shared.deinit();
    }
};
fn fixedForStages(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, native: []const []const Column, stages: Ctx.Stages, image: *const Image.Owned) !Fixed {
    const first = stages.members[0];
    var shared = try Base.fixedForStages(a, trusted, common(input), &.{}, .{ .native_main = first.native_main, .endpoints = first.endpoints, .endpoint_range = stages.endpoint_range, .program = stages.program, .program_allocator = stages.program_allocator, .lookup = stages.lookup }, image);
    errdefer shared.deinit();
    var list: std.ArrayList(Column) = .empty;
    errdefer list.deinit(a);
    for (native) |columns| try list.appendSlice(a, columns);
    for (stages.members) |member| try list.appendSlice(a, member.endpoints.matrix.columns[0..2]);
    // Common helper's leading endpoint prefix belongs to member0; every
    // member prefix was appended above. The remaining providers are shared.
    try list.appendSlice(a, shared.columns[2..]);
    for (stages.members) |member| if (member.caller) |caller| {
        try list.appendSlice(a, caller.fixed);
    };
    return .{ .a = a, .shared = shared, .columns = try list.toOwnedSlice(a) };
}
pub fn produce(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, native_fixed: []const []const Column, stages: Ctx.Stages, limits: Limits) !*Proof {
    return produceWithOptions(a, trusted, input, native_fixed, stages, limits, .{});
}
pub fn produceWithOptions(a: std.mem.Allocator, trusted: Scope.Trusted, proposal: Scope.Input, native_fixed: []const []const Column, source: Ctx.Stages, limits: Limits, options: Options) !*Proof {
    if (proposal.members.len == 0 or proposal.members.len != source.members.len or native_fixed.len != proposal.members.len) return error.InvalidGroupProducerRoster;
    var callers: usize = 0;
    for (proposal.members) |member| callers += @intFromBool(member.caller != null);
    const layout = try Layout.Plan.initWithProfile(proposal.members.len, callers, proposal.profile);
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var timing: Timings = .{};
    defer if (options.timings) |out| {
        timing.whole_ns = whole.read();
        out.* = timing;
    };
    var owned_image: ?Image.Owned = if (options.program == null) try Image.Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.scope.local.initial) else null;
    defer if (owned_image) |*v| v.deinit();
    const image = options.program orelse &owned_image.?;
    var scheme = try Scheme.init(a, trusted.config);
    var scheme_live = true;
    defer if (scheme_live) scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.always);
    var ignored = S.Channel{};
    var fixed = try fixedForStages(a, trusted, proposal, native_fixed, source, image);
    defer fixed.deinit();
    try scheme.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
    timing.fixed_ns = phase.lap();
    const native_guards = try a.alloc(?Halt.Owned, layout.n);
    defer a.free(native_guards);
    @memset(native_guards, null);
    defer for (native_guards) |*v| if (v.*) |*guard| guard.deinit();
    const caller_guards = try a.alloc(?Halt.Owned, layout.n);
    defer a.free(caller_guards);
    @memset(caller_guards, null);
    defer for (caller_guards) |*v| if (v.*) |*guard| guard.deinit();
    const members = try a.dupe(Scope.MemberInput, proposal.members);
    defer a.free(members);
    const stages = try a.dupe(Ctx.MemberStages, source.members);
    defer a.free(stages);
    const halt = Halt.Policy{ .halt_address = image.info.halt_flag };
    for (proposal.members, stages, 0..) |member, *stage, i| {
        const external = if (member.caller) |c| @import("blake3_ethereum_sha_profile.zig").externalCount(c.statement) else 0;
        native_guards[i] = try Halt.prepareWithExternal(a, member.shape, stage.native_main, halt, external);
        stage.native_main = native_guards[i].?.columns;
        if (member.caller != null) {
            const raw = stage.caller orelse return error.MissingGroupCallerStage;
            caller_guards[i] = try CallerHalt.prepare(a, &raw.plan, raw.fixed, raw.main, halt);
            stage.caller_main = caller_guards[i].?.columns;
        }
    }
    timing.guards_ns = phase.lap();
    for (stages) |stage| try scheme.commitBorrowedStreaming(a, stage.native_main, 8, &ignored);
    for (stages) |stage| try scheme.commitBorrowedStreaming(a, stage.endpoints.matrix.columns[2..], 8, &ignored);
    try scheme.commitBorrowedStreaming(a, source.endpoint_range.range16.columns[2..], 8, &ignored);
    const Adopt = @import("block_v7_complete_union_proof_v1.zig");
    try Adopt.appendPrivate(a, source.program_allocator, &scheme, &source.program.scheme, &proposal.program_roots, &ignored);
    try Adopt.appendPrivate(a, source.lookup.a, &scheme, &source.lookup.scheme, &proposal.lookup_roots, &ignored);
    for (stages) |stage| if (stage.caller != null) {
        try scheme.commitBorrowedStreaming(a, stage.caller_main, 8, &ignored);
    };
    if (scheme.trees.items.len != layout.firstRoots()) return error.InvalidGroupFirstTreeCount;
    const fixed_root = scheme.trees.items[0].root();
    const range_root = scheme.trees.items[layout.range()[1]].root();
    try optionalRoot(proposal.fixed_root, fixed_root);
    try optionalRoot(proposal.range_main_root, range_root);
    var caller_index: usize = 0;
    for (members, 0..) |*member, i| {
        const native_root = scheme.trees.items[layout.native(i)[1]].root();
        const endpoint_root = scheme.trees.items[layout.endpoint(i)[1]].root();
        try optionalRoot(member.native_main_root, native_root);
        try optionalRoot(member.endpoint_main_root, endpoint_root);
        member.native_main_root = native_root;
        member.endpoint_main_root = endpoint_root;
        if (member.caller) |*c| {
            const root = scheme.trees.items[layout.caller(caller_index)[1]].root();
            try optionalRoot(c.main_root, root);
            c.main_root = root;
            caller_index += 1;
        }
    }
    var input = proposal;
    input.members = members;
    input.fixed_root = fixed_root;
    input.range_main_root = range_root;
    var guarded = source;
    guarded.members = stages;
    guarded.batch_native_projections = options.batch_native_projections;
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
    const interactions = try context.interactionColumns(a);
    defer a.free(interactions);
    for (interactions) |columns| try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    if (scheme.trees.items.len != layout.traces()) return error.InvalidGroupTraceTreeCount;
    timing.interaction_commits_ns = phase.lap();
    const result = try a.create(Proof);
    errdefer a.destroy(result);
    result.a = a;
    result.arena = std.heap.ArenaAllocator.init(a);
    errdefer result.arena.deinit();
    const t = result.arena.allocator();
    var encoded = @import("bounded_artifact_writer_v1.zig").Writer.init(a, limits.max_claim_bytes);
    defer encoded.deinit();
    var count = limits.max_claim_items;
    try Wire.encode(Ledger.Claims, &encoded, context.claims, &count);
    var cursor = @import("guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = encoded.bytes.items };
    count = limits.max_claim_items;
    result.claims = try Wire.decode(Ledger.Claims, t, &cursor, &count);
    if (cursor.position != encoded.bytes.items.len) return error.InvalidGroupClaimEncoding;
    result.fixed_root = fixed_root;
    result.range_main_root = range_root;
    result.members = try t.dupe(Scope.MemberInput, members);
    for (result.members) |*member| {
        const shape = try t.create(@TypeOf(member.shape.*));
        shape.* = member.shape.*;
        shape.public_data.io_entries.input_words = &.{};
        shape.public_data.io_entries.output_words = &.{};
        member.shape = shape;
        if (member.caller) |*caller| {
            const statement = try t.create(@TypeOf(caller.statement.*));
            statement.* = caller.statement.*;
            caller.statement = statement;
        }
    }
    result.summary = summary;
    result.summary.sources = try t.dupe(@TypeOf(summary.sources[0]), summary.sources);
    result.endpoint_leases = try t.alloc(?*Retained.Owned, layout.n);
    @memset(result.endpoint_leases, null);
    errdefer for (result.endpoint_leases) |lease| if (lease) |v| v.deinit();
    var retained: usize = 0;
    if (options.retain_endpoints) for (members, result.endpoint_leases, 0..) |member, *lease, index| {
        lease.* = try Retained.Owned.acquireAt(a, &scheme, layout.endpoint(index)[1], member.endpoint_main_root, try @import("block_v8_native_endpoint_local_source_v1.zig").endpointLog(member.endpoint_count), options.max_retained_endpoint_bytes - retained);
        retained = try std.math.add(usize, retained, lease.*.?.retained_bytes);
    };
    timing.claim_copy_ns = phase.lap();
    scheme_live = false;
    result.stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, scheme);
    timing.core_ns = phase.lap();
    return result;
}
fn optionalRoot(nominated: [32]u8, actual: [32]u8) !void {
    if (!std.mem.allEqual(u8, &nominated, 0) and !std.meta.eql(nominated, actual)) return error.UntrustedGroupFirstRoot;
}
pub fn verify(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, stark: *const S.Proof, claims: Ledger.Claims, limits: Limits) !OwnedVerified {
    var captured = try verifyAndCapture(a, trusted, input, stark, claims, limits);
    const summary = captured.summary;
    // Transfer the owned source vector; the capture still owns its PCS buffers.
    captured.summary.sources = &.{};
    captured.deinit();
    return .{ .a = a, .summary = summary };
}
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(S.Hasher),
    final_channel: S.Channel,
    summary: Ledger.Summary,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.allocator.free(self.summary.sources);
        self.* = undefined;
    }
};
/// One fresh original verification. Recursive preparation can retain the exact
/// independently owned PCS capture without repeating source verification.
pub fn verifyAndCapture(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, stark: *const S.Proof, claims: Ledger.Claims, limits: Limits) !VerifiedCapture {
    const scope = try Scope.Owned.init(a, trusted, input, limits.scope);
    defer scope.deinit();
    const context = try Ctx.For(false).create(a, scope, input, null, claims, limits.context);
    defer context.deinit();
    const layout = context.layout;
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (roots.len != layout.traces() + 1 or !std.meta.eql(stark.commitment_scheme_proof.config, trusted.config) or !std.meta.eql(roots[0], input.fixed_root) or !std.meta.eql(roots[layout.range()[1]], input.range_main_root) or !std.meta.eql(roots[layout.program()[1]], input.program_roots[1]) or !std.meta.eql(roots[layout.lookup()[1]], input.lookup_roots[1])) return error.UntrustedGroupOriginalRoots;
    for (input.members, scope.member, 0..) |member, admitted, i| {
        if (!std.meta.eql(roots[layout.native(i)[1]], member.native_main_root) or !std.meta.eql(roots[layout.endpoint(i)[1]], member.endpoint_main_root)) return error.UntrustedGroupOriginalRoots;
        if (admitted.caller_index) |index| {
            if (!std.meta.eql(roots[layout.caller(index)[1]], member.caller.?.main_root)) return error.UntrustedGroupOriginalRoots;
        }
    }
    var fixed = try context.fixedColumns();
    defer fixed.deinit();
    var key = try Scheme.init(a, trusted.config);
    defer key.deinit(a);
    var ignored = S.Channel{};
    try key.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
    if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedGroupFixedRoot;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    const logs = try t.alloc([]const u32, layout.traces());
    @memset(logs, &.{});
    const fixed_logs = try t.alloc(u32, fixed.columns.len);
    for (fixed.columns, fixed_logs) |column, *log| log.* = column.log_size;
    logs[0] = fixed_logs;
    for (input.members, scope.member, context.members, 0..) |member, admitted, m, i| {
        logs[layout.native(i)[1]] = m.native.?.main;
        logs[layout.native(i)[2]] = m.native.?.interactions;
        const log = try @import("block_v8_native_endpoint_local_source_v1.zig").endpointLog(member.endpoint_count);
        logs[layout.endpoint(i)[1]] = try repeated(t, 23, log);
        logs[layout.endpoint(i)[2]] = try repeated(t, @import("block_v8_ram_endpoint_component_v1.zig").Spec.INTERACTION_COUNT, log);
        if (admitted.caller_index) |index| {
            logs[layout.caller(index)[1]] = try CallerHalt.mainLogs(t, &admitted.caller_plan.?);
            logs[layout.caller(index)[2]] = m.caller.?.arithmetic_logs;
            logs[layout.caller(index)[3]] = m.caller.?.ram_logs;
        }
    }
    logs[layout.range()[1]] = try repeated(t, 1, 16);
    logs[layout.range()[2]] = try repeated(t, 8, 16);
    logs[layout.program()[1]] = context.program.?.logs[1];
    logs[layout.program()[2]] = context.program.?.logs[2];
    logs[layout.lookup()[1]] = context.lookup.?.logs[1];
    logs[layout.lookup()[2]] = context.lookup.?.logs[2];
    var channel = try context.channel();
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, trusted.config);
    defer verifier.deinit(a);
    for (logs, 0..) |tree_logs, i| try verifier.commit(a, roots[i], tree_logs, if (i < layout.firstRoots()) &ignored else &channel);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, context.combined.?.handles, &channel, &verifier, stark, &capture);
    errdefer capture.deinit(a);
    const summary = try context.close();
    const sources = try a.dupe(@TypeOf(summary.sources[0]), summary.sources);
    return .{ .allocator = a, .proof = capture, .final_channel = channel, .summary = blk: {
        var result = summary;
        result.sources = sources;
        break :blk result;
    } };
}
pub const OwnedVerified = struct {
    a: std.mem.Allocator,
    summary: Ledger.Summary,
    pub fn deinit(self: *OwnedVerified) void {
        self.a.free(self.summary.sources);
        self.* = undefined;
    }
};
fn repeated(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
    const values = try a.alloc(u32, count);
    @memset(values, log);
    return values;
}
