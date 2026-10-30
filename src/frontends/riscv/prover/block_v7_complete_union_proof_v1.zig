//! Finite complete fresh-execution original STARK. Every original component
//! keeps its equations and physical claims; one merged fixed tree and one
//! composition/FRI authenticate all five families. One window only, CPU only.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Native = @import("block_v7_native_proof_v1.zig");
const NS = @import("block_v7_native_source_v1.zig");
const NC = @import("block_v7_native_components_v1.zig");
const Caller = @import("block_v7_caller_active_proof_v1.zig");
const CS = @import("block_v7_caller_active_source_v1.zig");
const Pair = @import("block_v7_native_caller_union_proof_v1.zig");
const Providers = @import("block_v7_complete_union_providers_v1.zig");
const Scope = @import("block_v7_complete_union_scope_v1.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const NF = @import("block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const CF = @import("block_v5_caller_fused_proof_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const MA = @import("block_v7_memory_joint_air_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
pub const Input = Scope.Input;
pub const MAPS = .{ [4]usize{ 0, 1, 2, 8 }, [5]usize{ 0, 3, 4, 9, 10 }, [3]usize{ 0, 5, 11 }, [3]usize{ 0, 6, 12 }, [3]usize{ 0, 7, 13 } };
pub const TRACE_TREES = 14;
pub const TAG: u32 = 0x42375546; // B7UF: finite complete union, never pair/old proof.
pub const VERSION: u32 = 1;
pub const Proof = struct {
    stark: S.Proof,
    native: []NF.Claim,
    access: []Memory.Claim,
    arithmetic: P.ExtensionClaim,
    relations: CF.ClaimFrames,
    program: Providers.Program.Claims,
    lookup: Providers.Lookup.Claims,
    ram: []MA.RamClaim,
    interval: [2]core.fields.qm31.QM31,
    range16: [2]core.fields.qm31.QM31,
    terminal: [1]core.fields.qm31.QM31,
    pub fn memory(self: *const Proof) MA.Claims {
        return .{ .ram = self.ram, .interval = self.interval, .range16 = self.range16, .terminal = self.terminal };
    }
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.native);
        a.free(self.access);
        a.free(self.ram);
        self.relations.deinit(a);
        self.* = undefined;
    }
};
pub const Stages = struct {
    native: *Native.For(Cpu).First,
    owner: *@import("blake3_execution_trace.zig").Owner,
    inputs: []const Memory.Input,
    caller: *Caller.ForBackend(Cpu).Stage,
    program: *@import("block_v7_program_provider_v1.zig").ForBackend(Cpu).FirstRound,
    lookup: *@import("block_v7_lookup_compact_proof_v1.zig").For(Cpu).Stage,
    memory: *@import("block_v7_memory_joint_proof_v1.zig").For(Cpu).Stage,
};
fn programPolicy(input: Input) Providers.Program.Policy {
    return .{ .plan = input.program_plan, .expected_program_root = input.program_plan.program_root, .roots = input.program_roots, .epoch = input.epoch, .entries = input.entries };
}
fn lookupPolicy(input: Input) Providers.Lookup.Policy {
    return .{ .plan = input.lookup_plan, .layout = input.lookup_layout, .roots = input.lookup_roots, .epoch = input.epoch, .entries = input.entries };
}
fn prefix(a: std.mem.Allocator, input: Input, root: [32]u8, nc: *const NC.Owner, schedule: anytype, native: []const NF.Claim, access: []const Memory.Claim, arithmetic: *const P.ExtensionClaim, relations: *const CF.ClaimFrames, rom: *const Providers.Program.Context, lookup: *const Providers.Lookup.Context, memory: *const Providers.Memory.Context) !S.Channel {
    var ch = S.Channel{};
    ch.mixU32s(&.{ TAG, VERSION, TRACE_TREES, TRACE_TREES + 1 });
    input.epoch.config.mixInto(&ch);
    ch.mixRoot(input.epoch.digest);
    ch.mixRoot(root);
    inline for (MAPS) |map| {
        ch.mixU32s(&.{map.len});
        inline for (map) |tree| ch.mixU32s(&.{tree});
    }
    try Native.recordAfterChallenges(&ch, input.native, try input.native.entry(a), nc.layout.slots, nc.slots, native, access);
    try CS.recordAfterChallenges(&ch, input.caller, try input.caller.entry(a), schedule, arithmetic, relations);
    try rom.recordAfterChallenges(&ch);
    try lookup.recordAfterChallenges(&ch);
    try memory.recordAfterChallenges(&ch);
    return ch;
}
fn fixed(a: std.mem.Allocator, input: Input, rom: *const Providers.Program.Context, lookup: *const Providers.Lookup.Context, memory: *const Providers.Memory.Context) ![]Column {
    return std.mem.concat(a, Column, &.{ try Pair.fixed(a, input.native, input.caller), rom.fixed_columns, lookup.fixed_columns, memory.fixed_columns });
}
pub fn appendPrivate(a: std.mem.Allocator, source_allocator: std.mem.Allocator, scheme: *Scheme, source: *Scheme, roots: []const [32]u8, ch: *S.Channel) !void {
    if (source.trees.items.len != roots.len or roots.len < 2) return error.InvalidCompleteUnionFirstTrees;
    for (source.trees.items, roots) |tree, root| if (!std.meta.eql(tree.root(), root)) return error.UntrustedUnionPrivateRoot;
    for (source.trees.items[1..]) |*tree| {
        try tree.share(source_allocator);
        var retained = tree.retainShared();
        scheme.appendCommittedTree(a, retained, ch) catch |err| {
            retained.deinit(source_allocator);
            return err;
        };
    }
}
pub fn prove(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, stages: Stages, pool: *engine.work_pool.WorkPool, limits: Receiver.Limits) !Proof {
    return proveWithOptions(a, trusted, input, stages, pool, limits, .{});
}
pub const Options = struct {
    /// Raw reconstruction remains the explicit oracle/fallback. Reuse changes
    /// polynomial ownership only; the merged root and transcript stay exact.
    fixed: enum { reuse_if_available, reuse_required, rebuild } = .reuse_if_available,
};
pub fn proveWithOptions(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, stages: Stages, pool: *engine.work_pool.WorkPool, limits: Receiver.Limits, options: Options) !Proof {
    const scope = try Scope.Owned.init(a, trusted, input, limits);
    defer scope.deinit();
    if (!stages.caller.first.owns_scheme or !std.meta.eql(try stages.caller.pin(0, (try input.native.entry(a)).identity).entry(a), try input.caller.entry(a))) return error.InvalidUnionCallerPhase;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const drawn = try input.epoch.draw(temp);
    const cd = try CS.draw(temp, input.epoch, try input.caller.entry(temp));
    const ni = try Pair.nativeInteractionWithScratch(temp, a, stages.native, stages.owner, stages.inputs, input.native, &drawn);
    const arithmetic = try @import("block_v7_caller_active_columns_v1.zig").interactions(temp, stages.caller.witness, &cd.relations, pool);
    const fused = try @import("block_v6_caller_joint_interaction_v1.zig").generate(temp, &stages.caller.columns, &stages.caller.schedule, stages.caller.inputs, stages.caller.first.snapshots, &cd.relations, &drawn.word);
    const nc = try NC.Owner.init(temp, input.native, ni.claims, ni.access, &drawn);
    var nb = try nc.proving();
    defer nb.deinit(temp);
    const cc = try Pair.callerOwner(true, temp, input.caller, &cd, &arithmetic.claim, &fused.claims, &stages.caller.schedule);
    const rom = try Providers.Program.prepare(Cpu, a, stages.program, programPolicy(input));
    defer rom.deinit();
    const lookup = try Providers.Lookup.prepare(Cpu, a, stages.lookup, lookupPolicy(input));
    defer lookup.deinit();
    const memory = try Providers.Memory.prepare(Cpu, stages.memory, input.epoch, input.entries);
    defer memory.deinit();
    if (!std.meta.eql(memory.roots, input.memory_roots) or memory.interval_log != input.interval_log or !std.meta.eql(try memory.policy.digest(), try scope.policy.digest())) return error.UntrustedCompleteUnionMemory;
    var combined = try @import("block_v7_heterogeneous_components_v1.zig").For(MAPS, TRACE_TREES, true).init(temp, .{ nb.handles, &.{cc.asProverComponent()}, rom.provers, lookup.provers, memory.provers }, .{ nc.fixed.len, stages.caller.schedule.fixed.len, rom.fixed_columns.len, lookup.fixed_columns.len, memory.fixed_columns.len });
    defer combined.deinit(temp);
    var scheme = try Scheme.init(a, input.epoch.config);
    var owned = true;
    defer if (owned) scheme.deinit(a);
    var ignored = S.Channel{};
    const FixedReuse = @import("block_v7_union_fixed_reuse_v1.zig");
    const fixed_sources = [_]FixedReuse.Source{
        .{ .allocator = a, .scheme = &stages.native.scheme, .expected_root = input.native.roots[0], .raw_logs = nc.fixed },
        .{ .allocator = a, .scheme = &stages.caller.first.scheme, .expected_root = input.caller.roots[0], .raw_logs = stages.caller.schedule.fixed },
        .{ .allocator = a, .scheme = &stages.program.scheme, .expected_root = input.program_roots[0], .raw_logs = rom.logs[0] },
        .{ .allocator = stages.lookup.a, .scheme = &stages.lookup.scheme, .expected_root = input.lookup_roots[0], .raw_logs = lookup.logs[0] },
        .{ .allocator = stages.memory.allocator, .scheme = &stages.memory.scheme, .expected_root = input.memory_roots[0], .raw_logs = memory.logs[0] },
    };
    const reused = options.fixed != .rebuild and try FixedReuse.tryAppend(a, &scheme, &fixed_sources, &ignored);
    if (!reused and options.fixed == .reuse_required) return error.UnionFixedReuseUnavailable;
    if (!reused) try scheme.commitBorrowedStreaming(a, try fixed(temp, input, rom, lookup, memory), 8, &ignored);
    try appendPrivate(a, a, &scheme, &stages.native.scheme, &(input.native.roots ++ .{input.native.access_root}), &ignored);
    try appendPrivate(a, a, &scheme, &stages.caller.first.scheme, &(input.caller.roots ++ .{input.caller.access_root}), &ignored);
    try appendPrivate(a, a, &scheme, &stages.program.scheme, &input.program_roots, &ignored);
    try appendPrivate(a, stages.lookup.a, &scheme, &stages.lookup.scheme, &input.lookup_roots, &ignored);
    try appendPrivate(a, stages.memory.allocator, &scheme, &stages.memory.scheme, &input.memory_roots, &ignored);
    var ch = try prefix(temp, input, scheme.trees.items[0].root(), &nc, &stages.caller.schedule, ni.claims, ni.access, &arithmetic.claim, &fused.claims, rom, lookup, memory);
    inline for (.{ ni.columns, try stages.caller.layout.columns(temp, 2, arithmetic.columns), fused.columns, rom.interaction, lookup.interaction, memory.interaction }) |columns| try scheme.commitBorrowedStreaming(a, columns, 8, &ch);
    const native = try a.dupe(NF.Claim, ni.claims);
    errdefer a.free(native);
    const access = try a.dupe(Memory.Claim, ni.access);
    errdefer a.free(access);
    const ram = try a.dupe(MA.RamClaim, memory.claims.ram);
    errdefer a.free(ram);
    var relations = try CF.ClaimFrames.clone(a, &fused.claims);
    errdefer relations.deinit(a);
    owned = false;
    const stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, combined.handles, &ch, scheme);
    return .{ .stark = stark, .native = native, .access = access, .arithmetic = arithmetic.claim, .relations = relations, .program = rom.claims, .lookup = lookup.claims, .ram = ram, .interval = memory.claims.interval, .range16 = memory.claims.range16, .terminal = memory.claims.terminal };
}
pub fn verify(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, proof: *const Proof, limits: Receiver.Limits) !Receiver.Verified {
    const scope = try Scope.Owned.init(a, trusted, input, limits);
    defer scope.deinit();
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (roots.len != 15 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, input.epoch.config)) return error.InvalidCompleteUnionShape;
    const expected = [7][32]u8{ input.native.roots[1], input.native.access_root, input.caller.roots[1], input.caller.access_root, input.program_roots[1], input.lookup_roots[1], input.memory_roots[1] };
    for (roots[1..8], expected) |actual, want| if (!std.meta.eql(actual, want)) return error.UntrustedUnionPrivateRoot;
    try @import("block_v5_native_execution_proof_v3.zig").ForBackend(Cpu).verifyFixed(a, input.native.shape, input.native.template, input.epoch.config);
    try Caller.ForBackend(Cpu).requireFixedRoot(a, input.caller);
    const rom = try Providers.Program.verifier(Cpu, a, programPolicy(input), proof.program);
    defer rom.deinit();
    const lookup = try Providers.Lookup.verifier(Cpu, a, lookupPolicy(input), proof.lookup, limits.compact_lookup);
    defer lookup.deinit();
    const memory = try Providers.Memory.verifier(Cpu, a, .{ .policy = scope.policy, .epoch = input.epoch, .entries = input.entries, .roots = input.memory_roots, .interval_log = input.interval_log, .claims = proof.memory() }, limits.joint_memory);
    defer memory.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var fs = try Scheme.init(a, input.epoch.config);
    defer fs.deinit(a);
    var ignored = S.Channel{};
    try fs.commitBorrowedStreaming(a, try fixed(temp, input, rom, lookup, memory), 8, &ignored);
    if (!std.meta.eql(roots[0], fs.trees.items[0].root())) return error.UntrustedUnionFixedRoot;
    const drawn = try input.epoch.draw(temp);
    const cd = try CS.draw(temp, input.epoch, try input.caller.entry(temp));
    const nc = try NC.Owner.init(temp, input.native, proof.native, proof.access, &drawn);
    var nb = try nc.verifying();
    defer nb.deinit(temp);
    const schedule = try @import("block_v7_caller_active_schedule_v1.zig").derive(temp, input.caller.statement, input.caller.total_steps, input.caller.frame);
    const cc = try Pair.callerOwner(false, temp, input.caller, &cd, &proof.arithmetic, &proof.relations, &schedule);
    var combined = try @import("block_v7_heterogeneous_components_v1.zig").For(MAPS, TRACE_TREES, false).init(temp, .{ nb.handles, &.{cc.asVerifierComponent()}, rom.verifiers, lookup.verifiers, memory.verifiers }, .{ nc.fixed.len, schedule.fixed.len, rom.fixed_columns.len, lookup.fixed_columns.len, memory.fixed_columns.len });
    defer combined.deinit(temp);
    var ch = try prefix(temp, input, roots[0], &nc, &schedule, proof.native, proof.access, &proof.arithmetic, &proof.relations, rom, lookup, memory);
    const logs = [14][]const u32{ try std.mem.concat(temp, u32, &.{ nc.fixed, schedule.fixed, rom.logs[0], lookup.logs[0], memory.logs[0] }), nc.main, nc.witness, cc.logs.items[1], cc.logs.items[2], rom.logs[1], lookup.logs[1], memory.logs[1], nc.interactions, cc.logs.items[3], cc.logs.items[4], rom.logs[2], lookup.logs[2], memory.logs[2] };
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, input.epoch.config);
    defer verifier.deinit(a);
    for (0..8) |i| try verifier.commit(a, roots[i], logs[i], &ignored);
    for (8..14) |i| try verifier.commit(a, roots[i], logs[i], &ch);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, combined.handles, &ch, &verifier, &proof.stark, &capture);
    defer capture.deinit(a);
    const memory_open = try @import("block_v7_memory_claim_closure_v1.zig").close(proof.memory());
    var closure = try @import("block_v7_execution_claim_closure_v1.zig").Accumulator.init(a, 1, 1, proof.program, input.program_plan.expected_fetches, proof.lookup, memory_open);
    defer closure.deinit();
    try closure.addNative(0, try NS.exportsFromClaims(temp, input.native, proof.native, proof.access, &drawn));
    try closure.addCaller(0, try CS.exports(&schedule, &proof.arithmetic, &proof.relations));
    const closed = try closure.finish();
    return .{ .statement = try scope.policy.digest(), .epoch = input.epoch.digest, .cycles = trusted.terminal.final_cycle, .segments = 1, .ram_events = closed.events, .program_fetches = closed.fetches, .output = trusted.terminal.output };
}
