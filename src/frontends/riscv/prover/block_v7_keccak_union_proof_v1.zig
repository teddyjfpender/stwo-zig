//! Finite shared-Keccak execution union. Original native, batch and provider
//! equations share one STARK; every original physical claim remains transcript
//! bound and per-window ownership/global RAM closure remain mandatory.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Scope = @import("block_v7_keccak_union_scope_v1.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Native = @import("block_v7_native_proof_v1.zig");
const NS = @import("block_v7_native_source_v1.zig");
const NC = @import("block_v7_native_components_v1.zig");
const Caller = @import("block_v7_caller_active_proof_v1.zig");
const BatchSource = @import("block_v7_keccak_batch_source_v1.zig");
const BatchProof = @import("block_v7_keccak_batch_proof_v1.zig");
const BatchGeometry = @import("block_v7_keccak_batch_geometry_v1.zig");
const BatchAir = @import("block_v7_keccak_batch_air_v1.zig");
const Prepared = @import("block_v7_keccak_batch_preparation_v1.zig").ForBackend(Cpu);
const Pair = @import("block_v7_native_caller_union_proof_v1.zig");
const Single = @import("block_v7_complete_union_proof_v1.zig");
const Providers = @import("block_v7_complete_union_providers_v1.zig");
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
const CF = @import("block_v5_caller_fused_proof_v1.zig");
const NF = @import("block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const MA = @import("block_v7_memory_joint_air_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const CC = @import("block_v6_caller_joint_components_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Column = engine.pcs.ColumnEvaluation;
const StageScope = engine.stage_profile.StageScope;
const Recorder = engine.stage_profile.Recorder;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
pub const Input = Scope.Input;
pub const Limits = Scope.Limits;
const NativeCache = @import("block_v7_shared_quotient_cache_v1.zig");
pub const ProducerStats = struct {
    native_cache_recovered_columns: usize = 0,
    native_cache_reused_columns: usize = 0,
    native_cache_retained_bytes: usize = 0,
    native_cache_requested_columns: usize = 0,
    native_cache_passthrough_columns: usize = 0,
    native_cache_capacity_misses: usize = 0,
    native_cache_evicted_columns: usize = 0,
    retained_pcs_model_bytes: u64 = 0,
    compact_storage_admission: bool = false,
    memory_allocator_live_after_preparation: usize = 0,
    memory_allocator_live_after_commit: usize = 0,
    memory_allocator_live_after_consumption: usize = 0,
    union_allocator_live_before_proof: ?usize = null,
    union_allocator_live_at_entry: ?usize = null,
    union_allocator_live_at_exit: ?usize = null,
    /// Cumulative allocator high-water mark, including work before this call.
    /// This is neither process RSS nor the incremental peak of this phase.
    union_allocator_peak_cumulative: ?usize = null,
};
pub const ProveOptions = struct {
    quotient_executor: ?*const engine.pcs.QuotientExecutor = null,
    /// One shared cap across every native window, not a per-window allowance.
    /// Zero selects the original uncached evaluator for exact A/B qualification.
    native_main_cache_bytes: usize = NativeCache.DEFAULT_RETAINED_BYTES,
    /// Charged bounded DEEP grouping metadata; affects implementation only.
    deep_group_budget: engine.pcs.DeepGroupBudget = .one_mib,
    consume_memory_producer: bool = false,
    /// Explicit producer resource model. Requires a hard budget allocator and
    /// checks actual first-round representations before preparing interactions.
    /// Never changes verifier limits, transcript or statement admission.
    compact_storage_admission: bool = false,
    stats: ?*ProducerStats = null,
    /// Borrowed hierarchical recorder; null preserves ordinary proving. The
    /// inclusive multi_prove node nests under any active caller stage. Sum
    /// children or their parent, never both. Caller snapshots after return.
    recorder: ?*Recorder = null,
};
pub const TAG: u32 = 0x42374b55; // B7KU
pub const VERSION: u32 = 1;
pub const NativeStage = struct { allocator: std.mem.Allocator, first: *Native.For(Cpu).First, owner: *@import("blake3_execution_trace.zig").Owner, inputs: []const Memory.Input };
pub const Stages = struct { natives: []const NativeStage, batches: []const *BatchProof.ForBackend(Cpu).Stage, program: *@import("block_v7_program_provider_v1.zig").ForBackend(Cpu).FirstRound, program_allocator: std.mem.Allocator, lookup: *@import("block_v7_lookup_compact_proof_v1.zig").For(Cpu).Stage, memory: *@import("block_v7_memory_joint_proof_v1.zig").For(Cpu).Stage };
pub const NativeClaims = struct { claims: []NF.Claim, access: []Memory.Claim };
pub const CallerClaims = BatchProof.Claims;
pub const Claims = struct {
    native: []NativeClaims,
    batches: []CallerClaims,
    program: Providers.Program.Claims,
    lookup: Providers.Lookup.Claims,
    ram: []MA.RamClaim,
    interval: [2]core.fields.qm31.QM31,
    range16: [2]core.fields.qm31.QM31,
    terminal: [1]core.fields.qm31.QM31,
    pub fn memory(self: Claims) MA.Claims {
        return .{ .ram = self.ram, .interval = self.interval, .range16 = self.range16, .terminal = self.terminal };
    }
};
pub const Proof = struct {
    stark: S.Proof,
    claims: Claims,
    claims_arena: std.heap.ArenaAllocator,
    pub fn view(self: *const Proof) ProofView {
        return .{ .stark = self.stark, .claims = self.claims };
    }
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.claims_arena.deinit();
        self.* = undefined;
    }
};
/// Immutable verifier view. No deinit/ownership API: the original producer or
/// bounded wire decoder retains the underlying storage for the whole call.
pub const ProofView = struct { stark: S.Proof, claims: Claims };
fn programPolicy(input: Input) Providers.Program.Policy {
    return .{ .plan = input.program_plan, .expected_program_root = input.program_plan.program_root, .roots = input.program_roots, .epoch = input.epoch, .entries = input.entries };
}
fn lookupPolicy(input: Input) Providers.Lookup.Policy {
    return .{ .plan = input.lookup_plan, .layout = input.lookup_layout, .roots = input.lookup_roots, .epoch = input.epoch, .entries = input.entries };
}
fn Context(comptime proving: bool) type {
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    const Placed = Placement.Dynamic(proving);
    const N = struct { values: Pair.NativeInteraction, component: NC.Owner, handles: []H };
    const C = struct {
        drawn: BatchSource.Drawn,
        geometry: BatchGeometry.Owned,
        values: BatchProof.Claims,
        arithmetic_columns: []Column,
        relation_columns: []Column,
        component: *BatchAir.Owner(proving),
        prepared: ?*Prepared = null,
        handles: [1]H,
    };
    return struct {
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        scope: *const Scope.Owned,
        input: Input,
        drawn: E.Drawn,
        natives: []N,
        batches: []C,
        program: ?*Providers.Program.Context = null,
        lookup: ?*Providers.Lookup.Context = null,
        memory: ?*Providers.Memory.Context = null,
        combined: ?Placed = null,
        const Self = @This();
        fn create(a: std.mem.Allocator, scope: *const Scope.Owned, input: Input, stages: ?Stages, proof: ?*const ProofView, limits: Limits, recorder: ?*Recorder) !*Self {
            var preparation_scope = try StageScope.begin(recorder, "keccak_union_context_preparation", "Interaction generation and component preparation");
            defer preparation_scope.end();
            const self = try a.create(Self);
            self.* = .{ .allocator = a, .arena = std.heap.ArenaAllocator.init(a), .scope = scope, .input = input, .drawn = undefined, .natives = &.{}, .batches = &.{} };
            errdefer self.deinit();
            const t = self.arena.allocator();
            {
                var phase = try StageScope.begin(recorder, "keccak_union_epoch_draw", "Epoch challenge derivation");
                defer phase.end();
                self.drawn = try input.epoch.draw(t);
            }
            if (proving) {
                if (stages.?.natives.len != input.natives.len or stages.?.batches.len != input.batches.len) return error.InvalidMultiUnionStages;
            } else {
                if (proof.?.claims.native.len != input.natives.len or proof.?.claims.batches.len != input.batches.len or proof.?.claims.ram.len != input.memory_geometry.len) return error.InvalidMultiUnionClaims;
                for (proof.?.claims.ram, input.memory_geometry) |claim, g| if (!std.meta.eql(claim.geometry, g)) return error.UntrustedMultiUnionMemoryGeometry;
            }
            self.natives = try t.alloc(N, input.natives.len);
            self.batches = try t.alloc(C, input.batches.len);
            for (self.batches) |*c| c.prepared = null;
            const parts = try t.alloc(Placed.Part, scope.sources.len);
            for (self.natives, input.natives, 0..) |*n, pin, i| {
                var phase = try StageScope.begin(recorder, "keccak_union_native_preparation", "Native interactions and component preparation");
                defer phase.end();
                if (proving) {
                    const st = stages.?.natives[i];
                    n.values = try Pair.nativeInteractionWithScratch(t, a, st.first, st.owner, st.inputs, pin, &self.drawn);
                } else {
                    try @import("block_v5_native_execution_proof_v3.zig").ForBackend(Cpu).verifyFixed(a, pin.shape, pin.template, input.epoch.config);
                    n.values = .{ .claims = proof.?.claims.native[i].claims, .access = proof.?.claims.native[i].access, .columns = &.{} };
                }
                n.component = try NC.Owner.init(t, pin, n.values.claims, n.values.access, &self.drawn);
                const owner = if (proving) try n.component.proving() else try n.component.verifying();
                n.handles = owner.handles;
                parts[i] = .{ .map = scope.placement.parts[i].mapping(), .handles = n.handles, .fixed_count = n.component.fixed.len };
            }
            for (self.batches, input.batches, 0..) |*c, pin, i| {
                const at = input.natives.len + i;
                c.geometry = try BatchGeometry.Owned.init(t, pin, limits.batch.owners);
                if (proving) {
                    const st = stages.?.batches[i];
                    if (!std.meta.eql(try st.pin.entry(t, input.natives, limits.batch.owners), scope.sources[at].entry)) return error.InvalidKeccakUnionBatchStage;
                    c.prepared = try Prepared.init(t, st, input.natives, input.epoch, input.entries, engine.work_pool.currentScopedPool() orelse return error.MissingWorkPool);
                    c.drawn = c.prepared.?.drawn;
                    c.values = c.prepared.?.claims;
                    c.arithmetic_columns = c.prepared.?.arithmetic_columns;
                    c.relation_columns = c.prepared.?.relation_columns;
                    c.component = c.prepared.?.owner;
                } else {
                    try BatchProof.ForBackend(Cpu).requireFixedRoot(a, pin, &c.geometry);
                    c.drawn = try BatchSource.draw(t, input.epoch, scope.sources[at].entry);
                    c.values = proof.?.claims.batches[i];
                    c.arithmetic_columns = &.{};
                    c.relation_columns = &.{};
                    c.component = try BatchAir.Owner(false).init(t, pin, &c.geometry, &c.drawn, &c.values);
                }
                c.handles = .{if (proving) c.component.joint.asProverComponent() else c.component.joint.asVerifierComponent()};
                parts[at] = .{ .map = scope.placement.parts[at].mapping(), .handles = &c.handles, .fixed_count = c.geometry.logs[0].len };
            }
            {
                var phase = try StageScope.begin(recorder, "keccak_union_program_preparation", "Program interactions and component preparation");
                defer phase.end();
                self.program = if (proving) try Providers.Program.prepare(Cpu, a, stages.?.program, programPolicy(input)) else try Providers.Program.verifier(Cpu, a, programPolicy(input), proof.?.claims.program);
            }
            {
                var phase = try StageScope.begin(recorder, "keccak_union_lookup_preparation", "Lookup interactions and component preparation");
                defer phase.end();
                self.lookup = if (proving) try Providers.Lookup.prepare(Cpu, a, stages.?.lookup, lookupPolicy(input)) else try Providers.Lookup.verifier(Cpu, a, lookupPolicy(input), proof.?.claims.lookup, limits.receiver.compact_lookup);
            }
            {
                var phase = try StageScope.begin(recorder, "keccak_union_memory_preparation", "Memory interactions and component preparation");
                defer phase.end();
                self.memory = if (proving) try Providers.Memory.prepare(Cpu, stages.?.memory, input.epoch, input.entries) else try Providers.Memory.verifier(Cpu, a, .{ .policy = scope.policy, .epoch = input.epoch, .entries = input.entries, .roots = input.memory_roots, .interval_log = input.interval_log, .claims = proof.?.claims.memory() }, limits.receiver.joint_memory);
            }
            const m = self.memory.?;
            if (!std.meta.eql(m.roots, input.memory_roots) or m.interval_log != input.interval_log or m.claims.ram.len != input.memory_geometry.len or !std.meta.eql(try m.policy.digest(), try scope.policy.digest())) return error.UntrustedMultiUnionMemory;
            for (m.claims.ram, input.memory_geometry) |claim, g| if (!std.meta.eql(claim.geometry, g)) return error.UntrustedMultiUnionMemoryGeometry;
            inline for (.{ self.program.?, self.lookup.?, self.memory.? }, 0..) |provider, i| {
                const at = input.natives.len + input.batches.len + i;
                parts[at] = .{ .map = scope.placement.parts[at].mapping(), .handles = if (proving) provider.provers else provider.verifiers, .fixed_count = provider.fixed_columns.len };
                for (provider.logs, scope.sources[at].logs[0..3]) |actual, expected| if (!std.mem.eql(u32, actual, expected)) return error.UntrustedMultiUnionProviderGeometry;
            }
            {
                var phase = try StageScope.begin(recorder, "keccak_union_component_placement", "Component placement");
                defer phase.end();
                self.combined = try Placed.init(t, parts, scope.placement.trace_trees);
            }
            return self;
        }
        fn deinit(self: *Self) void {
            const a = self.allocator;
            if (proving) for (self.batches) |c| if (c.prepared) |prepared| prepared.deinit();
            if (self.memory) |p| p.deinit();
            if (self.lookup) |p| p.deinit();
            if (self.program) |p| p.deinit();
            self.arena.deinit();
            a.destroy(self);
        }
        fn fixed(self: *Self) ![]Column {
            const t = self.arena.allocator();
            var result: std.ArrayList(Column) = .empty;
            for (self.input.natives, self.scope.sources[0..self.input.natives.len]) |pin, source| {
                const start = result.items.len;
                const Frame = @import("block_v5_native_frame_v1.zig");
                if (Frame.required(pin.shape)) {
                    _ = try Frame.expected(pin.shape, pin.template.external_retirements);
                    try result.appendSlice(t, try Frame.fixedColumns(t));
                } else try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(t, pin.shape, pin.template.external_retirements, &result);
                const columns = result.items[start..];
                if (columns.len != source.logs[0].len) return error.UntrustedMultiUnionFixedGeometry;
                for (columns, source.logs[0]) |column, log| if (column.log_size != log) return error.UntrustedMultiUnionFixedGeometry;
            }
            for (self.batches) |c| try result.appendSlice(t, try c.geometry.fixed(t));
            inline for (.{ self.program.?, self.lookup.?, self.memory.? }) |p| try result.appendSlice(t, p.fixed_columns);
            return result.toOwnedSlice(t);
        }
        fn channel(self: *Self, root: [32]u8) !S.Channel {
            var ch = S.Channel{};
            ch.mixU32s(&.{ TAG, VERSION, @intCast(self.scope.placement.trace_trees), @intCast(self.scope.sources.len) });
            self.input.epoch.config.mixInto(&ch);
            ch.mixRoot(self.input.epoch.digest);
            ch.mixRoot(root);
            for (self.scope.placement.parts) |part| {
                ch.mixU32s(&.{ @intFromEnum(part.source.family), part.source.index, part.source.root_count, part.source_trees });
                for (part.mapping()) |index| ch.mixU32s(&.{@intCast(index)});
            }
            for (self.natives, self.input.natives, 0..) |*n, pin, i| try Native.recordAfterChallenges(&ch, pin, self.scope.sources[i].entry, n.component.layout.slots, n.component.slots, n.values.claims, n.values.access);
            for (self.batches, self.input.batches, 0..) |*c, pin, i| try c.values.record(pin, self.scope.sources[self.natives.len + i].entry, &ch);
            try self.program.?.recordAfterChallenges(&ch);
            try self.lookup.?.recordAfterChallenges(&ch);
            try self.memory.?.recordAfterChallenges(&ch);
            return ch;
        }
        fn cloneClaims(self: *Self, a: std.mem.Allocator) !Claims {
            const native = try a.alloc(NativeClaims, self.natives.len);
            for (native, self.natives) |*out, n| out.* = .{ .claims = try a.dupe(NF.Claim, n.values.claims), .access = try a.dupe(Memory.Claim, n.values.access) };
            const batches = try a.alloc(CallerClaims, self.batches.len);
            for (batches, self.batches) |*out, c| {
                out.* = c.values;
                out.controls = try a.dupe([3]core.fields.qm31.QM31, c.values.controls);
            }
            const m = self.memory.?.claims;
            return .{ .native = native, .batches = batches, .program = self.program.?.claims, .lookup = self.lookup.?.claims, .ram = try a.dupe(MA.RamClaim, m.ram), .interval = m.interval, .range16 = m.range16, .terminal = m.terminal };
        }
    };
}
pub fn prove(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, stages: Stages, pool: *engine.work_pool.WorkPool, limits: Limits) !Proof {
    return proveWithOptions(a, trusted, input, stages, pool, limits, .{});
}
pub fn proveWithOptions(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, stages: Stages, pool: *engine.work_pool.WorkPool, limits: Limits, options: ProveOptions) !Proof {
    var prove_scope = try StageScope.begin(options.recorder, "keccak_union_prove", "Multi-window original proof including producer cleanup");
    defer prove_scope.end();
    if (options.stats) |stats| {
        stats.* = .{};
        if (engine.host_budget_allocator.SharedHostBudget.fromAllocator(a)) |budget| stats.union_allocator_live_at_entry = budget.snapshot().live_bytes;
    }
    defer if (options.stats) |stats| {
        if (engine.host_budget_allocator.SharedHostBudget.fromAllocator(a)) |budget| {
            const measured = budget.snapshot();
            stats.union_allocator_live_at_exit = measured.live_bytes;
            stats.union_allocator_peak_cumulative = measured.peak_live_bytes;
        }
    };
    if (options.native_main_cache_bytes > NativeCache.MAX_RETAINED_BYTES) return error.InvalidV7QuotientCacheBudget;
    var binding = try engine.work_pool.ScopedPoolBinding.initIfNeeded(pool);
    defer if (binding) |*owned_binding| owned_binding.deinit();
    const Residency = @import("block_v7_multi_union_residency_v1.zig");
    if (options.compact_storage_admission and engine.host_budget_allocator.SharedHostBudget.fromAllocator(a) == null) return error.MultiUnionProducerRequiresHardBudget;
    const storage = Residency.ProducerStorage{ .memory_inputs = stages.memory.limits.input_storage, .memory_interaction = stages.memory.limits.interaction_storage };
    const scope = blk: {
        var phase = try StageScope.begin(options.recorder, "keccak_union_admission", "Independent shape and resource admission");
        defer phase.end();
        break :blk if (options.compact_storage_admission)
            try Scope.Owned.initForProducer(a, trusted, input, limits, storage)
        else
            try Scope.Owned.init(a, trusted, input, limits);
    };
    var scope_live = true;
    defer if (scope_live) scope.deinit();
    if (options.compact_storage_admission) {
        if (!stages.memory.owns_scheme or !stages.memory.witness_live or stages.memory.scheme.trees.items.len != 2) return error.InvalidMultiUnionStages;
        const memory_source = scope.sources[scope.sources.len - 1];
        for (stages.memory.scheme.trees.items, memory_source.logs[0..2]) |tree, logs| try Residency.requireTreeStorage(logs, input.epoch.config.fri_config.log_blowup_factor, storage.memory_inputs, tree);
    }
    const ctx = try Context(true).create(a, scope, input, stages, null, limits, options.recorder);
    var ctx_live = true;
    defer if (ctx_live) ctx.deinit();
    if (options.stats) |stats| {
        stats.retained_pcs_model_bytes = scope.retained.total_bytes;
        stats.compact_storage_admission = options.compact_storage_admission;
        stats.memory_allocator_live_after_preparation = stages.memory.budget.snapshot().live_bytes;
    }
    var scheme = try Scheme.init(a, input.epoch.config);
    scheme.deep_group_budget = options.deep_group_budget;
    scheme.quotient_executor = options.quotient_executor;
    var owned = true;
    defer if (owned) scheme.deinit(a);
    var ignored = S.Channel{};
    const fixed = blk: {
        var phase = try StageScope.begin(options.recorder, "keccak_union_fixed_reconstruction", "Canonical fixed-column reconstruction");
        defer phase.end();
        break :blk try ctx.fixed();
    };
    {
        var phase = try StageScope.begin(options.recorder, "keccak_union_fixed_commitment", "Merged fixed commitment");
        defer phase.end();
        try scheme.commitBorrowedStreaming(a, fixed, 8, &ignored);
    }
    {
        var phase = try StageScope.begin(options.recorder, "keccak_union_private_root_adoption", "Adopt previously committed private trees");
        defer phase.end();
        for (stages.natives, scope.sources[0..input.natives.len]) |st, source| try Single.appendPrivate(a, st.allocator, &scheme, &st.first.scheme, source.entry.roots[0..source.entry.root_count], &ignored);
        for (stages.batches, scope.sources[input.natives.len..][0..input.batches.len]) |st, source| try Single.appendPrivate(a, st.allocator, &scheme, &st.scheme, source.entry.roots[0..source.entry.root_count], &ignored);
        try Single.appendPrivate(a, stages.program_allocator, &scheme, &stages.program.scheme, &input.program_roots, &ignored);
        try Single.appendPrivate(a, stages.lookup.a, &scheme, &stages.lookup.scheme, &input.lookup_roots, &ignored);
        try Single.appendPrivate(a, stages.memory.allocator, &scheme, &stages.memory.scheme, &input.memory_roots, &ignored);
    }
    var ch = blk: {
        var phase = try StageScope.begin(options.recorder, "keccak_union_claim_transcript", "Bind every physical claim into the transcript");
        defer phase.end();
        break :blk try ctx.channel(scheme.trees.items[0].root());
    };
    for (ctx.natives) |n| {
        var phase = try StageScope.begin(options.recorder, "keccak_union_native_interaction_commitment", "Native interaction commitment");
        defer phase.end();
        try scheme.commitBorrowedStreaming(a, n.values.columns, 8, &ch);
    }
    for (ctx.batches) |c| {
        var phase = try StageScope.begin(options.recorder, "keccak_union_caller_interaction_commitment", "Caller arithmetic and relation commitments");
        defer phase.end();
        try scheme.commitBorrowedStreaming(a, c.arithmetic_columns, 8, &ch);
        try scheme.commitBorrowedStreaming(a, c.relation_columns, 8, &ch);
    }
    inline for (.{ ctx.program.?, ctx.lookup.? }, .{ "keccak_union_program_interaction_commitment", "keccak_union_lookup_interaction_commitment" }) |provider, id| {
        var phase = try StageScope.begin(options.recorder, id, "Provider interaction commitment");
        defer phase.end();
        try scheme.commitBorrowedStreaming(a, provider.interaction, 8, &ch);
    }
    {
        var phase = try StageScope.begin(options.recorder, "keccak_union_memory_interaction_commitment", "Memory interaction commitment and storage admission");
        defer phase.end();
        if (try stages.memory.limits.interaction_storage.minimumCommitmentLog(input.epoch.config)) |log| {
            scheme.setCoefficientRetentionPolicy(.always);
            scheme.setCompactPolynomialStorage(log);
        }
        try scheme.commitBorrowedStreaming(a, ctx.memory.?.interaction, 8, &ch);
        scheme.compact_polynomial_storage = false;
        if (options.compact_storage_admission) {
            const memory_source = scope.sources[scope.sources.len - 1];
            try Residency.requireTreeStorage(memory_source.logs[2], input.epoch.config.fri_config.log_blowup_factor, storage.memory_interaction, scheme.trees.items[scheme.trees.items.len - 1]);
        }
    }
    if (options.stats) |stats| stats.memory_allocator_live_after_commit = stages.memory.budget.snapshot().live_bytes;
    if (options.consume_memory_producer) {
        var phase = try StageScope.begin(options.recorder, "keccak_union_memory_source_release", "Release consumed memory producer buffers");
        defer phase.end();
        // Both borrowed fixed data and all interaction rows have had their last
        // reader. Independent component metadata lives outside the row arena.
        try ctx.memory.?.releaseTransientRows();
        try stages.memory.releaseProducerState();
    }
    if (options.stats) |stats| stats.memory_allocator_live_after_consumption = stages.memory.budget.snapshot().live_bytes;
    if (scheme.trees.items.len != scope.placement.trace_trees) return error.InvalidMultiUnionTreeCount;
    var payload = std.heap.ArenaAllocator.init(a);
    errdefer payload.deinit();
    const claims = blk: {
        var phase = try StageScope.begin(options.recorder, "keccak_union_public_claim_copy", "Copy detached public claims");
        defer phase.end();
        break :blk try ctx.cloneClaims(payload.allocator());
    };
    if (options.stats) |stats| if (engine.host_budget_allocator.SharedHostBudget.fromAllocator(a)) |budget| {
        stats.union_allocator_live_before_proof = budget.snapshot().live_bytes;
    };
    const stark = blk: {
        var phase = try StageScope.begin(options.recorder, "keccak_union_core_proof", "STARK core including commitment-owner destruction");
        defer phase.end();
        // Immutable PCS MAIN views are shared by many projection components.
        // All caches use this ONE proof-scoped owner and synchronized allocator.
        const cache = try NativeCache.Owner.createWithUsage(a, options.native_main_cache_bytes, options.stats != null);
        for (ctx.natives) |*native| native.component.setQuotientCache(if (cache) |c| &c.cache else null);
        defer {
            for (ctx.natives) |*native| native.component.setQuotientCache(null);
            if (cache) |c| {
                if (options.stats) |stats| {
                    const snapshot = c.stats();
                    stats.native_cache_recovered_columns = snapshot.recovered_columns;
                    stats.native_cache_reused_columns = snapshot.reused_columns;
                    stats.native_cache_retained_bytes = snapshot.retained_bytes;
                    stats.native_cache_requested_columns = snapshot.requested_columns;
                    stats.native_cache_passthrough_columns = snapshot.passthrough_columns;
                    stats.native_cache_capacity_misses = snapshot.capacity_misses;
                    stats.native_cache_evicted_columns = snapshot.evicted_columns;
                }
                c.destroy();
            }
        }
        owned = false;
        var result = try engine.prove.proveExWithRecorder(Cpu, S.Hasher, S.MerkleChannel, a, ctx.combined.?.handles, &ch, scheme, false, options.recorder);
        result.aux.deinit(a);
        break :blk result.proof;
    };
    errdefer {
        var failed = stark;
        failed.deinit(a);
    }
    {
        var phase = try StageScope.begin(options.recorder, "keccak_union_producer_cleanup", "Release preparation metadata and provider contexts");
        defer phase.end();
        ctx.deinit();
        ctx_live = false;
        scope.deinit();
        scope_live = false;
    }
    return .{ .stark = stark, .claims = claims, .claims_arena = payload };
}
pub fn verify(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, proof: *const Proof, limits: Limits) !Receiver.Verified {
    const borrowed = proof.view();
    return verifyView(a, trusted, input, &borrowed, limits);
}
pub fn verifyView(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, proof: *const ProofView, limits: Limits) !Receiver.Verified {
    const scope = try Scope.Owned.init(a, trusted, input, limits);
    defer scope.deinit();
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (roots.len != scope.placement.trace_trees + 1 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, input.epoch.config)) return error.InvalidMultiUnionProofShape;
    var first_end: usize = 1;
    for (scope.sources, scope.placement.parts) |source, part| for (1..source.entry.root_count) |i| {
        if (!std.meta.eql(roots[part.map[i]], source.entry.roots[i])) return error.UntrustedUnionPrivateRoot;
        first_end += 1;
    };
    const ctx = try Context(false).create(a, scope, input, null, proof, limits, null);
    defer ctx.deinit();
    var fixed = try Scheme.init(a, input.epoch.config);
    defer fixed.deinit(a);
    var ignored = S.Channel{};
    try fixed.commitBorrowedStreaming(a, try ctx.fixed(), 8, &ignored);
    if (!std.meta.eql(roots[0], fixed.trees.items[0].root())) return error.UntrustedUnionFixedRoot;
    var ch = try ctx.channel(roots[0]);
    const t = ctx.arena.allocator();
    const logs = try t.alloc([]const u32, scope.placement.trace_trees);
    @memset(logs, &.{});
    var fixed_logs: std.ArrayList(u32) = .empty;
    for (scope.sources, scope.placement.parts) |source, part| {
        try fixed_logs.appendSlice(t, source.logs[0]);
        for (1..source.tree_count) |i| logs[part.map[i]] = source.logs[i];
    }
    logs[0] = try fixed_logs.toOwnedSlice(t);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, input.epoch.config);
    defer verifier.deinit(a);
    for (0..first_end) |i| try verifier.commit(a, roots[i], logs[i], &ignored);
    for (first_end..scope.placement.trace_trees) |i| try verifier.commit(a, roots[i], logs[i], &ch);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, ctx.combined.?.handles, &ch, &verifier, &proof.stark, &capture);
    defer capture.deinit(a);
    const memory = try @import("block_v7_memory_claim_closure_v1.zig").close(proof.claims.memory());
    var closure = try @import("block_v7_execution_claim_closure_v1.zig").Accumulator.init(a, input.natives.len, scope.caller_windows, proof.claims.program, input.program_plan.expected_fetches, proof.claims.lookup, memory);
    defer closure.deinit();
    for (proof.claims.native, input.natives, 0..) |claims, pin, i| try closure.addNative(i, try NS.exportsFromClaims(t, pin, claims.claims, claims.access, &ctx.drawn));
    for (proof.claims.batches, input.batches, ctx.batches) |claims, pin, *c| try @import("block_v7_keccak_batch_closure_v1.zig").addToExecution(&closure, pin, try claims.open(pin, c.component.lookup.slots));
    const totals = try closure.finish();
    return .{ .statement = try scope.policy.digest(), .epoch = input.epoch.digest, .cycles = trusted.terminal.final_cycle, .segments = @intCast(input.natives.len), .ram_events = totals.events, .program_fetches = totals.fetches, .output = trusted.terminal.output };
}
