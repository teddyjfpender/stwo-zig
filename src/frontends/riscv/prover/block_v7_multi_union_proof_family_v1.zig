//! Explicit bounded multi-window original-STARK protocol. Original equation
//! bodies, shared relation draws, physical claims and global closure are reused.
//! This is not the one-window B7UF proof and not a recursive publication proof.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const engine = @import("stwo_prover_engine");
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        const S = core.proof_suites.Blake3;
        const E = @import("block_v7_execution_epoch_v1.zig");
        const Scope = @import("block_v7_multi_union_scope_v1.zig").ForMode(window);
        const Receiver = @import("block_v7_execution_receiver_v1.zig");
        const Native = @import("block_v7_native_proof_v1.zig");
        const NS = @import("block_v7_native_source_v1.zig");
        const NC = @import("block_v7_native_components_v1.zig");
        const Caller = @import("block_v7_caller_active_proof_v1.zig");
        const CS = @import("block_v7_caller_active_source_v1.zig");
        const Pair = @import("block_v7_native_caller_union_proof_v1.zig");
        const Single = @import("block_v7_complete_union_proof_v1.zig");
        const Providers = struct {
            pub const Program = @import("block_v7_complete_union_program_v1.zig");
            pub const Lookup = @import("block_v7_complete_union_lookup_v1.zig");
            pub const Memory = @import("block_v7_complete_union_memory_v1.zig").ForMode(window);
        };
        const MemoryProof = if (window) @import("block_v7_window_memory_joint_v1.zig") else @import("block_v7_memory_joint_proof_v1.zig");
        const Placement = @import("block_v7_heterogeneous_components_v1.zig");
        const CF = @import("block_v5_caller_fused_proof_v1.zig");
        const NF = @import("block_v5_native_projection_fused_proof_v2.zig");
        const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
        const MA = if (window) @import("block_v7_window_memory_joint_air_v1.zig") else @import("block_v7_memory_joint_air_v1.zig");
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
            fixed_polynomials_reused: bool = false,
            memory_allocator_live_after_consumption: usize = 0,
            union_allocator_live_before_proof: ?usize = null,
            union_allocator_live_at_entry: ?usize = null,
            union_allocator_live_at_exit: ?usize = null,
            /// Cumulative allocator high-water mark, including work before this call.
            /// This is neither process RSS nor the incremental peak of this phase.
            union_allocator_peak_cumulative: ?usize = null,
        };
        pub const ProveOptions = struct {
            /// Reuse the admitted source fixed polynomials; the merged Merkle
            /// root and every verifier equation remain byte-identical. Raw
            /// reconstruction remains an explicit control/fallback.
            fixed: @import("block_v7_union_fixed_reuse_v1.zig").Policy = .reuse_if_available,
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
        pub const TAG: u32 = if (window) 0x42375557 else 0x4237554d; // B7UW / unchanged B7UM
        pub const VERSION: u32 = 1;
        pub const NativeStage = struct { allocator: std.mem.Allocator, first: *Native.For(Cpu).First, owner: *@import("blake3_execution_trace.zig").Owner, inputs: []const Memory.Input };
        pub const Stages = struct { natives: []const NativeStage, callers: []const *Caller.ForBackend(Cpu).Stage, program: *@import("block_v7_program_provider_v1.zig").ForBackend(Cpu).FirstRound, program_allocator: std.mem.Allocator, lookup: *@import("block_v7_lookup_compact_proof_v1.zig").For(Cpu).Stage, memory: *MemoryProof.For(Cpu).Stage };
        pub const NativeClaims = struct { claims: []NF.Claim, access: []Memory.Claim };
        pub const CallerClaims = struct { arithmetic: P.ExtensionClaim, relations: CF.ClaimFrames };
        pub const Claims = struct {
            native: []NativeClaims,
            callers: []CallerClaims,
            program: Providers.Program.Claims,
            lookup: Providers.Lookup.Claims,
            ram: []MA.RamClaim,
            interval: [2]core.fields.qm31.QM31,
            range16: [2]core.fields.qm31.QM31,
            terminal: if (window) void else [1]core.fields.qm31.QM31,
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
        /// Owned material from an independently reconstructed verifier. A closed
        /// summary is issued only after the original STARK and every global
        /// relation have verified. This is not yet a recursive proof.
        pub const VerifiedCapture = struct {
            allocator: std.mem.Allocator,
            proof: core.verifier.ProofCapture(S.Hasher),
            final_channel: S.Channel,
            claims: Claims,
            claims_arena: std.heap.ArenaAllocator,
            closed: Receiver.Verified,
            pub fn deinit(self: *VerifiedCapture) void {
                self.proof.deinit(self.allocator);
                self.claims_arena.deinit();
                self.* = undefined;
            }
        };
        /// Independently reconstructed component geometry for a recursive
        /// compiler. Public claims supply values, never the component roster,
        /// tree placement, fixed roots, or a successful-verification receipt.
        /// Borrowed input/claims must remain alive until deinit.
        pub const AdmittedComponents = struct {
            allocator: std.mem.Allocator,
            scope: *Scope.Owned,
            context: *Context(false),
            pub fn init(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, claims: *const Claims, limits: Limits) !AdmittedComponents {
                const scope = try Scope.Owned.init(a, trusted, input, limits);
                errdefer scope.deinit();
                const ctx = try Context(false).create(a, scope, input, null, claims, limits, null);
                return .{ .allocator = a, .scope = scope, .context = ctx };
            }
            pub fn handles(self: *const AdmittedComponents) []const core.air.components.Component {
                return self.context.combined.?.handles;
            }
            pub fn recordPrefix(self: *const AdmittedComponents, channel: anytype, fixed_root: [32]u8) !void {
                try self.context.recordPrefix(channel, fixed_root);
            }
            pub fn fixedRoot(self: *const AdmittedComponents) ![32]u8 {
                return self.context.expectedFixedRoot(self.allocator);
            }
            /// Arena-backed vectors with exactly the original global tree map.
            /// No composition tree is included in this trace inventory.
            pub fn traceLogs(self: *const AdmittedComponents, a: std.mem.Allocator) ![]const []const u32 {
                const logs = try a.alloc([]const u32, self.scope.placement.trace_trees);
                @memset(logs, &.{});
                var fixed: std.ArrayList(u32) = .empty;
                for (self.scope.sources, self.scope.placement.parts) |source, part| {
                    try fixed.appendSlice(a, source.logs[0]);
                    for (1..source.tree_count) |i| logs[part.map[i]] = source.logs[i];
                }
                logs[0] = try fixed.toOwnedSlice(a);
                return logs;
            }
            pub fn deinit(self: *AdmittedComponents) void {
                self.context.deinit();
                self.scope.deinit();
                self.* = undefined;
            }
        };
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
            const C = struct { drawn: CS.Drawn, schedule: Schedule, values: CallerClaims, arithmetic_columns: []Column, relation_columns: []Column, component: *CC.Owner(proving), handles: [1]H };
            return struct {
                allocator: std.mem.Allocator,
                arena: std.heap.ArenaAllocator,
                scope: *const Scope.Owned,
                input: Input,
                drawn: E.Drawn,
                natives: []N,
                callers: []C,
                program: ?*Providers.Program.Context = null,
                lookup: ?*Providers.Lookup.Context = null,
                memory: ?*Providers.Memory.Context = null,
                combined: ?Placed = null,
                const Self = @This();
                fn create(a: std.mem.Allocator, scope: *const Scope.Owned, input: Input, stages: ?Stages, claims: ?*const Claims, limits: Limits, recorder: ?*Recorder) !*Self {
                    var preparation_scope = try StageScope.begin(recorder, "multi_context_preparation", "Interaction generation and component preparation");
                    defer preparation_scope.end();
                    const self = try a.create(Self);
                    self.* = .{ .allocator = a, .arena = std.heap.ArenaAllocator.init(a), .scope = scope, .input = input, .drawn = undefined, .natives = &.{}, .callers = &.{} };
                    errdefer self.deinit();
                    const t = self.arena.allocator();
                    {
                        var phase = try StageScope.begin(recorder, "multi_epoch_draw", "Epoch challenge derivation");
                        defer phase.end();
                        self.drawn = try input.epoch.draw(t);
                    }
                    if (proving) {
                        if (stages.?.natives.len != input.natives.len or stages.?.callers.len != input.callers.len) return error.InvalidMultiUnionStages;
                    } else {
                        if (claims.?.native.len != input.natives.len or claims.?.callers.len != input.callers.len or claims.?.ram.len != input.memory_geometry.len) return error.InvalidMultiUnionClaims;
                        for (claims.?.ram, input.memory_geometry) |claim, g| if (!std.meta.eql(claim.geometry, g)) return error.UntrustedMultiUnionMemoryGeometry;
                    }
                    self.natives = try t.alloc(N, input.natives.len);
                    self.callers = try t.alloc(C, input.callers.len);
                    const parts = try t.alloc(Placed.Part, scope.sources.len);
                    for (self.natives, input.natives, 0..) |*n, pin, i| {
                        var phase = try StageScope.begin(recorder, "multi_native_preparation", "Native interactions and component preparation");
                        defer phase.end();
                        if (proving) {
                            const st = stages.?.natives[i];
                            n.values = try Pair.nativeInteractionWithScratch(t, a, st.first, st.owner, st.inputs, pin, &self.drawn);
                        } else {
                            try @import("block_v5_native_execution_proof_v3.zig").ForBackend(Cpu).verifyFixed(a, pin.shape, pin.template, input.epoch.config);
                            n.values = .{ .claims = claims.?.native[i].claims, .access = claims.?.native[i].access, .columns = &.{} };
                        }
                        n.component = try NC.Owner.init(t, pin, n.values.claims, n.values.access, &self.drawn);
                        const owner = if (proving) try n.component.proving() else try n.component.verifying();
                        n.handles = owner.handles;
                        parts[i] = .{ .map = scope.placement.parts[i].mapping(), .handles = n.handles, .fixed_count = n.component.fixed.len };
                    }
                    for (self.callers, input.callers, 0..) |*c, pin, i| {
                        var phase = try StageScope.begin(recorder, "multi_caller_preparation", "Caller interactions and component preparation");
                        defer phase.end();
                        c.drawn = try CS.draw(t, input.epoch, scope.sources[input.natives.len + i].entry);
                        c.schedule = try @import("block_v7_caller_active_schedule_v1.zig").derive(t, pin.statement, pin.total_steps, pin.frame);
                        if (proving) {
                            const st = stages.?.callers[i];
                            if (!st.first.owns_scheme or !std.meta.eql(try st.pin(pin.execution_index, pin.execution_identity).entry(t), scope.sources[input.natives.len + i].entry)) return error.InvalidMultiUnionCallerPhase;
                            const arithmetic = try @import("block_v7_caller_active_columns_v1.zig").interactions(t, st.witness, &c.drawn.relations, engine.work_pool.currentScopedPool() orelse return error.MissingWorkPool);
                            const fused = try @import("block_v6_caller_joint_interaction_v1.zig").generate(t, &st.columns, &st.schedule, st.inputs, st.first.snapshots, &c.drawn.relations, &self.drawn.word);
                            c.values = .{ .arithmetic = arithmetic.claim, .relations = fused.claims };
                            c.arithmetic_columns = try st.layout.columns(t, 2, arithmetic.columns);
                            c.relation_columns = fused.columns;
                        } else {
                            try Caller.ForBackend(Cpu).requireFixedRoot(a, pin);
                            c.values = claims.?.callers[i];
                            c.arithmetic_columns = &.{};
                            c.relation_columns = &.{};
                        }
                        c.component = try Pair.callerOwner(proving, t, pin, &c.drawn, &c.values.arithmetic, &c.values.relations, &c.schedule);
                        c.handles = .{if (proving) c.component.asProverComponent() else c.component.asVerifierComponent()};
                        const at = input.natives.len + i;
                        parts[at] = .{ .map = scope.placement.parts[at].mapping(), .handles = &c.handles, .fixed_count = c.schedule.fixed.len };
                    }
                    {
                        var phase = try StageScope.begin(recorder, "multi_program_preparation", "Program interactions and component preparation");
                        defer phase.end();
                        self.program = if (proving) try Providers.Program.prepare(Cpu, a, stages.?.program, programPolicy(input)) else try Providers.Program.verifier(Cpu, a, programPolicy(input), claims.?.program);
                    }
                    {
                        var phase = try StageScope.begin(recorder, "multi_lookup_preparation", "Lookup interactions and component preparation");
                        defer phase.end();
                        self.lookup = if (proving) try Providers.Lookup.prepare(Cpu, a, stages.?.lookup, lookupPolicy(input)) else try Providers.Lookup.verifier(Cpu, a, lookupPolicy(input), claims.?.lookup, limits.receiver.compact_lookup);
                    }
                    {
                        var phase = try StageScope.begin(recorder, "multi_memory_preparation", "Memory interactions and component preparation");
                        defer phase.end();
                        self.memory = if (proving) try Providers.Memory.prepare(Cpu, stages.?.memory, input.epoch, input.entries) else try Providers.Memory.verifier(Cpu, a, .{ .policy = scope.policy, .epoch = input.epoch, .entries = input.entries, .roots = input.memory_roots, .interval_log = input.interval_log, .claims = claims.?.memory() }, (if (window) limits.receiver.window_memory else limits.receiver.joint_memory));
                    }
                    const m = self.memory.?;
                    if (!std.meta.eql(m.roots, input.memory_roots) or m.interval_log != input.interval_log or m.claims.ram.len != input.memory_geometry.len or !std.meta.eql(try m.policy.digest(), try scope.policy.digest())) return error.UntrustedMultiUnionMemory;
                    for (m.claims.ram, input.memory_geometry) |claim, g| if (!std.meta.eql(claim.geometry, g)) return error.UntrustedMultiUnionMemoryGeometry;
                    inline for (.{ self.program.?, self.lookup.?, self.memory.? }, 0..) |provider, i| {
                        const at = input.natives.len + input.callers.len + i;
                        parts[at] = .{ .map = scope.placement.parts[at].mapping(), .handles = if (proving) provider.provers else provider.verifiers, .fixed_count = provider.fixed_columns.len };
                        for (provider.logs, scope.sources[at].logs[0..3]) |actual, expected| if (!std.mem.eql(u32, actual, expected)) return error.UntrustedMultiUnionProviderGeometry;
                    }
                    {
                        var phase = try StageScope.begin(recorder, "multi_component_placement", "Component placement");
                        defer phase.end();
                        self.combined = try Placed.init(t, parts, scope.placement.trace_trees);
                    }
                    return self;
                }
                fn deinit(self: *Self) void {
                    const a = self.allocator;
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
                    for (self.input.callers) |pin| {
                        const all = try P.preprocessed(t, pin.statement);
                        const layout = try @import("block_v7_caller_active_layout_v1.zig").Layout.derive(pin.statement, pin.total_steps);
                        try result.appendSlice(t, try layout.columns(t, 0, all));
                    }
                    inline for (.{ self.program.?, self.lookup.?, self.memory.? }) |p| try result.appendSlice(t, p.fixed_columns);
                    return result.toOwnedSlice(t);
                }
                fn expectedFixedRoot(self: *Self, a: std.mem.Allocator) ![32]u8 {
                    var scheme = try Scheme.init(a, self.input.epoch.config);
                    defer scheme.deinit(a);
                    var ignored = S.Channel{};
                    try scheme.commitBorrowedStreaming(a, try self.fixed(), 8, &ignored);
                    return scheme.trees.items[0].root();
                }
                fn channel(self: *Self, root: [32]u8) !S.Channel {
                    var ch = S.Channel{};
                    try self.recordPrefix(&ch, root);
                    return ch;
                }
                fn recordPrefix(self: *Self, ch: anytype, root: [32]u8) !void {
                    ch.mixU32s(&.{ TAG, VERSION, @intCast(self.scope.placement.trace_trees), @intCast(self.scope.sources.len) });
                    self.input.epoch.config.mixInto(ch);
                    ch.mixRoot(self.input.epoch.digest);
                    ch.mixRoot(root);
                    for (self.scope.placement.parts) |part| {
                        ch.mixU32s(&.{ @intFromEnum(part.source.family), part.source.index, part.source.root_count, part.source_trees });
                        for (part.mapping()) |index| ch.mixU32s(&.{@intCast(index)});
                    }
                    for (self.natives, self.input.natives, 0..) |*n, pin, i| try Native.recordAfterChallenges(ch, pin, self.scope.sources[i].entry, n.component.layout.slots, n.component.slots, n.values.claims, n.values.access);
                    for (self.callers, self.input.callers, 0..) |*c, pin, i| try CS.recordAfterChallenges(ch, pin, self.scope.sources[self.natives.len + i].entry, &c.schedule, &c.values.arithmetic, &c.values.relations);
                    try self.program.?.recordAfterChallenges(ch);
                    try self.lookup.?.recordAfterChallenges(ch);
                    try self.memory.?.recordAfterChallenges(ch);
                }
                fn cloneClaims(self: *Self, a: std.mem.Allocator) !Claims {
                    const native = try a.alloc(NativeClaims, self.natives.len);
                    for (native, self.natives) |*out, n| out.* = .{ .claims = try a.dupe(NF.Claim, n.values.claims), .access = try a.dupe(Memory.Claim, n.values.access) };
                    const callers = try a.alloc(CallerClaims, self.callers.len);
                    for (callers, self.callers) |*out, c| out.* = .{ .arithmetic = c.values.arithmetic, .relations = try CF.ClaimFrames.clone(a, &c.values.relations) };
                    const m = self.memory.?.claims;
                    return .{ .native = native, .callers = callers, .program = self.program.?.claims, .lookup = self.lookup.?.claims, .ram = try a.dupe(MA.RamClaim, m.ram), .interval = m.interval, .range16 = m.range16, .terminal = m.terminal };
                }
            };
        }
        /// Unauthenticated producer diagnostic only. This never verifies or returns a
        /// proof and must not be used as admission or publication authority. Each native
        /// uses the identical interaction generator and claim extractor as prove/verify.
        pub const NativeClaimDiagnostic = struct {
            index: usize,
            frame: @import("../air/block/memory_event.zig").Frame,
            public_clock: u32,
            ordinary_memory_residual: core.fields.qm31.QM31,
            auxiliary_clock_memory: core.fields.qm31.QM31,
            state_residual: core.fields.qm31.QM31,
            register_residual: core.fields.qm31.QM31,
            components: []@import("../air/statement.zig").FamilyComponentDesc,
            infrastructure: []@import("../air/statement.zig").InfraComponentDesc,
        };
        pub fn diagnoseNativeClaims(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, stages: Stages, pool: *engine.work_pool.WorkPool, limits: Limits) ![]NativeClaimDiagnostic {
            var binding = try engine.work_pool.ScopedPoolBinding.initIfNeeded(pool);
            defer if (binding) |*owned_binding| owned_binding.deinit();
            const scope = try Scope.Owned.init(a, trusted, input, limits);
            defer scope.deinit();
            if (stages.natives.len != input.natives.len) return error.InvalidMultiUnionStages;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const drawn = try input.epoch.draw(arena.allocator());
            const result = try a.alloc(NativeClaimDiagnostic, input.natives.len);
            var initialized: usize = 0;
            errdefer {
                for (result[0..initialized]) |item| {
                    a.free(item.components);
                    a.free(item.infrastructure);
                }
                a.free(result);
            }
            for (input.natives, stages.natives, result, 0..) |pin, stage, *item, i| {
                var scratch = std.heap.ArenaAllocator.init(a);
                defer scratch.deinit();
                const t = scratch.allocator();
                const generated = try Pair.nativeInteractionWithScratch(t, a, stage.first, stage.owner, stage.inputs, pin, &drawn);
                const exports = try NS.exportsFromClaims(t, pin, generated.claims, generated.access, &drawn);
                const components = try a.dupe(@import("../air/statement.zig").FamilyComponentDesc, pin.shape.component_descs[0..pin.shape.n_components]);
                errdefer a.free(components);
                const infrastructure = try a.dupe(@import("../air/statement.zig").InfraComponentDesc, pin.shape.infra_descs[0..pin.shape.n_infra]);
                item.* = .{ .index = i, .frame = pin.frame, .public_clock = pin.shape.public_data.clock, .ordinary_memory_residual = exports.ordinary_memory_residual, .auxiliary_clock_memory = exports.auxiliary_clock_memory, .state_residual = exports.state_residual, .register_residual = exports.register_residual, .components = components, .infrastructure = infrastructure };
                initialized += 1;
            }
            return result;
        }
        pub fn freeNativeClaimDiagnostics(a: std.mem.Allocator, items: []NativeClaimDiagnostic) void {
            for (items) |item| {
                a.free(item.components);
                a.free(item.infrastructure);
            }
            a.free(items);
        }
        pub fn prove(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, stages: Stages, pool: *engine.work_pool.WorkPool, limits: Limits) !Proof {
            return proveWithOptions(a, trusted, input, stages, pool, limits, .{});
        }
        pub fn proveWithOptions(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, stages: Stages, pool: *engine.work_pool.WorkPool, limits: Limits, options: ProveOptions) !Proof {
            var prove_scope = try StageScope.begin(options.recorder, "multi_prove", "Multi-window original proof including producer cleanup");
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
                var phase = try StageScope.begin(options.recorder, "multi_admission", "Independent shape and resource admission");
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
            {
                var phase = try StageScope.begin(options.recorder, "multi_fixed_commitment", "Merged fixed commitment with admitted polynomial reuse");
                defer phase.end();
                const FixedReuse = @import("block_v7_union_fixed_reuse_v1.zig");
                const sources = try a.alloc(FixedReuse.Source, scope.sources.len);
                defer a.free(sources);
                for (stages.natives, sources[0..input.natives.len], scope.sources[0..input.natives.len]) |stage, *source, admitted| {
                    source.* = .{ .allocator = stage.allocator, .scheme = &stage.first.scheme, .expected_root = admitted.entry.roots[0], .raw_logs = admitted.logs[0] };
                }
                const caller_base = input.natives.len;
                for (stages.callers, sources[caller_base..][0..input.callers.len], scope.sources[caller_base..][0..input.callers.len]) |stage, *source, admitted| {
                    source.* = .{ .allocator = stage.allocator, .scheme = &stage.first.scheme, .expected_root = admitted.entry.roots[0], .raw_logs = admitted.logs[0] };
                }
                const provider_base = caller_base + input.callers.len;
                sources[provider_base] = .{ .allocator = stages.program_allocator, .scheme = &stages.program.scheme, .expected_root = input.program_roots[0], .raw_logs = scope.sources[provider_base].logs[0] };
                sources[provider_base + 1] = .{ .allocator = stages.lookup.a, .scheme = &stages.lookup.scheme, .expected_root = input.lookup_roots[0], .raw_logs = scope.sources[provider_base + 1].logs[0] };
                sources[provider_base + 2] = .{ .allocator = stages.memory.allocator, .scheme = &stages.memory.scheme, .expected_root = input.memory_roots[0], .raw_logs = scope.sources[provider_base + 2].logs[0] };
                const reused = options.fixed != .rebuild and try FixedReuse.tryAppend(a, &scheme, sources, &ignored);
                if (options.stats) |stats| stats.fixed_polynomials_reused = reused;
                if (!reused and options.fixed == .reuse_required) return error.UnionFixedReuseUnavailable;
                if (!reused) {
                    var reconstruction = try StageScope.begin(options.recorder, "multi_fixed_reconstruction", "Canonical fixed-column reconstruction fallback");
                    defer reconstruction.end();
                    try scheme.commitBorrowedStreaming(a, try ctx.fixed(), 8, &ignored);
                }
            }
            {
                var phase = try StageScope.begin(options.recorder, "multi_private_root_adoption", "Adopt previously committed private trees");
                defer phase.end();
                for (stages.natives, scope.sources[0..input.natives.len]) |st, source| try Single.appendPrivate(a, st.allocator, &scheme, &st.first.scheme, source.entry.roots[0..source.entry.root_count], &ignored);
                for (stages.callers, scope.sources[input.natives.len..][0..input.callers.len]) |st, source| try Single.appendPrivate(a, st.allocator, &scheme, &st.first.scheme, source.entry.roots[0..source.entry.root_count], &ignored);
                try Single.appendPrivate(a, stages.program_allocator, &scheme, &stages.program.scheme, &input.program_roots, &ignored);
                try Single.appendPrivate(a, stages.lookup.a, &scheme, &stages.lookup.scheme, &input.lookup_roots, &ignored);
                try Single.appendPrivate(a, stages.memory.allocator, &scheme, &stages.memory.scheme, &input.memory_roots, &ignored);
            }
            var ch = blk: {
                var phase = try StageScope.begin(options.recorder, "multi_claim_transcript", "Bind every physical claim into the transcript");
                defer phase.end();
                break :blk try ctx.channel(scheme.trees.items[0].root());
            };
            for (ctx.natives) |n| {
                var phase = try StageScope.begin(options.recorder, "multi_native_interaction_commitment", "Native interaction commitment");
                defer phase.end();
                try scheme.commitBorrowedStreaming(a, n.values.columns, 8, &ch);
            }
            for (ctx.callers) |c| {
                var phase = try StageScope.begin(options.recorder, "multi_caller_interaction_commitment", "Caller arithmetic and relation commitments");
                defer phase.end();
                try scheme.commitBorrowedStreaming(a, c.arithmetic_columns, 8, &ch);
                try scheme.commitBorrowedStreaming(a, c.relation_columns, 8, &ch);
            }
            inline for (.{ ctx.program.?, ctx.lookup.? }, .{ "multi_program_interaction_commitment", "multi_lookup_interaction_commitment" }) |provider, id| {
                var phase = try StageScope.begin(options.recorder, id, "Provider interaction commitment");
                defer phase.end();
                try scheme.commitBorrowedStreaming(a, provider.interaction, 8, &ch);
            }
            {
                var phase = try StageScope.begin(options.recorder, "multi_memory_interaction_commitment", "Memory interaction commitment and storage admission");
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
                var phase = try StageScope.begin(options.recorder, "multi_memory_source_release", "Release consumed memory producer buffers");
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
                var phase = try StageScope.begin(options.recorder, "multi_public_claim_copy", "Copy detached public claims");
                defer phase.end();
                break :blk try ctx.cloneClaims(payload.allocator());
            };
            if (options.stats) |stats| if (engine.host_budget_allocator.SharedHostBudget.fromAllocator(a)) |budget| {
                stats.union_allocator_live_before_proof = budget.snapshot().live_bytes;
            };
            const stark = blk: {
                var phase = try StageScope.begin(options.recorder, "multi_core_proof", "STARK core including commitment-owner destruction");
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
                var phase = try StageScope.begin(options.recorder, "multi_producer_cleanup", "Release preparation metadata and provider contexts");
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
            var captured = try verifyViewAndCapture(a, trusted, input, proof, limits);
            defer captured.deinit();
            return captured.closed;
        }
        pub fn verifyViewAndCapture(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, proof: *const ProofView, limits: Limits) !VerifiedCapture {
            const scope = try Scope.Owned.init(a, trusted, input, limits);
            defer scope.deinit();
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != scope.placement.trace_trees + 1 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, input.epoch.config)) return error.InvalidMultiUnionProofShape;
            var first_end: usize = 1;
            for (scope.sources, scope.placement.parts) |source, part| for (1..source.entry.root_count) |i| {
                if (!std.meta.eql(roots[part.map[i]], source.entry.roots[i])) return error.UntrustedUnionPrivateRoot;
                first_end += 1;
            };
            const ctx = try Context(false).create(a, scope, input, null, &proof.claims, limits, null);
            defer ctx.deinit();
            var ignored = S.Channel{};
            if (!std.meta.eql(roots[0], try ctx.expectedFixedRoot(a))) return error.UntrustedUnionFixedRoot;
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
            errdefer capture.deinit(a);
            const memory = if (window)
                try @import("block_v7_window_memory_joint_protocol_v1.zig").closeVerifiedClaims(scope.policy, ctx.drawn.word.initial, proof.claims.memory())
            else
                try @import("block_v7_memory_claim_closure_v1.zig").close(proof.claims.memory());
            var closure = try @import("block_v7_execution_claim_closure_v1.zig").Accumulator.init(a, input.natives.len, input.callers.len, proof.claims.program, input.program_plan.expected_fetches, proof.claims.lookup, memory);
            defer closure.deinit();
            for (proof.claims.native, input.natives, 0..) |claims, pin, i| try closure.addNative(i, try NS.exportsFromClaims(t, pin, claims.claims, claims.access, &ctx.drawn));
            for (proof.claims.callers, input.callers, ctx.callers) |claims, pin, *c| try closure.addCaller(pin.execution_index, try CS.exports(&c.schedule, &claims.arithmetic, &claims.relations));
            const totals = try closure.finish();
            const closed: Receiver.Verified = .{ .statement = try scope.policy.digest(), .epoch = input.epoch.digest, .cycles = scope.policy.finalCycle(), .segments = @intCast(input.natives.len), .ram_events = totals.events, .program_fetches = totals.fetches, .output = if (window) @splat(0) else trusted.terminal.output, .scope = if (window) .declared_window else .complete_execution };
            var payload = std.heap.ArenaAllocator.init(a);
            errdefer payload.deinit();
            const claims = try ctx.cloneClaims(payload.allocator());
            return .{ .allocator = a, .proof = capture, .final_channel = ch, .claims = claims, .claims_arena = payload, .closed = closed };
        }
    };
}
