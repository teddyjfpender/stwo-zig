//! Native-v3 global closure kernel. Every provider and base proof is freshly
//! verified here; this module never accepts open receipts as input authority.
//! Complete bundle admission additionally verifies the exact recursive forest
//! from the native receipts created inside this call, under independent keys.
pub const DefaultReadonly = struct {
    pub const global = false;
    pub const CallerProof = @import("block_v5_caller_readonly_proof_v1.zig");
    pub const MemoryPolicy = @import("block_v5_word_memory_join_impl_v1.zig").DefaultReadonly;
};
pub fn ForStack(comptime Stack: type) type {
    return ForStackReadonly(Stack, DefaultReadonly);
}
/// Same original complete fresh loop and residual equations. Only an explicit
/// independent static policy selects grouped V2 proof/loader types.
pub fn ForStackReadonly(comptime Stack: type, comptime ReadonlyPolicy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const Seal = @import("block_v5_source_seal_v1.zig");
        const Programs = Stack.Programs;
        const Program = @import("block_v5_program_table_v1.zig");
        const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStackReadonly(Stack, ReadonlyPolicy.MemoryPolicy);
        const MemoryProofs = @import("block_v5_sorted_memory_v1.zig");
        const Tables = @import("block_v5_native_table_join_impl_v1.zig").ForStack(Stack);
        const Endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
        const CallerFused = @import("block_v5_caller_fused_proof_v1.zig");
        const CallerExternal = @import("block_execution_external_trace_v2.zig");
        const Fused = Stack.Fused;
        const FusedReceiver = Stack.FusedReceiver;
        const Native = Stack.Native;
        const Caller = @import("block_v5_precompile_family_proof_v1.zig");
        const Spans = @import("../recursion/block_v5_pc_clock_span_v1.zig");
        const Exact = Stack.Exact;
        const Manifest = Stack.Manifest;
        const NativeRecursive = Stack.NativeRecursive;
        const LeafProtocol = Stack.LeafProtocol;
        const LeafBus = Stack.LeafBus;
        const ParentBus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
        const Recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
        const PageMemory = @import("block_v5_memory_source_page_memory_init_v1.zig");
        pub const SourcePages = PageMemory.Source;

        pub const Pins = struct {
            execution_recipe: @import("block_v5_execution_recipe_v1.zig").Recipe = Recipe,
            expected_seal_digest: [32]u8,
            program: Program.Plan,
            memory: Memory.Pins,
            tables: Tables.Pins,

            pub fn validate(self: Pins) !Seal.Sealed {
                try self.execution_recipe.requireCompiled();
                try Recipe.requireMode(self.tables.seal.register_custody_mode);
                const executions = self.tables.executions.len;
                const words = self.memory.memory;
                try words.requireCanonical(self.tables.seal.register_custody_mode);
                if (executions == 0 or self.memory.executions.len != executions or
                    self.memory.ordinary_events.len != executions or self.tables.ordinary_events.len != executions or
                    self.memory.opcode_witness_roots.len != executions or
                    (words.instanceCount() == 0 and (self.tables.seal.register_custody_mode != 1 or words.totalEvents() != 0)) or
                    self.memory.extensions.len != self.tables.extensions.len)
                    return error.UntrustedV5GlobalPins;
                var previous_extension: ?u32 = null;
                for (self.tables.extensions) |extension| {
                    try Recipe.requireCaller(extension.statement, extension.total_steps);
                    if (extension.execution_index >= executions or
                        (previous_extension != null and extension.execution_index <= previous_extension.?))
                        return error.UntrustedV5GlobalCallerPins;
                    previous_extension = extension.execution_index;
                }
                const sealed = try Seal.seal(self.tables.seal, self.tables.roster);
                if (sealed.register_custody_mode == 1) {
                    const memory_registers = self.memory.register_windows orelse return error.MissingV5RegisterWindowPlan;
                    const table_registers = self.tables.register_windows orelse return error.MissingV5RegisterWindowPlan;
                    try Recipe.requireWindowVersion(memory_registers.version);
                    try Recipe.requireWindowVersion(table_registers.version);
                    if (!std.meta.eql(try memory_registers.digest(), sealed.register_endpoint_plan_digest) or
                        !std.meta.eql(try table_registers.digest(), sealed.register_endpoint_plan_digest)) return error.UntrustedV5RegisterWindowPlan;
                } else if (self.memory.register_windows != null or self.tables.register_windows != null) return error.UntrustedV5RegisterCustodyMode;
                try sealed.requireComplete(self.tables.seal, self.tables.roster);
                if (!std.meta.eql(sealed.digest, self.expected_seal_digest) or
                    !std.meta.eql(self.memory.memory.sealPins(), self.tables.seal) or
                    !std.meta.eql(self.memory.memory.expectedSealDigest(), sealed.digest) or
                    !sameRoster(self.memory.memory.firstRound(), self.tables.roster) or
                    !std.meta.eql(try self.memory.catalog.digest(), try self.tables.catalog.digest()) or
                    !std.meta.eql(try self.program.digest(), self.tables.seal.program_plan_digest) or
                    !std.meta.eql(self.program.program_root.bytes, self.tables.seal.program_root) or
                    self.memory.executions.len != self.tables.executions.len or
                    self.memory.extensions.len != self.tables.extensions.len or
                    self.memory.ordinary_events.len != self.tables.ordinary_events.len)
                    return error.UntrustedV5GlobalPins;
                for (self.memory.executions, self.tables.executions, self.memory.ordinary_events, self.tables.ordinary_events) |left, right, left_count, right_count| {
                    try Recipe.requireNative(left.shape);
                    try Recipe.requireNative(right.shape);
                    if (Stack.is_capacity) {
                        if (!std.meta.eql(left.limits, right.limits)) return error.UntrustedV5GlobalExecutionPins;
                        try left.limits.requireShape(left.shape, left.external_retirements);
                        try right.limits.requireShape(right.shape, right.external_retirements);
                    }
                    if (!std.meta.eql(left.admission.expected_id, right.admission.expected_id) or
                        !std.meta.eql(left.template_id, right.template_id) or left.profile != right.profile or left_count != right_count or Programs.externalRetirements(left) != Programs.externalRetirements(right))
                        return error.UntrustedV5GlobalExecutionPins;
                }
                for (self.memory.extensions, self.tables.extensions) |left, right| {
                    if (left.public.execution_index != right.execution_index or left.public.total_steps != right.total_steps or
                        !std.meta.eql(left.public.expected_key_id, right.expected_key_id) or
                        !std.meta.eql(left.public.statement.*, right.statement.*)) return error.UntrustedV5GlobalCallerPins;
                }
                _ = try blockSpan(self.tables.executions, sealed);
                return sealed;
            }
        };
        pub const Inputs = struct {
            public_input: []const u8,
            endpoint_sources: Endpoints.Sources,
            memory: MemoryProofs.Loader,
            execution_memory: Memory.Loader,
            tables: Tables.Loader,
            programs: Programs.Loader,
            readonly_providers: if (ReadonlyPolicy.global) ?@import("block_v5_readonly_input_global_provider_loader_v2.zig").Loader else void = if (ReadonlyPolicy.global) null else {},
        };
        pub const VerifiedGlobals = struct {
            native_program_memory_tables_registers_endpoints_closed: void = {},
            seal_digest: [32]u8,
            span: Spans.Span,
            config: core.pcs.PcsConfig,
            execution_count: u32,
            lookup_groups: u32,
            program_fetches: u64,
            memory_events: u64,
            byte_requests: u64,
            initial_rw_root: [32]u8,
            final_rw_root: [32]u8,
            /// This output attests base proofs and global closures, not compression.
            exact_recursive_forest: enum { pending, verified } = .pending,
        };

        pub const RecursiveLeafPin = struct {
            key: LeafProtocol.Key,
            expected_id: [32]u8,
            schedule: []const LeafBus.Wire,
        };
        pub const RecursivePins = struct {
            leaves: []const RecursiveLeafPin,
            parents: []const Exact.NodePin,
            outer: Exact.NodePin,
            file: Exact.FilePin,

            /// Reject weaker recursive setups before any base proof is consumed.
            /// Full value/span admission still happens after fresh global closure.
            pub fn validate(self: RecursivePins, config: core.pcs.PcsConfig, execution_count: usize) !void {
                if (self.leaves.len != execution_count) return error.InvalidV5CompleteRecursiveRoster;
                for (self.leaves) |leaf| {
                    if (!std.meta.eql(leaf.key.config, config) or !std.meta.eql(leaf.key.context.child_config, config))
                        return error.V5CompleteRecursiveSecurityMismatch;
                    if (!std.meta.eql(try leaf.key.identity(), leaf.expected_id) or
                        !std.meta.eql(try LeafBus.scheduleDigest(leaf.schedule), leaf.key.public_schedule_digest))
                        return error.UntrustedV5CompleteRecursiveKey;
                }
                for (self.parents) |parent| try validateParent(parent, config);
                try validateParent(self.outer, config);
            }
            fn validateParent(parent: Exact.NodePin, config: core.pcs.PcsConfig) !void {
                if (!std.meta.eql(parent.key.config, config) or !std.meta.eql(parent.key.context.child_config, config))
                    return error.V5CompleteRecursiveSecurityMismatch;
                if (!std.meta.eql(try parent.key.identity(), parent.expected_id) or
                    !std.meta.eql(try ParentBus.scheduleDigest(parent.schedule), parent.key.public_schedule_digest))
                    return error.UntrustedV5CompleteRecursiveKey;
            }
        };
        pub const CompleteBundle = struct {
            globals: VerifiedGlobals,
            recursive: Exact.Verified,
            pub fn deinit(self: *CompleteBundle) void {
                self.recursive.deinit();
                self.* = undefined;
            }
        };
        pub const DetachedForest = struct {
            dir: std.fs.Dir,
            manifest_sha256: [32]u8,
            limits: Manifest.Limits,
        };

        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const MemoryJoin = Memory.ForBackend(Backend);
                const TableJoin = Tables.ForBackend(Backend);
                const Hooks = struct {
                    memory: *MemoryJoin,
                    tables: *TableJoin,
                    native_receipts: []Native.OpenReceipt,
                    memory_pins: []const FusedReceiver.MemoryPin,
                    readonly_join: if (ReadonlyPolicy.global) *@import("block_v5_readonly_input_global_join_v2.zig").Owned else void,
                    fn onFused(raw: *anyopaque, a: std.mem.Allocator, index: u32, pin: Programs.InstancePin, fresh: *const Native.OpenReceipt, fused: *const Fused.Verified) !void {
                        const self: *@This() = @ptrCast(@alignCast(raw));
                        try self.memory.onFusedNative(index, pin, fresh, if (fused.memory) |*receipt| receipt else null);
                        try self.tables.onFusedNative(a, index, pin, fresh, self.memory_pins[index], if (fused.projections) |*receipt| receipt else null);
                        self.native_receipts[index] = fresh.*;
                    }
                    fn onReadonlyCaller(raw: *anyopaque, a: std.mem.Allocator, index: u32, pin: Programs.ExtensionPin, fresh: *const Caller.OpenReceipt, fused: *const ReadonlyPolicy.CallerProof.Verified) !void {
                        const self: *@This() = @ptrCast(@alignCast(raw));
                        try self.memory.onReadonlyPrecompile(index, pin, fresh, fused);
                        try self.tables.onFusedPrecompile(a, index, pin, fresh, &fused.state, &fused.tables);
                        if (ReadonlyPolicy.global) try self.readonly_join.caller(fused);
                    }
                    fn onFusedCaller(raw: *anyopaque, a: std.mem.Allocator, index: u32, pin: Programs.ExtensionPin, fresh: *const Caller.OpenReceipt, fused: *const CallerFused.Verified) !void {
                        const self: *@This() = @ptrCast(@alignCast(raw));
                        try self.memory.onFusedPrecompile(index, pin, fresh, &fused.memory);
                        try self.tables.onFusedPrecompile(a, index, pin, fresh, &fused.state, &fused.tables);
                    }
                };

                const Fresh = struct {
                    summary: VerifiedGlobals,
                    native_open_sum: Q,
                    receipts: []Native.OpenReceipt,
                    fn deinit(self: *Fresh, a: std.mem.Allocator) void {
                        a.free(self.receipts);
                        self.* = undefined;
                    }
                };
                const DetachedTransport = struct {
                    detached: DetachedForest,
                    file: Exact.FilePin,
                    fn verify(self: @This(), alloc: std.mem.Allocator, leaves: []const Exact.LeafPolicy, parents: []const Exact.NodePin, outer: Exact.NodePin, public_pins: Exact.OuterPins, open_sum: Q) !Exact.Verified {
                        return Manifest.verifyDetachedPinned(alloc, self.detached.dir, self.detached.manifest_sha256, leaves, parents, outer, self.file, public_pins, open_sum, self.detached.limits);
                    }
                };
                pub fn verifyGlobals(a: std.mem.Allocator, pins: Pins, inputs: Inputs) !VerifiedGlobals {
                    var fresh = try verifyFresh(a, pins, inputs);
                    defer fresh.deinit(a);
                    return fresh.summary;
                }
                /// Fresh original native/caller/provider/global loop with a
                /// genuine PAGE/lane/range source receiver selected internally.
                pub fn verifyGlobalsWithSourcePages(a: std.mem.Allocator, pins: Pins, inputs: Inputs, source: SourcePages) !VerifiedGlobals {
                    if (ReadonlyPolicy.global) return error.ReadonlySourcePageRecursiveClosurePending else {
                        var fresh = try verifyFreshSelected(true, a, pins, inputs, source);
                        defer fresh.deinit(a);
                        return fresh.summary;
                    }
                }
                pub fn verifyComplete(a: std.mem.Allocator, pins: Pins, inputs: Inputs, recursion: RecursivePins, loader: anytype) !CompleteBundle {
                    const Transport = struct {
                        loader: @TypeOf(loader),
                        file: Exact.FilePin,
                        fn verify(self: @This(), alloc: std.mem.Allocator, leaves: []const Exact.LeafPolicy, parents: []const Exact.NodePin, outer: Exact.NodePin, public_pins: Exact.OuterPins, open_sum: Q) !Exact.Verified {
                            return Exact.verifyLoaded(alloc, self.loader, self.file, leaves, parents, outer, public_pins, open_sum);
                        }
                    };
                    return verifyWithTransport(a, pins, inputs, recursion, Transport{ .loader = loader, .file = recursion.file });
                }
                /// Manifest/file metadata cannot supply native receipts or recursive
                /// policy. Both transport modes share the exact fresh global receive
                /// loop and rebuild policies from the same independent base pins.
                pub fn verifyCompleteDetached(a: std.mem.Allocator, pins: Pins, inputs: Inputs, recursion: RecursivePins, detached: DetachedForest) !CompleteBundle {
                    return verifyWithTransport(a, pins, inputs, recursion, DetachedTransport{ .detached = detached, .file = recursion.file });
                }
                pub fn verifyCompleteDetachedWithSourcePages(a: std.mem.Allocator, pins: Pins, inputs: Inputs, source: SourcePages, recursion: RecursivePins, detached: DetachedForest) !CompleteBundle {
                    if (ReadonlyPolicy.global) return error.ReadonlySourcePageRecursiveClosurePending else return verifyWithTransportSelected(true, a, pins, inputs, source, recursion, DetachedTransport{ .detached = detached, .file = recursion.file });
                }
                fn verifyWithTransport(a: std.mem.Allocator, pins: Pins, inputs: Inputs, recursion: RecursivePins, transport: anytype) !CompleteBundle {
                    return verifyWithTransportSelected(false, a, pins, inputs, {}, recursion, transport);
                }
                fn verifyWithTransportSelected(comptime pages: bool, a: std.mem.Allocator, pins: Pins, inputs: Inputs, source: if (pages) SourcePages else void, recursion: RecursivePins, transport: anytype) !CompleteBundle {
                    // Metadata is independent of produced proof bytes. Do not load the
                    // outer proof or accept a receipt until all global joins close.
                    const sealed = try pins.validate();
                    try recursion.validate(pins.tables.seal.config, pins.tables.executions.len);
                    var fresh = try verifyFreshSelected(pages, a, pins, inputs, source);
                    defer fresh.deinit(a);
                    const prepared = try a.alloc(NativeRecursive.Prepared, recursion.leaves.len);
                    defer a.free(prepared);
                    var initialized: usize = 0;
                    defer for (prepared[0..initialized]) |*value| value.deinit();
                    const policies = try a.alloc(Exact.LeafPolicy, recursion.leaves.len);
                    defer a.free(policies);
                    for (pins.tables.executions, recursion.leaves, fresh.receipts, policies, 0..) |pin, setup, exported, *policy, index| {
                        prepared[index] = try prepareRecursive(a, pin, @intCast(index), sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
                        initialized += 1;
                        prepared[index].reusable_public_inputs = true;
                        policy.* = .{ .native = &prepared[index], .exported = exported, .recursive_key = setup.key, .recursive_key_id = setup.expected_id, .recursive_schedule = setup.schedule };
                    }
                    const span = fresh.summary.span;
                    var recursive = try transport.verify(a, policies, recursion.parents, recursion.outer, .{
                        .job_id = span.job_id,
                        .source_image_digest = span.source_image_digest,
                        .sealed_digest = span.sealed_digest,
                        .segment_count = span.segment_count,
                        .first_cycle = span.first_cycle,
                        .last_cycle = span.last_cycle,
                        .initial_pc = span.initial_pc,
                        .final_pc = span.final_pc,
                    }, fresh.native_open_sum);
                    errdefer recursive.deinit();
                    if (!std.meta.eql(recursive.sealed_digest, sealed.digest) or !std.meta.eql(recursive.span, span) or
                        recursive.execution_count != fresh.summary.execution_count) return error.UntrustedV5CompleteRecursiveSpan;
                    var summary = fresh.summary;
                    summary.exact_recursive_forest = .verified;
                    return .{ .globals = summary, .recursive = recursive };
                }
                fn verifyFresh(a: std.mem.Allocator, pins: Pins, inputs: Inputs) !Fresh {
                    return verifyFreshSelected(false, a, pins, inputs, {});
                }
                fn verifyFreshSelected(comptime pages: bool, a: std.mem.Allocator, pins: Pins, inputs: Inputs, source: if (pages) SourcePages else void) !Fresh {
                    const sealed = try pins.validate();
                    if (pages and pins.memory.readonly != null) return error.ReadonlySourcePageRecursiveClosurePending;
                    var readonly_join: if (ReadonlyPolicy.global) @import("block_v5_readonly_input_global_join_v2.zig").Owned else void = if (ReadonlyPolicy.global) joined: {
                        const selected = pins.memory.readonly orelse return error.MissingReadonlyMemoryPolicy;
                        try @import("block_v5_readonly_input_global_provider_loader_v2.zig").require(inputs.readonly_providers, selected.roster);
                        break :joined try @import("block_v5_readonly_input_global_join_v2.zig").Owned.init(a, selected.roster, sealed, .{});
                    } else {};
                    defer if (ReadonlyPolicy.global) readonly_join.deinit();
                    const receipts = try a.alloc(Native.OpenReceipt, pins.tables.executions.len);
                    errdefer a.free(receipts);
                    const memory_pins = try a.alloc(FusedReceiver.MemoryPin, pins.tables.executions.len);
                    defer a.free(memory_pins);
                    for (pins.tables.executions, memory_pins, 0..) |pin, *memory_pin, index| memory_pin.* = .{
                        .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = pin.shape.public_data.clock },
                        .expected_events = pins.memory.ordinary_events[index],
                        .witness_root = pins.memory.opcode_witness_roots[index],
                    };
                    const caller_memory = try a.alloc(Programs.CallerMemoryPin, pins.memory.extensions.len);
                    defer a.free(caller_memory);
                    for (pins.memory.extensions, caller_memory, 0..) |pin, *memory_pin, extension_index| memory_pin.* = .{
                        .frame = memory_pins[pin.public.execution_index].frame,
                        .witness_root = pin.witness_root,
                        .expected_rw_events = try CallerExternal.expectedEventCountForMode(pin.public.statement, sealed.register_custody_mode),
                        .readonly = if (pins.memory.readonly) |selected| (if (ReadonlyPolicy.global) try selected.callerAuthority(sealed, extension_index) else selected.authority) else null,
                        .readonly_census = if (pins.memory.readonly) |selected| if (extension_index < selected.caller.len) selected.caller[extension_index] else return error.StaleReadonlyInputCensus else null,
                    };
                    // Reject all independently supplied native/catalog/ROM,
                    // caller and fused geometry before consuming any RAM or
                    // lookup provider proof. This is metadata admission only.
                    try Programs.ForBackend(Backend).admitRoster(a, pins.tables.seal, pins.tables.roster, sealed, pins.tables.catalog, pins.program, pins.tables.executions, pins.tables.extensions, memory_pins, caller_memory, inputs.programs);
                    var memory_join = if (pages)
                        try PageMemory.ForStack(Stack).init(Backend, a, pins.memory, inputs.public_input, source, inputs.execution_memory, sealed)
                    else if (ReadonlyPolicy.global)
                        try MemoryJoin.initWithGlobalReadonly(a, pins.memory, inputs.public_input, inputs.endpoint_sources, inputs.memory, inputs.execution_memory, sealed, &readonly_join)
                    else
                        try MemoryJoin.init(a, pins.memory, inputs.public_input, inputs.endpoint_sources, inputs.memory, inputs.execution_memory, sealed);
                    defer memory_join.deinit();
                    var table_join = try TableJoin.init(a, pins.tables, sealed, inputs.tables);
                    defer table_join.deinit();
                    var hooks = Hooks{ .memory = &memory_join, .tables = &table_join, .native_receipts = receipts, .memory_pins = memory_pins, .readonly_join = if (ReadonlyPolicy.global) &readonly_join else {} };
                    const programs = try Programs.ForBackend(Backend).verifyWithCompositeHooks(a, pins.tables.seal, pins.tables.roster, sealed, pins.tables.catalog, pins.program, pins.tables.executions, pins.tables.extensions, memory_pins, caller_memory, inputs.programs, .{ .context = &hooks, .on_fused = Hooks.onFused, .on_fused_caller = Hooks.onFusedCaller, .on_readonly_caller = Hooks.onReadonlyCaller });
                    if (ReadonlyPolicy.global) {
                        const selected = pins.memory.readonly orelse return error.MissingReadonlyMemoryPolicy;
                        try @import("block_v5_readonly_input_global_provider_loader_v2.zig").verifyAll(Backend, a, inputs.readonly_providers, selected.roster, sealed, pins.tables.seal, pins.tables.roster, &readonly_join);
                        const classified = try readonly_join.finish();
                        var actual_events: u64 = 0;
                        for (memory_join.byte_parts) |part| actual_events = try std.math.add(u64, actual_events, part.event_count);
                        if (classified.all_rw_events != actual_events or classified.readonly_events != memory_join.readonly_count or
                            classified.mutable_events != memory_join.fresh_memory.event_count or !classified.mutable_sum.eql(memory_join.transition_sum)) return error.UnclosedGlobalReadonlyMemoryPartition;
                    }
                    var joined = try table_join.finish(&memory_join);
                    defer joined.deinit(a);
                    // Each bus/census has already closed independently. This final
                    // accounting equation rejects any unpartitioned native obligation.
                    const residual = @import("block_v5_global_join_algebra_v1.zig").Algebra(Q).residual(.{
                        .native_open_sum = programs.native_open_sum,
                        .precompile_open_sum = programs.precompile_open_sum,
                        .public_program_boundary_sum = programs.public_program_boundary_sum,
                        .program_provider_sum = programs.program_provider_sum,
                        .table_provider_sum = joined.tables.provider_sum,
                        .ordinary_memory_opposite = joined.memory.ordinary_memory_opposite,
                        .external_memory_opposite = joined.memory.external_memory_opposite,
                        .auxiliary_clock_memory_sum = joined.tables.auxiliary_clock_memory_sum,
                        .register_compensation_sum = joined.tables.register_compensation_sum,
                    }, joined.memory.bytes);
                    var requests: u64 = 0;
                    for (joined.memory.bytes) |part| {
                        requests = try std.math.add(u64, requests, part.request_count);
                    }
                    if (!residual.isZero()) return error.UnclosedV5GlobalAccounting;
                    return .{ .receipts = receipts, .native_open_sum = programs.native_open_sum, .summary = .{ .seal_digest = sealed.digest, .span = try blockSpan(pins.tables.executions, sealed), .config = pins.tables.seal.config, .execution_count = sealed.execution_instance_count, .lookup_groups = joined.tables.group_count, .program_fetches = programs.fetch_count, .memory_events = joined.memory.memory.event_count, .byte_requests = requests, .initial_rw_root = joined.memory.memory.initial_rw_root, .final_rw_root = joined.memory.memory.final_rw_root } };
                }
            };
        }

        /// Rebuilds owned recursive geometry from independent receiver pins.
        /// This prepares no proof or receipt and supplies no native authority.
        pub fn prepareRecursive(a: std.mem.Allocator, pin: Programs.InstancePin, index: u32, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, catalog: Stack.Catalog.Admission) !NativeRecursive.Prepared {
            if (Stack.is_capacity) return NativeRecursive.Prepared.init(a, pin.shape, pin.external_retirements, pin.admission, pin.template, pin.template_id, index, sealed, pins, roster, catalog, pin.limits.native);
            return NativeRecursive.Prepared.init(a, pin.shape, pin.admission, pin.template, pin.template_id, index, sealed, pins, roster, catalog);
        }
        fn sameRoster(left: []const Seal.Entry, right: []const Seal.Entry) bool {
            if (left.len != right.len) return false;
            for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
            return true;
        }
        fn blockSpan(executions: []const Programs.InstancePin, sealed: Seal.Sealed) !Spans.Span {
            if (executions.len == 0 or executions.len != sealed.execution_instance_count) return error.InvalidV5GlobalExecutionCount;
            var span = try Spans.leaf(executions[0].admission, executions[0].shape, sealed.digest, sealed.execution_instance_count);
            for (executions[1..]) |pin| span = try Spans.merge(&.{ span, try Spans.leaf(pin.admission, pin.shape, sealed.digest, sealed.execution_instance_count) });
            if (span.first_index != 0 or span.segment_count != sealed.execution_instance_count) return error.IncompleteV5GlobalSpan;
            return span;
        }
    };
}
