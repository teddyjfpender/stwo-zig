//! Private fresh-hook join. Six table buses close per field-safe execution
//! group; PC/clock closes per leaf. No public receipt creates block authority.
pub fn ForStack(comptime Stack: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const Programs = Stack.Programs;
        const Native = Stack.Native;
        const Template = Stack.Template;
        const Catalog = Stack.Catalog;
        const Projection = @import("block_v5_native_lookup_request_proof_v1.zig");
        const Fused = struct {
            pub const VerifiedReceipt = Stack.ProjectionReceipt;
        };
        const FusedReceiver = Stack.FusedReceiver;
        const FusedSource = Stack.FusedSource;
        const Source = @import("block_v5_native_lookup_request_source_v1.zig");
        const EmptyNative = @import("block_v5_empty_native_tables_v1.zig");
        const Providers = @import("block_v5_native_lookup_proof_v1.zig");
        const Batch = @import("block_v5_native_lookup_batch_v1.zig");
        const Planning = @import("block_v5_native_lookup_plan_v1.zig");
        const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
        const Bytes = @import("block_v5_memory_byte_demand_v1.zig");
        const External = @import("block_execution_external_trace_v2.zig");
        const Family11 = @import("block_v5_precompile_family_proof_v1.zig");
        const State = @import("block_v5_precompile_state_request_proof_v1.zig");
        const CallerTables = @import("block_v5_precompile_lookup_proof_v1.zig");
        const CallerDemand = @import("block_v5_precompile_table_demand_v1.zig");
        const Seal = @import("block_v5_source_seal_v1.zig");
        const Schema = @import("../air/lookups/tables/schema.zig");
        const Universal = @import("../recursion/air/universal_challenges.zig");
        const Shared = @import("../recursion/air/universal_provider_relations.zig");
        const Tables = @import("block_v5_native_lookup_request_receiver_v1.zig");
        const Registers = @import("block_v5_register_windows_v1.zig");

        pub const Pins = struct {
            seal: Seal.Pins,
            roster: []const Seal.Entry,
            catalog: Catalog.Admission,
            executions: []const Programs.InstancePin,
            ordinary_events: []const u64,
            extensions: []const Programs.ExtensionPin,
            providers: []const Batch.Record,
            register_windows: ?Registers.Plan = null,
        };
        pub const Loader = struct {
            context: *anyopaque,
            take_projection: ?*const fn (*anyopaque, u32) anyerror!Projection.Proof = null,
            take_provider: *const fn (*anyopaque, u32) anyerror!Providers.Proof,
            take_caller_state: ?*const fn (*anyopaque, u32) anyerror!State.Proof = null,
            take_caller_tables: ?*const fn (*anyopaque, u32) anyerror!CallerTables.Proof = null,
        };
        pub const Joined = struct {
            tables: Tables.ClosedNativeTables,
            memory: Memory.OpenPartition,
            pub fn deinit(self: *Joined, a: std.mem.Allocator) void {
                self.memory.deinit(a);
                self.* = undefined;
            }
        };

        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const Self = @This();
                a: std.mem.Allocator,
                pins: Pins,
                sealed: Seal.Sealed,
                loader: Loader,
                provider_claims: [][Schema.KIND_COUNT]Q,
                native_claims: [][Schema.KIND_COUNT]Q,
                state_claims: []Q,
                register_claims: []Q,
                expected_events: []u64,
                auxiliary_clock_memory_sum: Q = Q.zero(),
                caller_table_sum: Q = Q.zero(),
                register_compensation_sum: Q = Q.zero(),
                next_native: u32 = 0,
                next_extension: u32 = 0,
                finished: bool = false,

                pub fn init(a: std.mem.Allocator, pins: Pins, sealed: Seal.Sealed, loader: Loader) !Self {
                    try sealed.require(pins.seal, pins.roster);
                    const recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
                    try recipe.requireMode(sealed.register_custody_mode);
                    for (pins.executions) |pin| try recipe.requireNative(pin.shape);
                    for (pins.extensions) |pin| try recipe.requireCaller(pin.statement, pin.total_steps);
                    if (sealed.register_custody_mode == 1) {
                        const windows = pins.register_windows orelse return error.MissingV5RegisterWindowPlan;
                        try recipe.requireWindowVersion(windows.version);
                        if (windows.windows.len != pins.executions.len or !std.meta.eql(try windows.digest(), sealed.register_endpoint_plan_digest)) return error.UntrustedV5RegisterWindowPlan;
                        for (pins.executions, windows.windows, 0..) |execution, window, index| {
                            try windows.requireNative(execution.shape);
                            try window.requirePublic(@intCast(index), execution.admission.context.first_cycle, &execution.shape.public_data);
                        }
                        for (pins.extensions) |extension| try windows.requireCaller(extension.statement);
                    } else if (pins.register_windows != null) return error.UntrustedV5RegisterCustodyMode;
                    if (pins.executions.len != sealed.execution_instance_count or pins.executions.len == 0 or
                        pins.executions.len != pins.ordinary_events.len or
                        pins.extensions.len != pins.seal.counts[@intFromEnum(Seal.Family.precompile) - 1] or
                        pins.providers.len != pins.seal.counts[@intFromEnum(Seal.Family.native_lookup) - 1] or
                        !std.meta.eql(try pins.catalog.digest(), pins.seal.native_template_catalog_digest)) return error.UntrustedV5TableJoinPins;
                    const demands = try a.alloc([Schema.KIND_COUNT]u64, pins.executions.len);
                    defer a.free(demands);
                    const expected_events = try a.dupe(u64, pins.ordinary_events);
                    errdefer a.free(expected_events);
                    for (pins.extensions, 0..) |extension, i| {
                        if (extension.execution_index >= pins.executions.len or
                            (i != 0 and extension.execution_index <= pins.extensions[i - 1].execution_index)) return error.InvalidV5TableCallerRoster;
                        expected_events[extension.execution_index] = try std.math.add(u64, expected_events[extension.execution_index], try External.expectedEventCountForMode(extension.statement, sealed.register_custody_mode));
                    }
                    for (pins.executions, demands, 0..) |pin, *demand, i| {
                        try pin.admission.require(pins.seal, &pin.shape.public_data);
                        try pins.catalog.admit(pins.seal, sealed, @intCast(i), pin.template, pin.template_id);
                        _ = try Bytes.opcodeDemandFromShapeForMode(a, pin.shape, frame(pin), pins.ordinary_events[i], sealed.register_custody_mode);
                        const companion = extensionAt(pins.extensions, @intCast(i));
                        const external_count = if (companion) |value| @import("blake3_ethereum_sha_profile.zig").externalCount(value.statement) else 0;
                        if (Programs.externalRetirements(pin) != external_count) return error.UntrustedV5TableCallerRoster;
                        demand.* = try Planning.nativeDemand(pin.shape, external_count);
                        try Planning.addDemand(demand, try Planning.sidecarMemoryDemand(expected_events[i]));
                        if (companion) |value| try CallerDemand.add(a, demand, value.statement, value.total_steps, pins.seal.config);
                    }
                    const plans = try a.alloc(Planning.Plan, pins.providers.len);
                    defer a.free(plans);
                    for (pins.providers, plans) |record, *plan| plan.* = record.plan;
                    try Planning.validateDemandRoster(plans, demands);
                    const provider_claims = try a.alloc([Schema.KIND_COUNT]Q, pins.providers.len);
                    errdefer a.free(provider_claims);
                    const native_claims = try a.alloc([Schema.KIND_COUNT]Q, pins.executions.len);
                    errdefer a.free(native_claims);
                    @memset(native_claims, @splat(Q.zero()));
                    const state_claims = try a.alloc(Q, pins.executions.len);
                    errdefer a.free(state_claims);
                    @memset(state_claims, Q.zero());
                    const register_claims = try a.alloc(Q, pins.executions.len);
                    errdefer a.free(register_claims);
                    @memset(register_claims, Q.zero());
                    const Api = Providers.ForBackend(Backend);
                    var basis = try Api.FixedBasis.init(a, pins.seal.config);
                    defer basis.deinit(a);
                    for (pins.providers, provider_claims) |record, *claims| {
                        const fresh = try Api.verifyOwnedWithBasis(a, try loader.take_provider(loader.context, record.plan.index), record.plan, record.roots, sealed, pins.seal, pins.roster, &basis);
                        claims.* = fresh.claims;
                    }
                    return .{ .a = a, .pins = pins, .sealed = sealed, .loader = loader, .provider_claims = provider_claims, .native_claims = native_claims, .state_claims = state_claims, .register_claims = register_claims, .expected_events = expected_events };
                }
                pub fn deinit(self: *Self) void {
                    self.a.free(self.expected_events);
                    self.a.free(self.state_claims);
                    self.a.free(self.register_claims);
                    self.a.free(self.native_claims);
                    self.a.free(self.provider_claims);
                    self.* = undefined;
                }
                fn beginNative(self: *Self, index: u32, callback: Programs.InstancePin, fresh: *const Native.OpenReceipt) !void {
                    if (self.finished or index != self.next_native or index >= self.pins.executions.len) return error.InvalidV5TableNativeHookOrder;
                    const pin = self.pins.executions[index];
                    if (Programs.externalRetirements(callback) != Programs.externalRetirements(pin) or callback.profile != pin.profile) return error.UntrustedV5TableNativeHook;
                    if (Stack.is_capacity) {
                        if (!std.meta.eql(callback.limits, pin.limits) or !std.meta.eql(fresh.exact_geometry_digest, try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(pin.shape, pin.external_retirements))) return error.UntrustedV5TableNativeHook;
                        try pin.limits.requireShape(pin.shape, pin.external_retirements);
                    }
                    if (!std.meta.eql(callback.admission.expected_id, pin.admission.expected_id) or !std.meta.eql(callback.template_id, pin.template_id) or
                        !std.meta.eql(fresh.template_id, pin.template_id) or !std.meta.eql(fresh.sealed_digest, self.sealed.digest) or
                        !std.meta.eql(try Programs.expectedInstance(pin, fresh.first_roots, index), fresh.instance_id)) return error.UntrustedV5TableNativeHook;
                    var channel = self.sealed.sharedChannel();
                    const relations = try Universal.UniversalRelations.draw(self.a, &channel);
                    const native_relations = try Shared.SharedProviderRelations.init(&relations);
                    self.state_claims[index] = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &pin.shape.public_data, &native_relations.native);
                    if (self.pins.register_windows) |windows| {
                        const compensation = try windows.compensation(index, &native_relations.native);
                        self.register_claims[index] = compensation;
                        self.register_compensation_sum = self.register_compensation_sum.add(compensation);
                    }
                }
                /// Canonical Global invokes this only with the fused receipt returned
                /// inside its fresh native/program verification. No second projection
                /// load/proof is admitted; group and register obligations stay separate.
                pub fn onFusedNative(self: *Self, _: std.mem.Allocator, index: u32, callback: Programs.InstancePin, fresh: *const Native.OpenReceipt, memory: FusedReceiver.MemoryPin, projection: ?*const Fused.VerifiedReceipt) !void {
                    try self.beginNative(index, callback, fresh);
                    const pin = self.pins.executions[index];
                    const slots = try FusedSource.slotsFromShapeForMode(self.a, pin.shape, Programs.externalRetirements(pin), self.sealed.register_custody_mode);
                    defer self.a.free(slots);
                    if (memory.expected_events != self.pins.ordinary_events[index]) return error.UntrustedV5TableFusedMemoryCensus;
                    _ = try FusedReceiver.admit(self.a, index, Programs.fusedPin(pin), memory, self.sealed, self.pins.seal, self.pins.roster, self.pins.catalog);
                    if (projection) |verified| {
                        if (slots.len == 0) return error.UnexpectedV5EmptyFusedProjection;
                        if (verified.execution_index != index or !std.meta.eql(verified.sealed_digest, self.sealed.digest) or
                            !std.meta.eql(verified.native_key_id, pin.template_id) or !std.meta.eql(verified.native_instance_id, fresh.instance_id) or
                            !std.meta.eql(verified.native_roots, fresh.first_roots)) return error.UntrustedV5TableFusedHook;
                        self.native_claims[index] = verified.claims;
                        self.state_claims[index] = self.state_claims[index].add(verified.registers_state_sum);
                        self.auxiliary_clock_memory_sum = self.auxiliary_clock_memory_sum.add(verified.auxiliary_clock_memory_sum);
                        self.register_claims[index] = self.register_claims[index].add(verified.register_memory_sum).add(verified.register_clock_memory_sum);
                    } else {
                        if (slots.len != 0) return error.MissingV5FusedProjectionReceipt;
                        const empty = try emptyFromFresh(self.a, pin, self.pins.catalog, fresh, index, self.sealed, self.pins.seal, self.pins.roster);
                        self.native_claims[index] = empty.claims;
                        self.state_claims[index] = empty.public_state_sum;
                        self.auxiliary_clock_memory_sum = self.auxiliary_clock_memory_sum.add(empty.auxiliary_clock_memory_sum);
                    }
                    self.next_native += 1;
                }
                /// Explicit old separate-projection hook, outside canonical Global.
                pub fn onNative(self: *Self, _: std.mem.Allocator, index: u32, callback: Programs.InstancePin, fresh: *const Native.OpenReceipt) !void {
                    if (Stack.is_capacity) {
                        return error.UnsupportedCapacitySeparateProjection;
                    } else {
                        try self.beginNative(index, callback, fresh);
                        const pin = self.pins.executions[index];
                        const slots = try Source.slotsFromShapeForMode(self.a, pin.shape, Programs.externalRetirements(pin), self.sealed.register_custody_mode);
                        defer self.a.free(slots);
                        if (slots.len != 0) {
                            const fixed = try Template.columnLogs(self.a, pin.shape, Programs.externalRetirements(pin), .fixed);
                            defer self.a.free(fixed);
                            const main = try Template.columnLogs(self.a, pin.shape, Programs.externalRetirements(pin), .main);
                            defer self.a.free(main);
                            const projection = try Projection.ForBackend(Backend).verifyOwned(self.a, try (self.loader.take_projection orelse return error.MissingV5SeparateProjectionLoader)(self.loader.context, index), self.sealed, index, pin.template_id, fresh.instance_id, slots, fixed, main, fresh.first_roots, fresh.first_roots, self.pins.seal.config);
                            self.native_claims[index] = projection.claims;
                            self.state_claims[index] = self.state_claims[index].add(projection.registers_state_sum);
                            self.auxiliary_clock_memory_sum = self.auxiliary_clock_memory_sum.add(projection.auxiliary_clock_memory_sum);
                            self.register_claims[index] = self.register_claims[index].add(projection.register_memory_sum).add(projection.register_clock_memory_sum);
                        } else {
                            const empty = try emptyFromFresh(self.a, pin, self.pins.catalog, fresh, index, self.sealed, self.pins.seal, self.pins.roster);
                            self.native_claims[index] = empty.claims;
                            self.state_claims[index] = empty.public_state_sum;
                            self.auxiliary_clock_memory_sum = self.auxiliary_clock_memory_sum.add(empty.auxiliary_clock_memory_sum);
                        }
                        self.next_native += 1;
                    }
                }
                /// The family11 fresh callback supplies authenticated caller roots;
                /// only their independently pinned same-root state proof closes PC.
                pub fn onPrecompile(self: *Self, a: std.mem.Allocator, index: u32, callback: Programs.ExtensionPin, fresh: *const Family11.OpenReceipt) !void {
                    if (self.finished or self.next_extension >= self.pins.extensions.len or index >= self.next_native)
                        return error.InvalidV5TableCallerHookOrder;
                    const expected = self.pins.extensions[self.next_extension];
                    if (expected.execution_index != index or callback.execution_index != index or callback.total_steps != expected.total_steps or
                        !std.meta.eql(callback.expected_key_id, expected.expected_key_id) or
                        !std.meta.eql(fresh.binding.caller_key_id, expected.expected_key_id) or
                        !std.meta.eql(fresh.binding.sealed_digest, self.sealed.digest)) return error.UntrustedV5TableCallerHook;
                    const state = try State.ForBackend(Backend).verifyOwned(self.a, try (self.loader.take_caller_state orelse return error.MissingV5CallerStateLoader)(self.loader.context, index), self.sealed, self.pins.seal, self.pins.roster, fresh, expected.statement, expected.total_steps);
                    const tables = try CallerTables.ForBackend(Backend).verifyOwned(self.a, try (self.loader.take_caller_tables orelse return error.MissingV5CallerTablesLoader)(self.loader.context, index), self.sealed, self.pins.seal, self.pins.roster, fresh, expected.statement, expected.total_steps);
                    try self.onFusedPrecompile(a, index, callback, fresh, &state, &tables);
                }
                /// Private scoped consumer of the composite freshly verified in the
                /// same enclosing Programs loop; never a detached receipt loader.
                pub fn onFusedPrecompile(self: *Self, _: std.mem.Allocator, index: u32, callback: Programs.ExtensionPin, fresh: *const Family11.OpenReceipt, state: *const State.Receipt, tables: *const CallerTables.Receipt) !void {
                    if (self.finished or self.next_extension >= self.pins.extensions.len or index >= self.next_native)
                        return error.InvalidV5TableCallerHookOrder;
                    const expected = self.pins.extensions[self.next_extension];
                    if (expected.execution_index != index or callback.execution_index != index or callback.total_steps != expected.total_steps or
                        !std.meta.eql(callback.expected_key_id, expected.expected_key_id) or
                        !std.meta.eql(fresh.binding.caller_key_id, expected.expected_key_id) or
                        !std.meta.eql(fresh.binding.sealed_digest, self.sealed.digest)) return error.UntrustedV5TableCallerHook;
                    if (state.caller_count != Programs.externalRetirements(self.pins.executions[index]) or
                        !std.meta.eql(state.binding, fresh.binding)) return error.UntrustedV5TableCallerStateCensus;
                    if (!std.meta.eql(tables.binding, fresh.binding) or tables.memory_event_count != try External.expectedEventCount(expected.statement))
                        return error.UntrustedV5CallerTableCensus;
                    for (&self.native_claims[index], tables.claims) |*sum, claim| {
                        sum.* = sum.add(claim);
                        self.caller_table_sum = self.caller_table_sum.add(claim);
                    }
                    self.auxiliary_clock_memory_sum = self.auxiliary_clock_memory_sum.add(tables.auxiliary_clock_memory_sum);
                    self.register_claims[index] = self.register_claims[index].add(tables.register_memory_sum);
                    self.state_claims[index] = self.state_claims[index].add(state.sum);
                    self.next_extension += 1;
                }
                /// Byte claims come only from finishing the actual private memory join;
                /// no caller-supplied scalar/receipt is accepted by this entrypoint.
                pub fn finish(self: *Self, memory_join: *Memory.ForBackend(Backend)) !Joined {
                    if (self.finished or self.next_native != self.pins.executions.len or self.next_extension != self.pins.extensions.len or
                        !std.meta.eql(memory_join.sealed.digest, self.sealed.digest) or memory_join.pins.executions.len != self.pins.executions.len or
                        memory_join.pins.extensions.len != self.pins.extensions.len or
                        memory_join.pins.ordinary_events.len != self.pins.ordinary_events.len) return error.IncompleteV5TableHooks;
                    for (self.pins.executions, memory_join.pins.executions, self.pins.ordinary_events, memory_join.pins.ordinary_events) |pin, memory_pin, count, memory_count|
                        if (!std.meta.eql(pin.admission.expected_id, memory_pin.admission.expected_id) or count != memory_count) return error.UntrustedV5TableMemoryJoin;
                    for (self.pins.extensions, memory_join.pins.extensions) |pin, memory_pin|
                        if (pin.execution_index != memory_pin.public.execution_index or
                            pin.total_steps != memory_pin.public.total_steps or
                            !std.meta.eql(pin.expected_key_id, memory_pin.public.expected_key_id)) return error.UntrustedV5TableMemoryJoin;
                    var sink = @import("block_v5_global_join_algebra_v1.zig").ScalarSink{};
                    try @import("block_v5_global_join_algebra_v1.zig").Algebra(Q).states(&sink, self.state_claims);
                    try requireRegisterWindowsClosed(self.sealed.register_custody_mode, self.register_claims);
                    var partition = try memory_join.finish();
                    errdefer partition.deinit(self.a);
                    if (self.sealed.register_custody_mode == 1) partition.memory.register_endpoints_verified = true;
                    if (partition.bytes.len != self.expected_events.len) return error.UntrustedV5TableMemoryJoin;
                    for (partition.bytes, self.expected_events, 0..) |part, expected, index| {
                        const demand = try Planning.sidecarMemoryDemand(expected);
                        if (part.index != index or part.event_count != expected or part.request_count != demand[@intFromEnum(Schema.Kind.range_check_8_8)] or part.max_requests != part.request_count)
                            return error.UntrustedV5TableByteCensus;
                    }
                    var provider_sum = Q.zero();
                    var native_table_sum = Q.zero();
                    for (self.pins.providers, self.provider_claims) |record, supply| {
                        const end = @as(usize, record.plan.first_execution) + record.plan.execution_count;
                        const totals = try @import("block_v5_global_join_algebra_v1.zig").Algebra(Q).lookupGroup(&sink, supply, self.native_claims[record.plan.first_execution..end], partition.bytes[record.plan.first_execution..end]);
                        native_table_sum = native_table_sum.add(totals.consumer_table_sum);
                        provider_sum = provider_sum.add(totals.provider_sum);
                    }
                    self.finished = true;
                    return .{ .tables = .{ .execution_count = self.sealed.execution_instance_count, .group_count = @intCast(self.pins.providers.len), .seal_digest = self.sealed.digest, .provider_sum = provider_sum, .native_table_sum = native_table_sum.sub(self.caller_table_sum), .caller_table_sum = self.caller_table_sum, .auxiliary_clock_memory_sum = self.auxiliary_clock_memory_sum, .register_compensation_sum = self.register_compensation_sum }, .memory = partition };
                }
            };
        }
        fn requireRegisterWindowsClosed(mode: u32, claims: []const Q) !void {
            var sink = @import("block_v5_global_join_algebra_v1.zig").ScalarSink{};
            try @import("block_v5_global_join_algebra_v1.zig").Algebra(Q).registers(&sink, mode, claims);
        }
        test "register windows reject cancellation between different local clock domains" {
            const positive = Q.one();
            const negative = Q.zero().sub(positive);
            try std.testing.expect(positive.add(negative).isZero());
            try std.testing.expectError(error.UnclosedV5RegisterWindow, requireRegisterWindowsClosed(1, &.{ positive, negative }));
            try requireRegisterWindowsClosed(1, &.{ Q.zero(), Q.zero() });
        }
        fn frame(pin: Programs.InstancePin) @import("../air/block/memory_event.zig").Frame {
            return .{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = @intCast(pin.shape.public_data.clock) };
        }
        fn extensionAt(values: []const Programs.ExtensionPin, index: u32) ?Programs.ExtensionPin {
            for (values) |value| if (value.execution_index == index) return value;
            return null;
        }

        /// Capacity absence retains the genuine proved frame/PC obligation. No old
        /// receipt conversion is involved; frame equations still have to cancel the
        /// freshly verified caller state in finish().
        fn emptyFromFresh(a: std.mem.Allocator, pin: Programs.InstancePin, catalog: Catalog.Admission, fresh: *const Native.OpenReceipt, index: u32, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry) !EmptyNative.Partition {
            if (!Stack.is_capacity) return EmptyNative.fromFresh(a, .{ .shape = pin.shape, .admission = pin.admission, .template = pin.template, .template_id = pin.template_id, .catalog = catalog }, fresh, index, sealed, pins, roster);
            try EmptyNative.validateShape(a, pin.shape, pin.external_retirements);
            try Native.admitWithCatalog(a, pin.shape, pin.external_retirements, pin.admission, pin.template, pin.template_id, fresh.instance_id, fresh.first_roots, index, sealed, pins, roster, catalog);
            try pin.limits.requireShape(pin.shape, pin.external_retirements);
            if (!std.meta.eql(fresh.instance_id, try Programs.expectedInstance(pin, fresh.first_roots, index)) or
                !std.meta.eql(fresh.template_id, pin.template_id) or !std.meta.eql(fresh.sealed_digest, sealed.digest) or
                !std.meta.eql(fresh.first_roots[0], pin.template.fixed_root) or
                !std.meta.eql(fresh.exact_geometry_digest, try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(pin.shape, pin.external_retirements))) return error.UntrustedV5EmptyNativeTables;
            var found = false;
            for (roster) |entry| if (entry.family == .execution and entry.index == index) {
                if (found or !std.meta.eql(entry.instance_id, fresh.instance_id) or !std.meta.eql(entry.roots, fresh.first_roots)) return error.UntrustedV5EmptyNativeTables;
                found = true;
            };
            if (!found) return error.MissingV5EmptyNativeTables;
            var channel = sealed.sharedChannel();
            const universal = try Universal.UniversalRelations.draw(a, &channel);
            const relations = try Shared.SharedProviderRelations.init(&universal);
            const public_state_sum = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &pin.shape.public_data, &relations.native);
            if (!fresh.open_sum.eql(public_state_sum)) return error.UntrustedV5EmptyNativeOpenClaim;
            // validateShape proves both the lookup and clock infrastructures absent;
            // the native frame remains proof-attested and its public sum is retained.
            return .{ .claims = @splat(Q.zero()), .public_state_sum = public_state_sum, .auxiliary_clock_memory_sum = Q.zero() };
        }
    };
}
