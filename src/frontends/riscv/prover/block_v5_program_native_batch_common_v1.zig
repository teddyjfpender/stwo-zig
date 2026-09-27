//! Lightweight native-v3 program closure over fresh catalog-admitted proofs.
//! This receiver deliberately returns an OPEN native residual. Memory,
//! endpoint, public/provider and recursive obligations belong to the enclosing
//! block receiver. The legacy B3SHART1 bridge is a separate module.
const std = @import("std");
const core = @import("stwo_core");
const LegacyCatalog = @import("block_v5_native_template_catalog_v1.zig");
const Request = @import("block_v5_program_request_proof_v1.zig");
const Table = @import("block_v5_program_table_proof_v1.zig");
const Program = @import("block_v5_program_table_v1.zig");
const Boundary = @import("block_v5_program_boundary_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Shape = @import("../air/statement.zig");
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;
const universal = @import("../recursion/air/universal_challenges.zig");
const Precompile = @import("block_v5_precompile_family_proof_v1.zig");
const Caller = @import("block_v5_precompile_protocol_v1.zig");
const ExtensionRequest = @import("block_v5_program_extension_proof_v1.zig");
const ExtensionReceiver = @import("block_v5_program_extension_receiver_v1.zig");
const ExtensionProfile = @import("blake3_ethereum_sha_profile.zig");
const LegacyFused = @import("block_v5_native_projection_fused_proof_v2.zig");
const LegacyFusedSource = @import("block_v5_native_projection_fused_source_v1.zig");
const LegacyFusedReceiver = @import("block_v5_native_projection_fused_receiver_v2.zig");
const FusedMemory = @import("block_execution_sidecar_batch_v2.zig");
const DefaultCallerReadonly = @import("block_v5_caller_readonly_proof_v1.zig");
const DefaultCallerReadonlyReceiver = @import("block_v5_caller_readonly_receiver_v1.zig");
const CallerFused = @import("block_v5_caller_fused_proof_v1.zig");
const CallerReceiver = @import("block_v5_caller_fused_receiver_v1.zig");
const Q = core.fields.qm31.QM31;

/// Explicit native protocols share validation/closure logic without sharing
/// admission authority. Lightweight admits global public pins; v1 admits Plan.
pub fn ForNative(comptime Native: type, comptime Template: type, comptime Admission: type, comptime lightweight: bool) type {
    return ForNativeProtocol(Native, Template, Admission, lightweight, false);
}
/// The lightweight canonical route selects fused=true. Explicit old protocol
/// aliases retain their separate proof types without implicit dispatch/fallback.
pub fn ForNativeProtocol(comptime Native: type, comptime Template: type, comptime Admission: type, comptime lightweight: bool, comptime fused: bool) type {
    return ForNativeStack(Native, Template, Admission, lightweight, fused, LegacyStack);
}
const LegacyStack = struct {
    pub const capacity = false;
    pub const Catalog = LegacyCatalog;
    pub const Fused = LegacyFused;
    pub const Source = LegacyFusedSource;
    pub const Receiver = LegacyFusedReceiver;
};
/// One genuine fresh program/provider closure implementation. The stack chooses
/// distinct typed proof/catalog/fused authority; bytes cannot select a stack.
pub const DefaultReadonly = struct {
    pub const global = false;
    pub const CallerProof = DefaultCallerReadonly;
    pub const CallerReceiver = DefaultCallerReadonlyReceiver;
    pub const CallerAuthority = @import("block_v5_caller_readonly_protocol_v1.zig").Authority;
};
pub fn ForNativeStack(comptime Native: type, comptime Template: type, comptime Admission: type, comptime lightweight: bool, comptime fused: bool, comptime Stack: type) type {
    return ForNativeStackReadonly(Native, Template, Admission, lightweight, fused, Stack, DefaultReadonly);
}
/// Static independent protocol selection. The complete caller/program/native
/// verification loop below is shared verbatim; received bytes choose no flavor.
pub fn ForNativeStackReadonly(comptime Native: type, comptime Template: type, comptime Admission: type, comptime lightweight: bool, comptime fused: bool, comptime Stack: type, comptime ReadonlyPolicy: type) type {
    const CallerReadonly = ReadonlyPolicy.CallerProof;
    const CallerReadonlyReceiver = ReadonlyPolicy.CallerReceiver;
    const Catalog = Stack.Catalog;
    const Fused = Stack.Fused;
    const FusedSource = Stack.Source;
    const FusedReceiver = Stack.Receiver;
    return struct {
        pub const InstancePin = if (Stack.capacity) struct {
            shape: *const Shape.Blake3ExecutionStatement,
            external_retirements: u32,
            admission: Admission,
            template: Native.Template,
            template_id: [32]u8,
            profile: Profile,
            limits: Fused.Limits = .{},
        } else struct {
            shape: *const Shape.Blake3ExecutionStatement,
            admission: Admission,
            template: Native.Template,
            template_id: [32]u8,
            profile: Profile,
        };
        /// Scoped per-execution caller companion. Global batching of provider
        /// arithmetic can replace this bridge without changing opcode request slots.
        pub const ExtensionPin = struct {
            execution_index: u32,
            statement: *const ExtensionProfile.admission.Statement,
            total_steps: u32,
            expected_key_id: [32]u8,
        };

        pub const CallerMemoryPin = struct {
            frame: @import("../air/block/memory_event.zig").Frame,
            witness_root: [32]u8,
            expected_rw_events: u64,
            readonly: ?ReadonlyPolicy.CallerAuthority = null,
            readonly_census: ?@import("block_v5_readonly_input_proposal_v1.zig").Census = null,
        };
        /// Loaders transfer one proof at a time, never a precomputed receipt.
        pub const Loader = struct {
            context: *anyopaque,
            take_native: *const fn (*anyopaque, u32) anyerror!Native.Proof,
            take_request: ?*const fn (*anyopaque, u32) anyerror!Request.Proof = null,
            take_fused: ?*const fn (*anyopaque, u32) anyerror!Fused.Proof = null,
            take_table: *const fn (*anyopaque) anyerror!Table.Proof,
            take_precompile: ?*const fn (*anyopaque, u32) anyerror!Precompile.Proof = null,
            take_caller_readonly: ?*const fn (*anyopaque, u32) anyerror!CallerReadonly.Proof = null,
            take_caller_fused: ?*const fn (*anyopaque, u32) anyerror!CallerFused.Proof = null,
            take_extension_request: ?*const fn (*anyopaque, u32) anyerror!ExtensionRequest.Proof = null,
        };
        /// Internal block joins reuse these exact fresh base receipts. Hooks
        /// receive no proof ownership and cannot replace base verification.
        pub const Hooks = struct {
            context: *anyopaque,
            on_native: ?*const fn (*anyopaque, std.mem.Allocator, u32, InstancePin, *const Native.OpenReceipt) anyerror!void = null,
            on_fused: ?*const fn (*anyopaque, std.mem.Allocator, u32, InstancePin, *const Native.OpenReceipt, *const Fused.Verified) anyerror!void = null,
            on_readonly_caller: ?*const fn (*anyopaque, std.mem.Allocator, u32, ExtensionPin, *const Precompile.OpenReceipt, *const CallerReadonly.Verified) anyerror!void = null,
            on_fused_caller: ?*const fn (*anyopaque, std.mem.Allocator, u32, ExtensionPin, *const Precompile.OpenReceipt, *const CallerFused.Verified) anyerror!void = null,
            on_precompile: ?*const fn (*anyopaque, std.mem.Allocator, u32, ExtensionPin, *const Precompile.OpenReceipt) anyerror!void = null,
        };

        pub const ScopedPrograms = struct {
            native_programs_fresh_verified: void = {},
            native_open_sum: Q,
            program_provider_sum: Q,
            public_program_boundary_sum: Q,
            precompile_open_sum: Q,
            fetch_count: u64,
            seal_digest: [32]u8,
        };

        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                fn verifyFused(a: std.mem.Allocator, loader: Loader, index: u32, pin: InstancePin, memory: FusedReceiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, catalog: Catalog.Admission) !FusedReceiver.Open {
                    const independent = fusedPin(pin);
                    const fused_slots = try FusedSource.slotsFromShapeForMode(a, pin.shape, externalRetirements(pin), sealed.register_custody_mode);
                    defer a.free(fused_slots);
                    const memory_slots = try memorySlots(a, pin, memory.frame, sealed.register_custody_mode);
                    defer a.free(memory_slots);
                    var projection: ?Fused.Proof = null;
                    var owns = true;
                    defer if (owns) if (projection) |*proof| proof.deinit(a);
                    if (fused_slots.len != 0 or memory_slots.len != 0)
                        projection = try (loader.take_fused orelse return error.MissingV5FusedProjectionLoader)(loader.context, index);
                    const native = try loader.take_native(loader.context, index);
                    owns = false;
                    return FusedReceiver.ForBackend(Backend).verifyOwned(a, native, projection, index, independent, memory, sealed, pins, roster, catalog);
                }
                pub fn verify(
                    a: std.mem.Allocator,
                    pins: Seal.Pins,
                    roster: []const Seal.Entry,
                    sealed: Seal.Sealed,
                    catalog: Catalog.Admission,
                    plan: Program.Plan,
                    instances: []const InstancePin,
                    loader: Loader,
                ) !ScopedPrograms {
                    return verifyWithExtensions(a, pins, roster, sealed, catalog, plan, instances, &.{}, loader);
                }
                pub fn verifyWithExtensions(
                    a: std.mem.Allocator,
                    pins: Seal.Pins,
                    roster: []const Seal.Entry,
                    sealed: Seal.Sealed,
                    catalog: Catalog.Admission,
                    plan: Program.Plan,
                    instances: []const InstancePin,
                    extensions: []const ExtensionPin,
                    loader: Loader,
                ) !ScopedPrograms {
                    return verifyWithHooks(a, pins, roster, sealed, catalog, plan, instances, extensions, loader, null);
                }
                pub fn verifyWithHooks(
                    a: std.mem.Allocator,
                    pins: Seal.Pins,
                    roster: []const Seal.Entry,
                    sealed: Seal.Sealed,
                    catalog: Catalog.Admission,
                    plan: Program.Plan,
                    instances: []const InstancePin,
                    extensions: []const ExtensionPin,
                    loader: Loader,
                    hooks: ?Hooks,
                ) !ScopedPrograms {
                    return verifyInternal(a, pins, roster, sealed, catalog, plan, instances, extensions, &.{}, &.{}, loader, hooks);
                }
                pub fn verifyWithFusedMemoryHooks(
                    a: std.mem.Allocator,
                    pins: Seal.Pins,
                    roster: []const Seal.Entry,
                    sealed: Seal.Sealed,
                    catalog: Catalog.Admission,
                    plan: Program.Plan,
                    instances: []const InstancePin,
                    extensions: []const ExtensionPin,
                    memory: []const FusedReceiver.MemoryPin,
                    loader: Loader,
                    hooks: ?Hooks,
                ) !ScopedPrograms {
                    return verifyInternal(a, pins, roster, sealed, catalog, plan, instances, extensions, memory, &.{}, loader, hooks);
                }
                /// All canonical native/caller side receipts arise in this
                /// one fresh proof loop; memory pins are independent of bytes.
                pub fn verifyWithCompositeHooks(a: std.mem.Allocator, pins: Seal.Pins, roster: []const Seal.Entry, sealed: Seal.Sealed, catalog: Catalog.Admission, plan: Program.Plan, instances: []const InstancePin, extensions: []const ExtensionPin, memory: []const FusedReceiver.MemoryPin, caller_memory: []const CallerMemoryPin, loader: Loader, hooks: ?Hooks) !ScopedPrograms {
                    return verifyInternal(a, pins, roster, sealed, catalog, plan, instances, extensions, memory, caller_memory, loader, hooks);
                }
                fn callerPin(extension: ExtensionPin, memory: CallerMemoryPin, execution: Seal.Entry, caller: Seal.Entry) CallerReceiver.Pin {
                    return .{ .statement = extension.statement, .total_steps = extension.total_steps, .execution_instance_id = execution.instance_id, .expected_key_id = extension.expected_key_id, .expected_caller_instance_id = caller.instance_id, .roots = caller.roots, .witness_root = memory.witness_root, .frame = memory.frame, .expected_rw_events = memory.expected_rw_events };
                }
                fn readonlyPin(pin: CallerReceiver.Pin, authority: ReadonlyPolicy.CallerAuthority) CallerReadonlyReceiver.Pin {
                    return .{ .statement = pin.statement, .total_steps = pin.total_steps, .expected_key_id = pin.expected_key_id, .execution_instance_id = pin.execution_instance_id, .expected_caller_instance_id = pin.expected_caller_instance_id, .roots = pin.roots, .witness_root = pin.witness_root, .frame = pin.frame, .expected_rw_events = pin.expected_rw_events, .readonly = authority };
                }
                fn verifyReadonlyCaller(a: std.mem.Allocator, loader: Loader, index: u32, independent: CallerReadonlyReceiver.Pin, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry) !CallerReadonlyReceiver.Open {
                    var projection = try (loader.take_caller_readonly orelse return error.MissingV5CallerReadonlyLoader)(loader.context, index);
                    var owns = true;
                    defer if (owns) projection.deinit(a);
                    const base = try (loader.take_precompile orelse return error.MissingV5CallerLoader)(loader.context, index);
                    owns = false;
                    return CallerReadonlyReceiver.ForBackend(Backend).verifyOwned(a, base, projection, index, independent, sealed, pins, roster);
                }
                fn verifyCaller(a: std.mem.Allocator, loader: Loader, index: u32, independent: CallerReceiver.Pin, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry) !CallerReceiver.Open {
                    var projection = try (loader.take_caller_fused orelse return error.MissingV5CallerFusionLoader)(loader.context, index);
                    var owns = true;
                    defer if (owns) projection.deinit(a);
                    const base = try (loader.take_precompile orelse return error.MissingV5CallerLoader)(loader.context, index);
                    owns = false;
                    return CallerReceiver.ForBackend(Backend).verifyOwned(a, base, projection, index, independent, sealed, pins, roster);
                }
                /// Admit independent policy before any proof-file callback. This
                /// preflight never establishes cryptographic acceptance; the fresh
                /// verification loop still consumes and verifies each real proof.
                pub fn admitRoster(
                    a: std.mem.Allocator,
                    pins: Seal.Pins,
                    roster: []const Seal.Entry,
                    sealed: Seal.Sealed,
                    catalog: Catalog.Admission,
                    plan: Program.Plan,
                    instances: []const InstancePin,
                    extensions: []const ExtensionPin,
                    memory: []const FusedReceiver.MemoryPin,
                    caller_memory: []const CallerMemoryPin,
                    loader: Loader,
                ) !void {
                    try sealed.require(pins, roster);
                    if (lightweight and fused) {
                        const recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
                        try recipe.requireMode(sealed.register_custody_mode);
                        for (instances) |pin| try recipe.requireNative(pin.shape);
                        for (extensions) |pin| try recipe.requireCaller(pin.statement, pin.total_steps);
                    }
                    if (fused and memory.len != instances.len) return error.MissingV5FusedMemoryPins;
                    if (fused and caller_memory.len != extensions.len) return error.MissingV5CallerCompositeMemoryPins;
                    if (!fused and caller_memory.len != 0) return error.UntrustedV5CallerCompositeMemoryPins;
                    if (!fused and memory.len != 0) return error.UntrustedV5SeparateMemoryPins;
                    if (instances.len == 0 or instances.len != sealed.execution_instance_count or
                        !std.meta.eql(plan.program_root.bytes, pins.program_root) or
                        !std.meta.eql(try plan.digest(), pins.program_plan_digest) or
                        !std.meta.eql(try catalog.digest(), pins.native_template_catalog_digest))
                        return error.UntrustedV5NativeProgramBatch;
                    if (pins.counts[@intFromEnum(Seal.Family.precompile) - 1] != extensions.len or
                        pins.counts[@intFromEnum(Seal.Family.program_extension_request) - 1] != extensions.len or
                        (extensions.len != 0 and (loader.take_precompile == null or
                            (if (ReadonlyPolicy.global) loader.take_caller_readonly == null else if (fused) loader.take_caller_fused == null else loader.take_extension_request == null))))
                        return error.V5ProgramExtensionAdmissionRequired;
                    for (extensions, 0..) |extension, index| {
                        if (extension.execution_index >= instances.len or
                            (index != 0 and extension.execution_index <= extensions[index - 1].execution_index))
                            return error.InvalidV5ProgramExtensionRoster;
                    }
                    if (fused) for (extensions, caller_memory) |extension, memory_pin| {
                        const index = extension.execution_index;
                        if (!std.meta.eql(memory_pin.frame, memory[index].frame)) return error.UntrustedV5CallerCompositeFrame;
                        const independent = callerPin(extension, memory_pin, try find(roster, .execution, index), try find(roster, .precompile, index));
                        if (memory_pin.readonly) |authority| {
                            const census = memory_pin.readonly_census orelse return error.MissingV5CallerReadonlyCensus;
                            try census.require(memory_pin.expected_rw_events);
                            if (loader.take_caller_readonly == null) return error.MissingV5CallerReadonlyLoader;
                            try CallerReadonlyReceiver.admit(a, index, readonlyPin(independent, authority), sealed, pins, roster);
                        } else {
                            if (memory_pin.readonly_census != null) return error.UntrustedV5CallerReadonlyCensus;
                            try CallerReceiver.admit(a, index, independent, sealed, pins, roster);
                        }
                    };
                    const table_entry = try find(roster, .program, 0);
                    if (!std.meta.eql(table_entry.instance_id, try Table.instanceId(plan)))
                        return error.UntrustedV5ProgramTableId;
                    for (instances, 0..) |pin, index| {
                        const ordinal: u32 = @intCast(index);
                        try catalog.admit(pins, sealed, ordinal, pin.template, pin.template_id);
                        if (lightweight) try pin.admission.require(pins, &pin.shape.public_data) else try pin.admission.validatePublic(&pin.shape.public_data);
                        const extension = extensionAt(extensions, ordinal);
                        const external_count = if (extension) |value| ExtensionProfile.externalCount(value.statement) else 0;
                        if (externalRetirements(pin) != external_count or
                            (extension != null and extension.?.total_steps != pin.shape.public_data.clock) or
                            !programRootMatches(pin.admission, plan.program_root))
                            return error.V5ProgramExtensionAdmissionRequired;
                        const native_entry = try find(roster, .execution, ordinal);
                        const request_entry = try find(roster, .program_request, ordinal);
                        const expected_instance = try expectedInstance(pin, native_entry.roots, ordinal);
                        const slots = try Request.slotsFromStatement(a, pin.shape);
                        defer a.free(slots);
                        if (fused) {
                            const fused_slots = try FusedSource.slotsFromShapeForMode(a, pin.shape, externalRetirements(pin), sealed.register_custody_mode);
                            defer a.free(fused_slots);
                            _ = try FusedReceiver.admit(a, ordinal, fusedPin(pin), memory[index], sealed, pins, roster, catalog);
                            const memory_slots = try memorySlots(a, pin, memory[index].frame, sealed.register_custody_mode);
                            defer a.free(memory_slots);
                            if ((fused_slots.len != 0 or memory_slots.len != 0) and loader.take_fused == null) return error.MissingV5FusedProjectionLoader;
                        } else if (!std.meta.eql(native_entry.instance_id, expected_instance) or
                            !std.meta.eql(request_entry.roots, native_entry.roots) or
                            !std.meta.eql(request_entry.instance_id, Request.nativeV5InstanceId(pin.template_id, expected_instance, ordinal, slots)))
                            return error.UntrustedV5NativeProgramRequest;
                    }
                }
                fn verifyInternal(
                    a: std.mem.Allocator,
                    pins: Seal.Pins,
                    roster: []const Seal.Entry,
                    sealed: Seal.Sealed,
                    catalog: Catalog.Admission,
                    plan: Program.Plan,
                    instances: []const InstancePin,
                    extensions: []const ExtensionPin,
                    memory: []const FusedReceiver.MemoryPin,
                    caller_memory: []const CallerMemoryPin,
                    loader: Loader,
                    hooks: ?Hooks,
                ) !ScopedPrograms {
                    try admitRoster(a, pins, roster, sealed, catalog, plan, instances, extensions, memory, caller_memory, loader);
                    const table_entry = try find(roster, .program, 0);
                    const program_seal = sealed.programSeal();
                    const table_receipt = try Table.ForBackend(Backend).verifyOwned(a, try loader.take_table(loader.context), plan, program_seal, plan.program_root, table_entry.roots, pins.config);
                    const requests = try a.alloc(Table.VerifiedNativeRequest, try std.math.mul(usize, instances.len, 3));
                    defer a.free(requests);
                    var channel = sealed.sharedChannel();
                    const relations = try universal.UniversalRelations.draw(a, &channel);
                    var native_open_sum = Q.zero();
                    var precompile_open_sum = Q.zero();
                    var public_program_boundary_sum = Q.zero();
                    var fetch_count: u64 = 0;
                    for (instances, 0..) |pin, index| {
                        const ordinal: u32 = @intCast(index);
                        var fused_open: ?FusedReceiver.Open = if (fused) try verifyFused(a, loader, ordinal, pin, memory[index], sealed, pins, roster, catalog) else null;
                        defer if (fused) if (fused_open) |*open| open.deinit(a);
                        const native_receipt = if (fused) fused_open.?.native else try verifyNative(Backend, a, try loader.take_native(loader.context, ordinal), pin, ordinal, sealed, pins, roster, catalog);
                        native_open_sum = native_open_sum.add(native_receipt.open_sum);
                        const fixed_logs = try Template.columnLogs(a, pin.shape, externalRetirements(pin), .fixed);
                        defer a.free(fixed_logs);
                        const main_logs = try Template.columnLogs(a, pin.shape, externalRetirements(pin), .main);
                        defer a.free(main_logs);
                        const slots = try Request.slotsFromStatement(a, pin.shape);
                        defer a.free(slots);
                        var program_channel_for_fused = program_seal.sharedChannel();
                        const request_receipt: Request.VerifiedReceipt = if (fused)
                            .{ .sum = if (fused_open.?.fused.projections) |projection| projection.program_sum else Q.zero(), .fetch_count = if (fused_open.?.fused.projections) |projection| projection.fetch_count else 0, .native_roots = native_receipt.first_roots, .native_key_id = pin.template_id, .sealed_channel_digest = program_channel_for_fused.digestBytes() }
                        else if (lightweight and slots.len == 0)
                            try @import("block_v5_empty_program_request_v1.zig").fromFresh(pin.shape, externalRetirements(pin), &native_receipt, ordinal, sealed, pins, roster)
                        else
                            try Request.ForBackend(Backend).verifyOwned(a, try (loader.take_request orelse return error.MissingV5ProgramRequestLoader)(loader.context, ordinal), program_seal, ordinal, pin.template_id, slots, fixed_logs, main_logs, native_receipt.first_roots, (try find(roster, .program_request, ordinal)).roots, pins.config);
                        requests[3 * index] = request_receipt.closureReceipt();
                        const boundary = try Boundary.deriveFromPinnedNativePublic(pin.profile, &pin.shape.public_data, &relations);
                        public_program_boundary_sum = public_program_boundary_sum.add(boundary.sum);
                        if (hooks) |hook| {
                            if (hook.on_native) |callback| try callback(hook.context, a, ordinal, pin, &native_receipt);
                            if (fused) if (hook.on_fused) |callback| try callback(hook.context, a, ordinal, pin, &native_receipt, &fused_open.?.fused);
                        }
                        var program_channel = program_seal.sharedChannel();
                        const channel_digest = program_channel.digestBytes();
                        requests[3 * index + 1] = .{ .claim = boundary.sum, .fetch_count = boundary.fetch_count, .sealed_channel_digest = channel_digest };
                        requests[3 * index + 2] = .{ .claim = Q.zero(), .fetch_count = 0, .sealed_channel_digest = channel_digest };
                        if (extensionAt(extensions, ordinal)) |extension| {
                            if (fused) {
                                var ordinal_extension: usize = 0;
                                while (extensions[ordinal_extension].execution_index != ordinal) : (ordinal_extension += 1) {}
                                const independent = callerPin(extension, caller_memory[ordinal_extension], try find(roster, .execution, ordinal), try find(roster, .precompile, ordinal));
                                if (!std.meta.eql(independent.execution_instance_id, native_receipt.instance_id)) return error.UntrustedV5CallerCompositeExecution;
                                if (caller_memory[ordinal_extension].readonly) |authority| {
                                    var open = try verifyReadonlyCaller(a, loader, ordinal, readonlyPin(independent, authority), sealed, pins, roster);
                                    defer open.deinit(a);
                                    const census = caller_memory[ordinal_extension].readonly_census orelse return error.MissingV5CallerReadonlyCensus;
                                    try census.require(open.fused.partition.all_rw_events);
                                    if (census.mutable != open.fused.partition.mutable_events or census.readonly != open.fused.partition.readonly_events) return error.StaleReadonlyInputCensus;
                                    if (hooks) |callbacks| {
                                        const callback = callbacks.on_readonly_caller orelse return error.MissingV5CallerReadonlyClosure;
                                        try callback(callbacks.context, a, ordinal, extension, &open.caller, &open.fused);
                                    } else return error.MissingV5CallerReadonlyClosure;
                                    requests[3 * index + 2] = open.fused.program.closureReceipt();
                                    fetch_count = try std.math.add(u64, fetch_count, open.fused.program.fetch_count);
                                    precompile_open_sum = precompile_open_sum.add(open.caller.open_sum);
                                } else {
                                    var open = try verifyCaller(a, loader, ordinal, independent, sealed, pins, roster);
                                    defer open.deinit(a);
                                    precompile_open_sum = precompile_open_sum.add(open.caller.open_sum);
                                    requests[3 * index + 2] = open.fused.program.closureReceipt();
                                    if (hooks) |hook| if (hook.on_fused_caller) |callback| try callback(hook.context, a, ordinal, extension, &open.caller, &open.fused);
                                    fetch_count = try std.math.add(u64, fetch_count, open.fused.program.fetch_count);
                                }
                            } else {
                                const arithmetic = try Precompile.ForBackend(Backend).verifyOwned(a, try loader.take_precompile.?(loader.context, ordinal), extension.statement, extension.total_steps, extension.expected_key_id, native_receipt.instance_id, ordinal, sealed, pins, roster);
                                precompile_open_sum = precompile_open_sum.add(arithmetic.open_sum);
                                const caller_fixed = try Caller.columnLogs(a, extension.statement, .fixed);
                                defer a.free(caller_fixed);
                                const caller_main = try Caller.columnLogs(a, extension.statement, .main);
                                defer a.free(caller_main);
                                const caller_request = try ExtensionReceiver.ForBackend(Backend).verifyOwned(a, try loader.take_extension_request.?(loader.context, ordinal), sealed, pins, roster, arithmetic.binding, extension.statement, extension.total_steps, caller_fixed, caller_main);
                                requests[3 * index + 2] = caller_request.closureReceipt();
                                if (hooks) |hook| if (hook.on_precompile) |callback|
                                    try callback(hook.context, a, ordinal, extension, &arithmetic);
                                fetch_count = try std.math.add(u64, fetch_count, caller_request.fetch_count);
                            }
                        }
                        fetch_count = try std.math.add(u64, fetch_count, try std.math.add(u64, request_receipt.fetch_count, boundary.fetch_count));
                    }
                    try Table.closed(table_receipt, requests, program_seal);
                    return .{ .native_open_sum = native_open_sum, .program_provider_sum = table_receipt.claim, .public_program_boundary_sum = public_program_boundary_sum, .precompile_open_sum = precompile_open_sum, .fetch_count = fetch_count, .seal_digest = sealed.digest };
                }
            };
        }

        pub fn externalRetirements(pin: InstancePin) u32 {
            return if (Stack.capacity) pin.external_retirements else pin.template.external_retirements;
        }
        pub fn expectedInstance(pin: InstancePin, roots: Seal.Roots, index: u32) ![32]u8 {
            if (Stack.capacity) return Template.instanceId(pin.template_id, pin.shape, pin.external_retirements, pin.admission, roots, index);
            return Template.instanceId(pin.template_id, pin.shape, pin.admission, roots, index);
        }
        pub fn fusedPin(pin: InstancePin) FusedReceiver.InstancePin {
            if (Stack.capacity) return .{ .shape = pin.shape, .external_retirements = pin.external_retirements, .admission = pin.admission, .template = pin.template, .template_id = pin.template_id, .profile = pin.profile, .limits = pin.limits };
            return .{ .shape = pin.shape, .admission = pin.admission, .template = pin.template, .template_id = pin.template_id, .profile = pin.profile };
        }
        fn memorySlots(a: std.mem.Allocator, pin: InstancePin, frame: @import("../air/block/memory_event.zig").Frame, mode: u32) ![]@import("block_v5_opcode_memory_sidecar_proof_v1.zig").Slot {
            if (Stack.capacity) return FusedSource.memorySlots(a, pin.shape, pin.external_retirements, frame, mode);
            return FusedMemory.slotsFromStatementForMode(a, pin.shape, frame, mode);
        }
        fn verifyNative(comptime Backend: type, a: std.mem.Allocator, received: Native.Proof, pin: InstancePin, index: u32, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, catalog: Catalog.Admission) !Native.OpenReceipt {
            if (Stack.capacity) return Native.ForBackend(Backend).verifyOwnedWithCatalog(a, received, pin.shape, pin.external_retirements, pin.admission, pin.template, pin.template_id, index, sealed, pins, roster, pin.limits.native, catalog);
            return Native.ForBackend(Backend).verifyOwnedWithCatalog(a, received, pin.shape, pin.admission, pin.template, pin.template_id, pin.profile, index, sealed, pins, roster, catalog);
        }

        fn extensionAt(extensions: []const ExtensionPin, index: u32) ?ExtensionPin {
            for (extensions) |pin| if (pin.execution_index == index) return pin;
            return null;
        }

        fn find(entries: []const Seal.Entry, family: Seal.Family, index: u32) !Seal.Entry {
            for (entries) |entry| if (entry.family == family and entry.index == index) return entry;
            return error.MissingV5NativeProgramEntry;
        }

        fn programRootMatches(admission: Admission, root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest) bool {
            return if (lightweight) std.meta.eql(admission.context.program_root, root.bytes) else std.meta.eql(admission.plan.roots[0], root);
        }
    };
}
