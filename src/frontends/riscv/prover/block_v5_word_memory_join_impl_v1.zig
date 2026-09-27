//! Private complete-receiver plumbing. Hooks are invoked only by the native
//! and family11 fresh-verification loop, never by a public receipt API. This
//! module closes the packed bus but exposes no complete-block constructor.
pub const DefaultReadonly = struct {
    pub const global = false;
    pub const Pins = @import("block_v5_readonly_input_memory_policy_v1.zig").Pins;
    pub const NativeProof = @import("block_v5_readonly_input_proof_v1.zig").Proof;
    pub const CallerProof = @import("block_v5_caller_readonly_proof_v1.zig");
};
pub fn ForStack(comptime Stack: type) type {
    return ForStackReadonly(Stack, DefaultReadonly);
}
/// One original byte/register/packed transition receiver; the explicit policy
/// chooses only original scoped or independently admitted GLOBAL classification.
pub fn ForStackReadonly(comptime Stack: type, comptime ReadonlyPolicy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const programs = Stack.Programs;
        const native = Stack.Native;
        const native_protocol = Stack.Template;
        const catalog_mod = Stack.Catalog;
        const precompile = @import("block_v5_precompile_family_proof_v1.zig");
        const caller_protocol = @import("block_v5_precompile_protocol_v1.zig");
        const profile = @import("blake3_ethereum_sha_profile.zig");
        const opcode = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
        const external = @import("block_v5_external_memory_sidecar_proof_v1.zig");
        const external_source = @import("block_execution_external_trace_v2.zig");
        const memory = @import("block_v5_word_memory_receiver_v1.zig");
        const sorted = @import("block_v5_sorted_memory_v1.zig");
        const endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
        const bytes = @import("block_v5_memory_byte_demand_v1.zig");
        const empty = @import("block_v5_empty_opcode_memory_v1.zig");
        const seal = @import("block_v5_source_seal_v1.zig");
        const Registers = @import("block_v5_register_windows_v1.zig");
        pub const ExtensionPin = struct { public: programs.ExtensionPin, witness_root: [32]u8 };
        pub const Pins = struct {
            memory: sorted.Pins,
            catalog: catalog_mod.Admission,
            executions: []const programs.InstancePin,
            opcode_witness_roots: []const [32]u8,
            ordinary_events: []const u64,
            extensions: []const ExtensionPin,
            register_windows: ?Registers.Plan = null,
            readonly: ?ReadonlyPolicy.Pins = null,
        };
        const FusedSource = Stack.FusedSource;
        const FusedReceiver = Stack.FusedReceiver;
        pub const Loader = if (Stack.is_capacity) struct {
            context: *anyopaque,
            // Capacity ordinary access is part of B5CF. There is deliberately
            // no legacy opcode proof loader on this typed path.
            take_native_readonly: ?*const fn (*anyopaque, std.mem.Allocator, u32) anyerror!ReadonlyPolicy.NativeProof = null,
            take_external: ?*const fn (*anyopaque, u32) anyerror!external.Proof = null,
        } else struct {
            context: *anyopaque,
            take_opcode: *const fn (*anyopaque, u32) anyerror!opcode.Proof,
            take_native_readonly: ?*const fn (*anyopaque, std.mem.Allocator, u32) anyerror!ReadonlyPolicy.NativeProof = null,
            take_external: ?*const fn (*anyopaque, u32) anyerror!external.Proof = null,
        };
        pub const ExecutionBytes = struct { index: u32, event_count: u64, request_count: u64, max_requests: u64, sum: Q };
        pub const OpenPartition = struct {
            packed_transitions_initial_final_rw_registers_range16_closed: void = {},
            memory: memory.Scoped,
            bytes: []ExecutionBytes,
            ordinary_memory_opposite: Q,
            external_memory_opposite: Q,
            allocator: std.mem.Allocator,
            /// Grouped signed native provider proofs must still cancel these positive
            /// byte parts, and native clock/program/VM partitions must close separately.
            pub fn deinit(self: *OpenPartition, _: std.mem.Allocator) void {
                self.allocator.free(self.bytes);
                self.* = undefined;
            }
        };
        /// Independent metadata admission only. Original init and the
        /// genuine PAGE wrapper share this exact body; this grants no receipt.
        pub fn admitPins(a: std.mem.Allocator, pins: Pins, sealed: seal.Sealed) !void {
            try sealed.require(pins.memory.sealPins(), pins.memory.firstRound());
            const recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
            try recipe.requireMode(sealed.register_custody_mode);
            for (pins.executions) |pin| try recipe.requireNative(pin.shape);
            for (pins.extensions) |pin| try recipe.requireCaller(pin.public.statement, pin.public.total_steps);
            if (pins.executions.len == 0 or pins.executions.len != sealed.execution_instance_count or
                pins.executions.len != pins.opcode_witness_roots.len or pins.executions.len != pins.ordinary_events.len or
                (sealed.register_custody_mode == 0 and pins.memory.registerEndpoints() == null) or pins.extensions.len != pins.memory.sealPins().counts[@intFromEnum(seal.Family.precompile) - 1] or
                pins.extensions.len != pins.memory.sealPins().counts[@intFromEnum(seal.Family.execution_external_sidecar) - 1]) return error.UntrustedV5MemoryJoinPins;
            // Native-v3 has no per-leaf register memory compensation. Only
            // the block's endpoints acquire value authority through sorted
            // register closure; intermediate spans assert PC/clock only.
            if (!std.meta.eql(pins.executions[0].shape.public_data.initial_regs, pins.memory.source().initial.initial_registers)) return error.UntrustedV5MemoryRegisterBoundary;
            if (sealed.register_custody_mode == 1) {
                const plan = pins.register_windows orelse return error.MissingV5RegisterWindowPlan;
                try recipe.requireWindowVersion(plan.version);
                if (!std.meta.eql(try plan.digest(), sealed.register_endpoint_plan_digest) or plan.windows.len != pins.executions.len or
                    !std.meta.eql(plan.initial_registers, pins.memory.source().initial.initial_registers)) return error.UntrustedV5RegisterWindowPlan;
                for (plan.windows, pins.executions, 0..) |window, execution, index| {
                    try plan.requireNative(execution.shape);
                    try window.requirePublic(@intCast(index), execution.admission.context.first_cycle, &execution.shape.public_data);
                }
                for (pins.extensions) |extension| try plan.requireCaller(extension.public.statement);
            } else {
                if (pins.register_windows != null or !std.meta.eql(pins.executions[pins.executions.len - 1].shape.public_data.final_regs, pins.memory.registerEndpoints().?.final_registers)) return error.UntrustedV5MemoryRegisterBoundary;
            }
            if (pins.readonly == null and !std.mem.allEqual(u8, &sealed.readonly_roster_digest, 0)) return error.MissingReadonlyMemoryPolicy;
            if (pins.readonly) |selected| {
                const events = try a.alloc(u64, pins.extensions.len);
                defer a.free(events);
                for (pins.extensions, events) |extension, *count| count.* = try external_source.expectedEventCountForMode(extension.public.statement, sealed.register_custody_mode);
                try selected.require(a, sealed, pins.memory.sealPins(), pins.memory.firstRound(), pins.ordinary_events, events, pins.memory.totalEvents());
            }
            for (pins.executions, 0..) |pin, index| {
                try pins.catalog.admit(pins.memory.sealPins(), sealed, @intCast(index), pin.template, pin.template_id);
                try pin.admission.require(pins.memory.sealPins(), &pin.shape.public_data);
                const frame = publicFrame(pin);
                const demand = try bytes.opcodeDemandFromShapeForMode(a, pin.shape, frame, pins.ordinary_events[index], sealed.register_custody_mode);
                if (demand.event_count == 0) {
                    const native_entry = try executionEntry(pins.memory.firstRound(), @intCast(index));
                    const canonical = if (Stack.is_capacity) try FusedSource.emptyEntry(a, pin.shape, programs.externalRetirements(pin), frame, native_entry, 0, sealed.register_custody_mode) else try empty.firstRoundEntryForMode(a, pin.shape, frame, native_entry, 0, sealed.register_custody_mode);
                    var found = false;
                    for (pins.memory.firstRound()) |entry| if (entry.family == .execution_sidecar and entry.index == index) {
                        if (!std.meta.eql(entry, canonical) or !std.meta.eql(pins.opcode_witness_roots[index], canonical.roots[0])) return error.UntrustedV5EmptyOpcodeEntry;
                        found = true;
                    };
                    if (!found) return error.UntrustedV5EmptyOpcodeEntry;
                }
                const companion = extensionAt(pins.extensions, @intCast(index));
                if (programs.externalRetirements(pin) != (if (companion) |value| profile.externalCount(value.public.statement) else 0)) return error.UntrustedV5MemoryCallerCensus;
            }
            for (pins.extensions, 0..) |extension, index| {
                if (extension.public.execution_index >= pins.executions.len or (index != 0 and extension.public.execution_index <= pins.extensions[index - 1].public.execution_index) or
                    extension.public.total_steps != pins.executions[extension.public.execution_index].shape.public_data.clock or
                    (try external_source.expectedEventCountForMode(extension.public.statement, sealed.register_custody_mode)) == 0) return error.UntrustedV5MemoryCallerCensus;
            }
        }
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const Self = @This();
                a: std.mem.Allocator,
                pins: Pins,
                sealed: seal.Sealed,
                loader: Loader,
                fresh_memory: memory.Scoped,
                byte_parts: []ExecutionBytes,
                next_native: u32 = 0,
                next_extension: u32 = 0,
                transition_sum: Q = Q.zero(),
                readonly_count: u64 = 0,
                ordinary_opposite: Q = Q.zero(),
                external_opposite: Q = Q.zero(),
                owned: bool = true,
                readonly_session: if (ReadonlyPolicy.global) *@import("block_v5_readonly_input_global_join_v2.zig").Owned else void,
                pub fn deinit(self: *Self) void {
                    if (self.owned) self.a.free(self.byte_parts);
                    self.* = undefined;
                }
                pub fn init(a: std.mem.Allocator, pins: Pins, input: []const u8, files: endpoints.Sources, memory_loader: sorted.Loader, loader: Loader, sealed: seal.Sealed) !Self {
                    if (ReadonlyPolicy.global) return error.MissingGlobalReadonlyJoinSession else return initKernel(a, pins, input, files, memory_loader, loader, sealed, {});
                }
                pub fn initWithGlobalReadonly(a: std.mem.Allocator, pins: Pins, input: []const u8, files: endpoints.Sources, memory_loader: sorted.Loader, loader: Loader, sealed: seal.Sealed, joined: *@import("block_v5_readonly_input_global_join_v2.zig").Owned) !Self {
                    if (!ReadonlyPolicy.global) @compileError("GLOBAL session requires the explicit v2 policy");
                    const selected = pins.readonly orelse return error.MissingReadonlyMemoryPolicy;
                    try @import("block_v5_readonly_input_global_source_receiver_v2.zig").requireSession(.{ .authority = selected.roster, .ordinal = 0 }, joined, sealed);
                    return initKernel(a, pins, input, files, memory_loader, loader, sealed, joined);
                }
                fn initKernel(a: std.mem.Allocator, pins: Pins, input: []const u8, files: endpoints.Sources, memory_loader: sorted.Loader, loader: Loader, sealed: seal.Sealed, joined: if (ReadonlyPolicy.global) *@import("block_v5_readonly_input_global_join_v2.zig").Owned else void) !Self {
                    if (pins.readonly) |selected| if (!std.mem.eql(u8, selected.authority.input, input)) return error.UntrustedReadonlyInputBytes;
                    try admitPins(a, pins, sealed);
                    const closed = try sorted.verify(Backend, a, pins.memory, input, files, memory_loader, sealed);
                    if (sealed.register_custody_mode == 0 and !closed.register_endpoints_verified) return error.UnclosedV5GlobalRegisterEndpoints;
                    const parts = try a.alloc(ExecutionBytes, pins.executions.len);
                    for (parts, 0..) |*part, index| part.* = .{ .index = @intCast(index), .event_count = 0, .request_count = 0, .max_requests = 0, .sum = Q.zero() };
                    return .{ .a = a, .pins = pins, .sealed = sealed, .loader = loader, .fresh_memory = closed, .byte_parts = parts, .readonly_session = joined };
                }
                /// Called immediately after native-v3 verification inside the private
                /// core loop. A callback result never changes that native receipt.
                pub fn onNative(self: *Self, _: std.mem.Allocator, index: u32, callback_pin: programs.InstancePin, fresh: *const native.OpenReceipt) !void {
                    if (Stack.is_capacity) {
                        return error.UnsupportedCapacitySeparateProjection;
                    } else {
                        if (!self.owned or index != self.next_native or index >= self.pins.executions.len) return error.InvalidV5MemoryNativeHookOrder;
                        const pin = self.pins.executions[index];
                        try requireCallback(pin, callback_pin, fresh);
                        if (!std.meta.eql(callback_pin.admission.expected_id, pin.admission.expected_id) or !std.meta.eql(callback_pin.template_id, pin.template_id) or
                            !std.meta.eql(fresh.sealed_digest, self.sealed.digest) or !std.meta.eql(fresh.template_id, pin.template_id) or
                            !std.meta.eql(try programs.expectedInstance(pin, fresh.first_roots, index), fresh.instance_id)) return error.UntrustedV5MemoryNativeHook;
                        const slots = try memorySlots(self.a, pin, publicFrame(pin), self.sealed.register_custody_mode);
                        defer self.a.free(slots);
                        if (slots.len == 0) {
                            return self.onFusedNative(index, callback_pin, fresh, null);
                        }
                        const fixed = try native_protocol.columnLogs(self.a, pin.shape, programs.externalRetirements(pin), .fixed);
                        defer self.a.free(fixed);
                        const main = try native_protocol.columnLogs(self.a, pin.shape, programs.externalRetirements(pin), .main);
                        defer self.a.free(main);
                        const received = try self.loader.take_opcode(self.loader.context, index);
                        var verified = try opcode.ForPackedBackend(Backend).verifyOwned(self.a, received, self.sealed, self.pins.memory.sealPins(), self.pins.memory.firstRound(), self.pins.catalog, fresh, index, slots, fixed, main, self.pins.opcode_witness_roots[index], self.pins.memory.sealPins().config);
                        defer verified.deinit(self.a);
                        try self.onFusedNative(index, callback_pin, fresh, &verified);
                    }
                }
                /// Private fused-verifier hook. The proof loop freshly verifies native
                /// and the joint projection/access STARK before calling this method.
                /// This consumes no separate opcode loader and takes no ownership of
                /// the scoped receipt's range arrays. Null is admitted only by exact
                /// independently reconstructed typed absence, never a scalar zero.
                pub fn onFusedNative(self: *Self, index: u32, callback_pin: programs.InstancePin, fresh: *const native.OpenReceipt, verified: ?*const opcode.Verified) !void {
                    if (!self.owned or index != self.next_native or index >= self.pins.executions.len) return error.InvalidV5MemoryNativeHookOrder;
                    const pin = self.pins.executions[index];
                    try requireCallback(pin, callback_pin, fresh);
                    if (!std.meta.eql(callback_pin.admission.expected_id, pin.admission.expected_id) or !std.meta.eql(callback_pin.template_id, pin.template_id) or
                        !std.meta.eql(fresh.sealed_digest, self.sealed.digest) or !std.meta.eql(fresh.template_id, pin.template_id) or
                        !std.meta.eql(try programs.expectedInstance(pin, fresh.first_roots, index), fresh.instance_id)) return error.UntrustedV5MemoryNativeHook;
                    const execution = try executionEntry(self.pins.memory.firstRound(), index);
                    if (!std.meta.eql(execution.roots, fresh.first_roots) or !std.meta.eql(execution.instance_id, fresh.instance_id)) return error.UntrustedV5MemoryNativeHook;
                    const slots = try memorySlots(self.a, pin, publicFrame(pin), self.sealed.register_custody_mode);
                    defer self.a.free(slots);
                    if (slots.len == 0) {
                        if (verified != null) return error.UntrustedV5EmptyOpcodeEntry;
                        if (Stack.is_capacity) {
                            _ = try FusedReceiver.admit(self.a, index, programs.fusedPin(pin), .{ .frame = publicFrame(pin), .expected_events = self.pins.ordinary_events[index], .witness_root = self.pins.opcode_witness_roots[index] }, self.sealed, self.pins.memory.sealPins(), self.pins.memory.firstRound(), self.pins.catalog);
                        } else try empty.admit(self.a, pin.shape, publicFrame(pin), fresh, index, self.pins.ordinary_events[index], self.sealed, self.pins.memory.sealPins(), self.pins.memory.firstRound());
                        if (self.pins.readonly) |selected| {
                            const expected = selected.native[index];
                            if (expected.pin != null or expected.census.all_rw != 0 or expected.census.mutable != 0 or expected.census.readonly != 0) return error.UntrustedReadonlyInputAbsence;
                            if (ReadonlyPolicy.global) _ = try @import("block_v5_readonly_input_global_source_receiver_v2.zig").ForStack(Stack).ForBackend(Backend).consumeAfterFreshNative(self.a, null, index, fresh, null, self.pins.opcode_witness_roots[index], self.sealed, self.pins.memory.sealPins(), self.pins.memory.firstRound(), .{ .authority = selected.roster, .ordinal = expected.ordinal, .limits = selected.classifier_limits }, self.readonly_session);
                        }
                        self.next_native += 1;
                        return;
                    }
                    const receipt = verified orelse return error.MissingV5FusedMemoryReceipt;
                    if (receipt.instance_index != index or !std.meta.eql(receipt.native_roots, fresh.first_roots) or
                        !std.meta.eql(receipt.native_instance_id, fresh.instance_id) or
                        !std.meta.eql(receipt.witness_root, self.pins.opcode_witness_roots[index]) or receipt.range_claims.len != slots.len)
                        return error.UntrustedV5FusedMemoryReceipt;
                    const expected = opcode.packedEntry(fresh.instance_id, fresh.first_roots, receipt.witness_root, index, slots);
                    var found = false;
                    for (self.pins.memory.firstRound()) |present| if (present.family == .execution_sidecar and present.index == index) {
                        if (!std.meta.eql(expected, present)) return error.UntrustedV5FusedMemoryReceipt;
                        found = true;
                    };
                    if (!found) return error.UntrustedV5FusedMemoryReceipt;
                    const demand = try bytes.opcodeDemand(slots, self.pins.ordinary_events[index]);
                    const sum = try bytes.freshRequests(receipt.*, demand, self.sealed.digest);
                    try self.add(index, demand, sum);
                    if (self.pins.readonly) |selected| {
                        if (ReadonlyPolicy.global) {
                            const expected = selected.native[index];
                            const received = if (expected.census.all_rw == 0) null else try (self.loader.take_native_readonly orelse return error.MissingReadonlyInputProof)(self.loader.context, self.a, index);
                            const partition = try @import("block_v5_readonly_input_global_source_receiver_v2.zig").ForStack(Stack).ForBackend(Backend).consumeAfterFreshNative(self.a, received, index, fresh, receipt, self.pins.opcode_witness_roots[index], self.sealed, self.pins.memory.sealPins(), self.pins.memory.firstRound(), .{ .authority = selected.roster, .ordinal = expected.ordinal, .limits = selected.classifier_limits }, self.readonly_session);
                            self.transition_sum = self.transition_sum.add(partition.mutable_sum);
                            self.readonly_count = try std.math.add(u64, self.readonly_count, partition.readonly_count);
                        } else {
                            const class_expected = selected.native[index];
                            const class_pin = class_expected.pin orelse return error.MissingReadonlyInputPin;
                            const Classification = @import("block_v5_readonly_input_proof_v1.zig");
                            if (!std.meta.eql(class_pin.source_identity, Classification.sourceIdentity(.native, index, self.sealed.digest, fresh.instance_id, fresh.first_roots, receipt.witness_root))) return error.UntrustedReadonlyInputSourceIdentity;
                            var plan = try selected.authority.admit(self.a);
                            defer plan.deinit();
                            const proof = try (self.loader.take_native_readonly orelse return error.MissingReadonlyInputProof)(self.loader.context, self.a, index);
                            const partition = try Classification.ForBackend(Backend).verifyOwned(self.a, proof, class_pin, plan, self.sealed, self.pins.memory.sealPins(), self.pins.memory.firstRound());
                            try @import("block_v5_readonly_input_receiver_v1.zig").checkSourceEquation(partition, receipt.transition_sum, receipt.event_count, class_pin);
                            if (partition.mutable_events != class_expected.census.mutable or partition.claim.readonly_count != class_expected.census.readonly) return error.StaleReadonlyInputCensus;
                            self.transition_sum = self.transition_sum.add(partition.claim.mutable_sum);
                            self.readonly_count = try std.math.add(u64, self.readonly_count, partition.claim.readonly_count);
                        }
                    } else self.transition_sum = self.transition_sum.add(receipt.transition_sum);
                    self.ordinary_opposite = self.ordinary_opposite.add(receipt.universal_sum);
                    self.next_native += 1;
                }
                /// Called only after family11 arithmetic freshly verifies in that same
                /// loop. This reuses its authenticated caller roots, not opcode roots.
                pub fn onPrecompile(self: *Self, _: std.mem.Allocator, index: u32, callback_pin: programs.ExtensionPin, fresh: *const precompile.OpenReceipt) !void {
                    if (!self.owned or self.next_extension >= self.pins.extensions.len or index >= self.next_native) return error.InvalidV5MemoryCallerHookOrder;
                    const expected = self.pins.extensions[self.next_extension];
                    if (expected.public.execution_index != index or callback_pin.execution_index != index or !std.meta.eql(callback_pin.expected_key_id, expected.public.expected_key_id) or
                        !std.meta.eql(fresh.binding.caller_key_id, expected.public.expected_key_id) or !std.meta.eql(fresh.binding.sealed_digest, self.sealed.digest)) return error.UntrustedV5MemoryCallerHook;
                    const fixed = try caller_protocol.columnLogs(self.a, expected.public.statement, .fixed);
                    defer self.a.free(fixed);
                    const main = try caller_protocol.columnLogs(self.a, expected.public.statement, .main);
                    defer self.a.free(main);
                    const slots = try external_source.descriptorsFromStatementForMode(self.a, expected.public.statement, fixed, main, publicFrame(self.pins.executions[index]), self.sealed.register_custody_mode);
                    defer self.a.free(slots);
                    const received = try (self.loader.take_external orelse return error.MissingV5ExternalMemoryLoader)(self.loader.context, index);
                    var verified = try external.ForPackedBackend(Backend).verifyOwned(self.a, received, self.sealed, self.pins.memory.sealPins(), self.pins.memory.firstRound(), &fresh.binding, index, slots, fixed, main, expected.witness_root, self.pins.memory.sealPins().config);
                    defer verified.deinit(self.a);
                    try self.onFusedPrecompile(index, callback_pin, fresh, &verified);
                }
                /// Fresh composite access receipt borrowed only inside Global's proof
                /// verification callback. All independent source/event checks remain.
                pub fn onFusedPrecompile(self: *Self, index: u32, callback_pin: programs.ExtensionPin, fresh: *const precompile.OpenReceipt, verified: *const external.Verified) !void {
                    if (self.pins.readonly != null) return error.MissingV5CallerReadonlyClosure;
                    return self.onFusedPrecompileInternal(index, callback_pin, fresh, verified);
                }
                pub fn onReadonlyPrecompile(self: *Self, index: u32, callback_pin: programs.ExtensionPin, fresh: *const precompile.OpenReceipt, verified: *const ReadonlyPolicy.CallerProof.Verified) !void {
                    const selected = self.pins.readonly orelse return error.UnexpectedV5CallerReadonlyProof;
                    if (self.next_extension >= selected.caller.len) return error.InvalidV5MemoryCallerHookOrder;
                    const expected = selected.caller[self.next_extension];
                    const partition = verified.partition;
                    try expected.require(partition.all_rw_events);
                    if (partition.mutable_events != expected.mutable or partition.readonly_events != expected.readonly or
                        !partition.mutable_sum.add(partition.readonly_sum).eql(verified.memory.transition_sum) or
                        !std.meta.eql(partition.selection_digest, selected.authority.selection.expected_digest) or
                        !std.meta.eql(partition.plan_digest, selected.authority.plan.expected_digest) or !std.meta.eql(partition.sealed_digest, self.sealed.digest)) return error.StaleReadonlyInputCensus;
                    const previous = self.transition_sum;
                    try self.onFusedPrecompileInternal(index, callback_pin, fresh, &verified.memory);
                    self.transition_sum = previous.add(partition.mutable_sum);
                    self.readonly_count = try std.math.add(u64, self.readonly_count, partition.readonly_events);
                }
                fn onFusedPrecompileInternal(self: *Self, index: u32, callback_pin: programs.ExtensionPin, fresh: *const precompile.OpenReceipt, verified: *const external.Verified) !void {
                    if (!self.owned or self.next_extension >= self.pins.extensions.len or index >= self.next_native) return error.InvalidV5MemoryCallerHookOrder;
                    const expected = self.pins.extensions[self.next_extension];
                    if (expected.public.execution_index != index or callback_pin.execution_index != index or !std.meta.eql(callback_pin.expected_key_id, expected.public.expected_key_id) or
                        !std.meta.eql(fresh.binding.caller_key_id, expected.public.expected_key_id) or !std.meta.eql(fresh.binding.sealed_digest, self.sealed.digest)) return error.UntrustedV5MemoryCallerHook;
                    const fixed = try caller_protocol.columnLogs(self.a, expected.public.statement, .fixed);
                    defer self.a.free(fixed);
                    const main = try caller_protocol.columnLogs(self.a, expected.public.statement, .main);
                    defer self.a.free(main);
                    const slots = try external_source.descriptorsFromStatementForMode(self.a, expected.public.statement, fixed, main, publicFrame(self.pins.executions[index]), self.sealed.register_custody_mode);
                    defer self.a.free(slots);
                    if (verified.instance_index != index or !std.meta.eql(verified.caller_roots, fresh.binding.first_roots) or
                        !std.meta.eql(verified.witness_root, expected.witness_root) or
                        !std.meta.eql(verified.execution_instance_id, fresh.binding.execution_instance_id) or
                        !std.meta.eql(verified.caller_instance_id, fresh.binding.caller_instance_id) or
                        !std.meta.eql(verified.sealed_digest, self.sealed.digest)) return error.UntrustedV5FusedCallerMemoryIdentity;
                    const demand = try bytes.externalDemandForMode(expected.public.statement, slots, self.sealed.register_custody_mode);
                    try self.add(index, demand, try bytes.freshRequests(verified.*, demand, self.sealed.digest));
                    self.transition_sum = self.transition_sum.add(verified.transition_sum);
                    self.external_opposite = self.external_opposite.add(verified.universal_sum);
                    self.next_extension += 1;
                }
                pub fn finish(self: *Self) !OpenPartition {
                    if (!self.owned or self.next_native != self.pins.executions.len or self.next_extension != self.pins.extensions.len) return error.IncompleteV5MemoryHooks;
                    var count: u64 = 0;
                    for (self.byte_parts) |part| count = try std.math.add(u64, count, part.event_count);
                    if (self.readonly_count > count or count - self.readonly_count != self.fresh_memory.event_count) return error.UnclosedV5PackedTransitionBus;
                    var sink = @import("block_v5_global_join_algebra_v1.zig").ScalarSink{};
                    try @import("block_v5_global_join_algebra_v1.zig").Algebra(Q).transition(&sink, self.transition_sum, self.fresh_memory.transition_sum);
                    self.owned = false;
                    return .{ .memory = self.fresh_memory, .bytes = self.byte_parts, .ordinary_memory_opposite = self.ordinary_opposite, .external_memory_opposite = self.external_opposite, .allocator = self.a };
                }
                fn add(self: *Self, index: u32, demand: bytes.Demand, sum: Q) !void {
                    const part = &self.byte_parts[index];
                    part.event_count = try std.math.add(u64, part.event_count, demand.event_count);
                    part.request_count = try std.math.add(u64, part.request_count, demand.request_count);
                    part.max_requests = try std.math.add(u64, part.max_requests, demand.max_requests);
                    part.sum = part.sum.add(sum);
                }
            };
        }
        fn publicFrame(pin: programs.InstancePin) @import("../air/block/memory_event.zig").Frame {
            return .{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = @intCast(pin.shape.public_data.clock) };
        }
        fn extensionAt(values: []const ExtensionPin, index: u32) ?ExtensionPin {
            for (values) |value| if (value.public.execution_index == index) return value;
            return null;
        }
        fn executionEntry(entries: []const seal.Entry, index: u32) !seal.Entry {
            for (entries) |entry| if (entry.family == .execution and entry.index == index) return entry;
            return error.MissingV5EmptyOpcodeNative;
        }

        fn memorySlots(a: std.mem.Allocator, pin: programs.InstancePin, frame: @import("../air/block/memory_event.zig").Frame, mode: u32) ![]opcode.Slot {
            if (Stack.is_capacity) return FusedSource.memorySlots(a, pin.shape, programs.externalRetirements(pin), frame, mode);
            return @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, pin.shape, frame, mode);
        }
        fn requireCallback(pin: programs.InstancePin, callback: programs.InstancePin, fresh: *const native.OpenReceipt) !void {
            if (programs.externalRetirements(pin) != programs.externalRetirements(callback) or pin.profile != callback.profile) return error.UntrustedV5MemoryNativeHook;
            if (Stack.is_capacity) {
                if (!std.meta.eql(pin.limits, callback.limits) or
                    !std.meta.eql(fresh.exact_geometry_digest, try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(pin.shape, pin.external_retirements))) return error.UntrustedV5MemoryNativeHook;
                try pin.limits.requireShape(pin.shape, pin.external_retirements);
            }
        }
    };
}
