//! Internally fresh source verification; caller-supplied scalar receipts never
//! authorize removal of RAM events. Outputs remain scoped/open globally.
const std = @import("std");
const core = @import("stwo_core");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Classification = @import("block_v5_readonly_input_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const CallerFused = @import("block_v5_caller_fused_proof_v1.zig");
const CallerReceiver = @import("block_v5_caller_fused_receiver_v1.zig");
fn publicPlan(a: std.mem.Allocator, pins: Plan.Pins, input: []const u8, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry) !Plan.Owned {
    try sealed.require(seal_pins, entries);
    if (sealed.register_custody_mode != 1 or !std.meta.eql(try pins.source.digest(), sealed.initialSourcePlanDigest()) or
        !std.meta.eql(try pins.source.digest(), seal_pins.initial_source_plan_digest)) return error.UntrustedReadonlyInputSourceAuthority;
    return Plan.admit(a, pins, input);
}
/// Both directions use exactly the same source-multiset/count closure. This is
/// called only after the source verifier has freshly checked base+fused bytes.
pub fn checkSourceEquation(partition: Classification.Open, sum: core.fields.qm31.QM31, events: u64, pin: Classification.Pin) !void {
    if (events != pin.events or try std.math.add(u64, partition.mutable_events, partition.claim.readonly_count) != events or
        !partition.claim.source_sum.add(sum).isZero()) return error.UnclosedReadonlyInputSource;
}
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const Native = if (capacity) @import("block_v5_native_capacity_proof_v1.zig") else @import("block_v5_native_execution_proof_v3.zig");
        const NativeFused = if (capacity) @import("block_v5_native_capacity_fused_proof_v1.zig") else @import("block_v5_native_projection_fused_proof_v2.zig");
        const NativeReceiver = if (capacity) @import("block_v5_native_capacity_fused_receiver_v1.zig") else @import("block_v5_native_projection_fused_receiver_v2.zig");
        const Catalog = if (capacity) @import("block_v5_native_capacity_catalog_v1.zig") else @import("block_v5_native_template_catalog_v1.zig");
        pub const NativeOpen = struct {
            source: NativeReceiver.Open,
            partition: ?Classification.Open,
            pub fn deinit(self: *NativeOpen, a: std.mem.Allocator) void {
                self.source.deinit(a);
                self.* = undefined;
            }
        };
        pub const CallerOpen = struct {
            source: CallerReceiver.Open,
            partition: Classification.Open,
            pub fn deinit(self: *CallerOpen, a: std.mem.Allocator) void {
                self.source.deinit(a);
                self.* = undefined;
            }
        };

        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                /// Transfers all proof ownership on every success/error path. The
                /// existing source receipt is retained so its table/register/ROM/byte
                /// obligations cannot disappear behind the new readonly partition.
                pub fn verifyNativeOwned(a: std.mem.Allocator, native: Native.Proof, fused: ?NativeFused.Proof, received: ?Classification.Proof, plan_pins: Plan.Pins, public_input: []const u8, classification_pin: ?Classification.Pin, index: u32, native_pin: NativeReceiver.InstancePin, memory_pin: NativeReceiver.MemoryPin, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !NativeOpen {
                    // Native receiver owns both source inputs from this call onward.
                    var classification = received;
                    var owns_classification = true;
                    defer if (owns_classification) if (classification) |*proof| proof.deinit(a);
                    var source = try NativeReceiver.ForBackend(Backend).verifyOwned(a, native, fused, index, native_pin, memory_pin, sealed, seal_pins, entries, catalog);
                    errdefer source.deinit(a);
                    var plan = try publicPlan(a, plan_pins, public_input, sealed, seal_pins, entries);
                    defer plan.deinit();
                    const memory = source.fused.memory;
                    if (memory == null) {
                        if (memory_pin.expected_events != 0 or classification_pin != null or classification != null) return error.UntrustedReadonlyInputAbsence;
                        return .{ .source = source, .partition = null };
                    }
                    const fresh = memory.?;
                    const pin = classification_pin orelse return error.MissingReadonlyInputPin;
                    if (!fresh.packed_transition or fresh.event_count != memory_pin.expected_events or pin.events != fresh.event_count or
                        !std.meta.eql(pin.source_identity, Classification.sourceIdentity(.native, index, sealed.digest, source.native.instance_id, fresh.native_roots, fresh.witness_root)))
                        return error.UntrustedReadonlyInputSourceIdentity;
                    const proof = classification orelse return error.MissingReadonlyInputProof;
                    owns_classification = false;
                    const partition = try Classification.ForBackend(Backend).verifyOwned(a, proof, pin, plan, sealed, seal_pins, entries);
                    try checkSourceEquation(partition, fresh.transition_sum, fresh.event_count, pin);
                    return .{ .source = source, .partition = partition };
                }
                pub fn verifyCallerOwned(a: std.mem.Allocator, caller: Family.Proof, fused: CallerFused.Proof, received: Classification.Proof, plan_pins: Plan.Pins, public_input: []const u8, classification_pin: Classification.Pin, index: u32, caller_pin: CallerReceiver.Pin, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry) !CallerOpen {
                    var classification = received;
                    var owns_classification = true;
                    defer if (owns_classification) classification.deinit(a);
                    var source = try CallerReceiver.ForBackend(Backend).verifyOwned(a, caller, fused, index, caller_pin, sealed, seal_pins, entries);
                    errdefer source.deinit(a);
                    var plan = try publicPlan(a, plan_pins, public_input, sealed, seal_pins, entries);
                    defer plan.deinit();
                    const fresh = source.fused.memory;
                    if (!fresh.packed_transition or fresh.event_count != caller_pin.expected_rw_events or classification_pin.events != fresh.event_count or
                        !std.meta.eql(classification_pin.source_identity, Classification.sourceIdentity(.caller, index, sealed.digest, source.caller.binding.caller_instance_id, fresh.caller_roots, fresh.witness_root)))
                        return error.UntrustedReadonlyInputSourceIdentity;
                    owns_classification = false;
                    const partition = try Classification.ForBackend(Backend).verifyOwned(a, classification, classification_pin, plan, sealed, seal_pins, entries);
                    try checkSourceEquation(partition, fresh.transition_sum, fresh.event_count, classification_pin);
                    return .{ .source = source, .partition = partition };
                }
            };
        }
    };
}
