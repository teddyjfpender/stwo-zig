//! Detached fresh caller+composite verification. A public receipt alone cannot
//! enter this API. The result is scoped until all independently planned buses
//! and provider groups have closed in the complete block receiver.
const std = @import("std");
const core = @import("stwo_core");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Fused = @import("block_v5_caller_readonly_proof_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Seal = @import("block_v5_source_seal_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const Pin = struct {
    statement: *const Profile.admission.Statement,
    total_steps: u32,
    execution_instance_id: [32]u8,
    expected_key_id: [32]u8,
    expected_caller_instance_id: [32]u8,
    roots: Seal.Roots,
    witness_root: [32]u8,
    frame: Frame,
    expected_rw_events: u64,
    readonly: @import("block_v5_caller_readonly_protocol_v1.zig").Authority,
};
pub const Open = struct {
    caller: Family.OpenReceipt,
    fused: Fused.Verified,
    pub fn deinit(self: *Open, a: std.mem.Allocator) void {
        self.fused.deinit(a);
        self.* = undefined;
    }
};
pub fn binding(index: u32, pin: Pin, sealed: Seal.Sealed) Protocol.CallerBinding {
    return .{ .execution_index = index, .caller_entry_index = index, .execution_instance_id = pin.execution_instance_id, .caller_key_id = pin.expected_key_id, .caller_instance_id = pin.expected_caller_instance_id, .first_roots = pin.roots, .sealed_digest = sealed.digest };
}
pub fn admit(a: std.mem.Allocator, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
    var admitted_plan = try pin.readonly.admit(a);
    defer admitted_plan.deinit();
    try Protocol.validate(pin.statement, pin.total_steps, pins.config);
    try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, pin.statement);
    if (pin.frame.cycle_count != pin.total_steps or !std.meta.eql(pin.expected_key_id, try Protocol.keyId(pin.statement, pin.total_steps, pins.config, pin.roots[0])) or !std.meta.eql(pin.expected_caller_instance_id, Protocol.instanceId(pin.expected_key_id, pin.execution_instance_id, index, pin.roots))) return error.UntrustedV5CallerCompositePin;
    var schedule = try Schedule.init(a, pin.statement, pin.total_steps, pin.frame, sealed.register_custody_mode);
    defer schedule.deinit();
    if (schedule.rw_events != pin.expected_rw_events) return error.UntrustedV5CallerCompositeEventCensus;
    try Fused.admit(binding(index, pin, sealed), pin.witness_root, pin.frame, &schedule, sealed, pins, entries, pin.readonly);
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Ownership transfers for both actual proofs on every path.
        pub fn verifyOwned(a: std.mem.Allocator, caller_received: Family.Proof, fused_received: Fused.Proof, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Open {
            var caller = caller_received;
            var fused = fused_received;
            var owns_caller = true;
            var owns_fused = true;
            defer if (owns_caller) caller.deinit(a);
            defer if (owns_fused) fused.deinit(a);
            try admit(a, index, pin, sealed, pins, entries);
            owns_caller = false;
            const fresh = try Family.ForBackend(Backend).verifyOwned(a, caller, pin.statement, pin.total_steps, pin.expected_key_id, pin.execution_instance_id, index, sealed, pins, entries);
            if (!std.meta.eql(fresh.binding, binding(index, pin, sealed))) return error.UntrustedV5CallerCompositeFreshBase;
            owns_fused = false;
            const result = try Fused.ForBackend(Backend).verifyAfterFreshCaller(a, fused, &fresh, pin.statement, pin.total_steps, pin.frame, pin.witness_root, sealed, pins, entries, pin.readonly);
            return .{ .caller = fresh, .fused = result };
        }
        /// Exact sparse absence is a missing obligation, never a fake zero
        /// receipt. No caller/projection proof is skipped for a supplied Pin.
        pub fn verifyOptionalOwned(a: std.mem.Allocator, caller_received: ?Family.Proof, fused_received: ?Fused.Proof, index: u32, pin: ?Pin, readonly: @import("block_v5_caller_readonly_protocol_v1.zig").Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !?Open {
            var caller = caller_received;
            var fused = fused_received;
            var owns = true;
            defer if (owns) {
                if (caller) |*proof| proof.deinit(a);
                if (fused) |*proof| proof.deinit(a);
            };
            var plan = try readonly.admit(a);
            defer plan.deinit();
            try sealed.require(pins, entries);
            if (sealed.register_custody_mode != 1 or !std.meta.eql(sealed.initial_source_plan_digest, try readonly.plan.source.digest())) return error.UntrustedCallerReadonlySourceAuthority;
            if (pin) |present| {
                if (!std.meta.eql(present.readonly.selection.expected_digest, readonly.selection.expected_digest) or !std.meta.eql(present.readonly.plan.expected_digest, readonly.plan.expected_digest) or !std.meta.eql(present.readonly.limits, readonly.limits)) return error.UntrustedCallerReadonlySelection;
                if (caller == null or fused == null) return error.MissingV5CallerCompositeProof;
                owns = false;
                return try verifyOwned(a, caller.?, fused.?, index, present, sealed, pins, entries);
            }
            try requireAbsence(index, sealed, entries);
            if (caller != null or fused != null) return error.UnexpectedV5AbsentCallerProof;
            return null;
        }
    };
}
/// Source seal already validates exact family cardinality/order. A complete
/// receiver must additionally derive its sparse Pin roster from pinned job
/// execution/caller census; this structural absence alone creates no authority.
pub fn requireAbsence(index: u32, sealed: Seal.Sealed, entries: []const Seal.Entry) !void {
    if (index >= sealed.execution_instance_count) return error.UntrustedV5CallerCompositeAbsentIndex;
    var execution = false;
    for (entries) |item| {
        if (item.index != index) continue;
        if (item.family == .execution) execution = true;
        if (item.family == .precompile or item.family == .program_extension_request or item.family == .execution_external_sidecar) return error.MissingV5CallerCompositePin;
    }
    if (!execution) return error.MissingV5CallerCompositeExecution;
}
