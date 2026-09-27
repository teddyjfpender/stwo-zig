//! Consumed ORIGINAL native/fused or caller arithmetic proofs, followed by the
//! genuine compact V2 classifier. No Open DTO is an alternate verification API.
const std = @import("std");
const core = @import("stwo_core");
const Seal = @import("block_v5_source_seal_v1.zig");
const Source = @import("block_v5_native_readonly_source_proof_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Join = @import("block_v5_readonly_input_global_join_v2.zig");
const Caller = @import("block_v5_caller_readonly_global_receiver_v2.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Q = core.fields.qm31.QM31;
pub const NativePolicy = struct {
    authority: *const Roster.Authority,
    ordinal: u32,
    limits: @import("block_v5_readonly_input_proof_v1.zig").Limits = .{},
};
/// Internal scoped result used by the original memory hook, not block authority.
pub const NativePartition = struct { mutable_sum: Q, readonly_count: u64 };
pub fn requireSession(policy: NativePolicy, joined: *const Join.Owned, sealed: Seal.Sealed) !void {
    // A session is constructed inside the complete receiver from this same
    // independent owner. Never substitute an unrelated accumulator mid-loop.
    if (joined.authority != policy.authority or !std.meta.eql(joined.sealed, sealed)) return error.UntrustedGlobalReadonlyJoinSession;
    try policy.authority.requireEpoch(sealed);
}
pub fn ForStack(comptime Stack: type) type {
    return struct {
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                /// All three original proof arguments transfer on EVERY path.
                /// The original fused receiver freshly verifies native first;
                /// classification then closes its actual all-RW transition sum.
                pub fn verifyNativeOwned(a: std.mem.Allocator, native_received: Stack.Native.Proof, fused_received: ?Stack.Fused.Proof, classifier_received: ?Source.Proof, index: u32, pin: Stack.FusedReceiver.InstancePin, memory: Stack.FusedReceiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Stack.Catalog.Admission, policy: NativePolicy, joined: *Join.Owned) !Stack.FusedReceiver.Open {
                    var classifier = classifier_received;
                    var owns_classifier = true;
                    defer if (owns_classifier) if (classifier) |*proof| proof.deinit(a);
                    // Even a rejected independent policy must consume originals.
                    var original = try Stack.FusedReceiver.ForBackend(Backend).verifyOwned(a, native_received, fused_received, index, pin, memory, sealed, pins, entries, catalog);
                    errdefer original.deinit(a);
                    owns_classifier = false;
                    _ = try consumeAfterFreshNative(a, classifier, index, &original.native, if (original.fused.memory) |*part| part else null, memory.witness_root, sealed, pins, entries, policy, joined);
                    return original;
                }
                /// Internal hook only. Complete receive invokes it solely from
                /// the ORIGINAL consumed proof loop after both verifiers pass.
                /// Public complete APIs never accept `fresh` or `memory` DTOs.
                pub fn consumeAfterFreshNative(a: std.mem.Allocator, received: ?Source.Proof, index: u32, fresh: *const Stack.Native.OpenReceipt, memory: ?*const @import("block_v5_opcode_memory_sidecar_proof_v1.zig").Verified, witness_root: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, policy: NativePolicy, joined: *Join.Owned) !NativePartition {
                    var proof = received;
                    var owns = true;
                    defer if (owns) if (proof) |*present| present.deinit(a);
                    try requireSession(policy, joined, sealed);
                    const expected = try policy.authority.source(policy.ordinal);
                    if (expected.kind != .native or expected.index != index or !std.meta.eql(expected.roots, .{ fresh.first_roots[0], fresh.first_roots[1], witness_root }) or
                        !std.meta.eql(fresh.sealed_digest, sealed.digest)) return error.UntrustedGlobalReadonlyFreshNative;
                    if (memory) |part| {
                        if (part.instance_index != index or !std.meta.eql(part.native_roots, fresh.first_roots) or !std.meta.eql(part.native_instance_id, fresh.instance_id) or
                            !std.meta.eql(part.witness_root, witness_root) or part.event_count != expected.census.all_rw) return error.UntrustedGlobalReadonlyFreshNative;
                    } else if (expected.census.all_rw != 0) return error.MissingGlobalReadonlyFreshAccess;
                    if (expected.census.all_rw == 0) {
                        if (proof != null or expected.classifier_roots != null) return error.UntrustedGlobalReadonlyClassifierAbsence;
                        const actual = if (memory) |part| part.transition_sum else Q.zero();
                        try joined.nativeAbsent(policy.ordinal, actual, if (memory) |part| part.event_count else 0);
                        return .{ .mutable_sum = Q.zero(), .readonly_count = 0 };
                    }
                    const received_classifier = proof orelse return error.MissingGlobalReadonlyClassifierProof;
                    const classifier_pin = try Source.Pin.fromAuthority(policy.authority, policy.ordinal, pins.config, policy.limits);
                    owns = false;
                    const verified = try Source.ForBackend(Backend).verifyOwned(a, received_classifier, classifier_pin, policy.authority, sealed, pins, entries);
                    const access = memory orelse return error.MissingGlobalReadonlyFreshAccess;
                    try joined.native(verified, access.transition_sum, access.event_count);
                    return .{ .mutable_sum = verified.claim.mutable_sum, .readonly_count = verified.claim.readonly_count };
                }
            };
        }
    };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Consumes both actual proofs before entering group accounting. Returned
        /// arrays remain owned by Open and are destroyed on join failure.
        pub fn verifyCallerOwned(a: std.mem.Allocator, caller_received: Family.Proof, classifier_received: @import("block_v5_caller_readonly_global_proof_v2.zig").Proof, index: u32, pin: Caller.Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, joined: *Join.Owned) !Caller.Open {
            var actual = try Caller.ForBackend(Backend).verifyOwned(a, caller_received, classifier_received, index, pin, sealed, pins, entries);
            errdefer actual.deinit(a);
            try requireSession(.{ .authority = pin.readonly.roster, .ordinal = pin.readonly.ordinal }, joined, sealed);
            try joined.caller(&actual.fused);
            return actual;
        }
    };
}
