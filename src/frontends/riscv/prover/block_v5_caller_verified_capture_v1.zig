//! Full real arithmetic and fused STARK capture. No externally supplied open
//! receipt can enter this detached entry; both proof byte objects verify fresh.
const std = @import("std");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Receiver = @import("block_v5_caller_fused_receiver_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Pin = Receiver.Pin;
pub const Verified = struct {
    caller: Family.VerifiedCapture,
    fused: Fused.VerifiedCapture,
    pub fn deinit(self: *Verified) void {
        self.fused.deinit();
        self.caller.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Verified, a: std.mem.Allocator, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
        try Receiver.admit(a, index, pin, sealed, pins, entries);
        try self.caller.validate(a, pin.statement, pin.total_steps, Receiver.binding(index, pin, sealed), sealed, pins, entries);
        try self.fused.validateAfterFreshCaller(a, &self.caller.receipt, pin.statement, pin.total_steps, pin.frame, pin.witness_root, sealed, pins, entries);
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Both original proofs transfer ownership on every failure or success.
        pub fn verifyOwned(a: std.mem.Allocator, caller_received: Family.Proof, fused_received: Fused.Proof, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Verified {
            return verifyInternal(true, a, &caller_received, &fused_received, index, pin, sealed, pins, entries);
        }
        /// No source proof arrays/PCS leases are retained or cloned. Source
        /// objects must stay alive and immutable only until verification ends.
        pub fn verifyBorrowed(a: std.mem.Allocator, caller: *const Family.Proof, fused: *const Fused.Proof, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Verified {
            return verifyInternal(false, a, caller, fused, index, pin, sealed, pins, entries);
        }
        fn verifyInternal(comptime take: bool, a: std.mem.Allocator, caller_received: *const Family.Proof, fused_received: *const Fused.Proof, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Verified {
            var caller = caller_received.*;
            var fused = fused_received.*;
            var owns_caller = take;
            var owns_fused = take;
            defer if (owns_caller) caller.deinit(a);
            defer if (owns_fused) fused.deinit(a);
            try Receiver.admit(a, index, pin, sealed, pins, entries);
            const Base = Family.ForBackend(Backend);
            var fresh = if (take) owned: {
                owns_caller = false;
                break :owned try Base.verifyCaptureOwned(a, caller, pin.statement, pin.total_steps, pin.expected_key_id, pin.execution_instance_id, index, sealed, pins, entries);
            } else try Base.verifyCaptureBorrowed(a, caller_received, pin.statement, pin.total_steps, pin.expected_key_id, pin.execution_instance_id, index, sealed, pins, entries);
            errdefer fresh.deinit();
            if (!std.meta.eql(fresh.receipt.binding, Receiver.binding(index, pin, sealed))) return error.UntrustedV5CallerCompositeFreshBase;
            const Access = Fused.ForBackend(Backend);
            const projected = if (take) owned: {
                owns_fused = false;
                break :owned try Access.verifyCaptureOwnedAfterFreshCaller(a, fused, &fresh.receipt, pin.statement, pin.total_steps, pin.frame, pin.witness_root, sealed, pins, entries);
            } else try Access.verifyCaptureBorrowedAfterFreshCaller(a, fused_received, &fresh.receipt, pin.statement, pin.total_steps, pin.frame, pin.witness_root, sealed, pins, entries);
            return .{ .caller = fresh, .fused = projected };
        }
    };
}
