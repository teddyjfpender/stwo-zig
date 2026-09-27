//! Opt-in genuine B5CT leaf publication. One real native proof is freshly
//! captured, recursively proved, encoded and freshly checked before transfer.
//! No NativeV3 warm callback/receipt is admitted and no canonical default changes.
const std = @import("std");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Prepared = @import("block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
const Bus = @import("../recursion/block_v5_capacity_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_capacity_parent_protocol_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Receiver = @import("../recursion/block_v5_capacity_recursive_leaf_v1.zig");
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    expected_key_id: [32]u8,
    schedule: []Bus.Wire,
    native: Native.OpenReceipt,
    public_values: Bus.Values,
    span: @import("../recursion/block_v5_pc_clock_span_v1.zig").Span,
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.schedule);
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success consumes the owned artifact; error retains it at this stage.
    put_leaf: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const SetupCache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForCapacityBackend(Backend);
        pub const Options = struct { profile: Parent.protocol.Profile, cache: ?*SetupCache = null, transcript_capacity: u32 = 2, boundary: ?@import("block_v5_proof_boundary_v1.zig").Boundary = null };
        pub fn captureNative(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Prepared, options: Options) !Native.VerifiedCapture {
            try checkBoundary(options);
            if (!std.meta.eql(options.profile.config(), admitted.config) or !std.meta.eql(admitted.template.config, admitted.config)) return error.CapacityRecursiveSecurityMismatch;
            try admitted.validate(admitted.template_id);
            return if (admitted.catalog) |catalog|
                Native.ForBackend(Backend).verifyCaptureBorrowedWithCatalog(a, proof, admitted.shape, admitted.external_retirements, admitted.pin, admitted.template, admitted.template_id, admitted.index, admitted.sealed, admitted.pins, admitted.entries, admitted.limits, catalog)
            else
                Native.ForBackend(Backend).verifyCaptureBorrowed(a, proof, admitted.shape, admitted.external_retirements, admitted.pin, admitted.template, admitted.template_id, admitted.index, admitted.sealed, admitted.pins, admitted.entries, admitted.limits);
        }
        pub fn publish(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Prepared, options: Options, sink: Sink) !void {
            var capture = try captureNative(a, proof, admitted, options);
            defer capture.deinit();
            try publishFromVerifiedCapture(a, &capture, admitted, options, sink);
        }
        /// Borrows a genuinely fresh, independently owned native capture. No
        /// source proof, execution replay or native PCS is retained by this path.
        /// Mutation seal and full independent admission are checked anew.
        pub fn publishFromVerifiedCapture(a: std.mem.Allocator, capture: *const Native.VerifiedCapture, admitted: *const Prepared, options: Options, sink: Sink) !void {
            try checkBoundary(options);
            if (!std.meta.eql(options.profile.config(), admitted.config) or !std.meta.eql(admitted.template.config, admitted.config)) return error.CapacityRecursiveSecurityMismatch;
            try capture.validate(admitted, admitted.template_id);
            var rows = try Bus.prepare(a, admitted, capture, options.transcript_capacity);
            defer rows.deinit();
            try checkBoundary(options);
            var cached: ?SetupCache.Proved = null;
            var owns_cached = false;
            defer if (owns_cached) cached.?.proof.deinit();
            const key = if (options.cache) |cache| hit: {
                if (cache.options.profile != options.profile) return error.CapacityRecursiveSecurityMismatch;
                cached = try cache.provePreparedConsuming(&rows);
                owns_cached = true;
                break :hit cached.?.key;
            } else cold: {
                const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, options.profile);
                break :cold try Protocol.Key.fromGeometry(geometry, rows.wires);
            };
            if (!std.meta.eql(key.config, admitted.config) or !std.meta.eql(key.context.child_config, admitted.config)) return error.CapacityRecursiveSecurityMismatch;
            const key_id = try key.identity();
            const authority = try Protocol.Admission.init(key, key_id, rows.wires, rows.values);
            const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            var plan: ?*Plan = null;
            defer if (plan) |value| value.deinit();
            if (cached == null) plan = try Plan.init(a, &rows.recursive.rows, authority);
            var proved = if (cached) |value| value.proof else try plan.?.prove(a, &rows.recursive.rows);
            owns_cached = false;
            defer proved.deinit();
            try checkBoundary(options);
            const bytes = try Parent.codec.encode(a, &proved, &authority);
            var owns_bytes = true;
            defer if (owns_bytes) a.free(bytes);
            var fresh = try Receiver.verify(a, bytes, key, key_id, rows.wires, admitted, capture.receipt);
            defer fresh.deinit();
            try checkBoundary(options);
            const schedule = try a.dupe(Bus.Wire, rows.wires);
            var owns_schedule = true;
            defer if (owns_schedule) a.free(schedule);
            var artifact = Artifact{ .bytes = bytes, .key = key, .expected_key_id = key_id, .schedule = schedule, .native = capture.receipt, .public_values = fresh.public_values, .span = fresh.pc_clock_span };
            try sink.put_leaf(sink.context, admitted.index, &artifact);
            owns_bytes = false;
            owns_schedule = false;
        }
        fn checkBoundary(options: Options) !void {
            if (options.boundary) |boundary| try boundary.check(boundary.context);
        }
    };
}
