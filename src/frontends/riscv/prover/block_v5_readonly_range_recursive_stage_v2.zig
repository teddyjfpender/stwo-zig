//! Original Range16 verifier kernel under independent readonly provider roster.
//! An independently supplied expected key/schedule is mandatory before capture;
//! this stage does not derive expected authority from a private proof witness.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_range16_proof_v1.zig");
const Admission = @import("block_v5_readonly_range_recursive_admission_v2.zig");
const Capture = @import("block_v5_readonly_range_recursive_capture_v2.zig");
const Bus = @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_range16_parent_protocol_v1.zig");
const Leaf = @import("../recursion/block_v5_range16_recursive_leaf_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const TemplateCallback = @import("block_v5_recursive_template_callback_v1.zig").ForTypes(Admission.Prepared, Protocol.Key, Bus.Wire);
pub const Expected = struct {
    key: Protocol.Key,
    key_id: [32]u8,
    /// Borrowed immutable independently reconstructed schedule. It must outlive
    /// the synchronous stage call; received envelopes never select this field.
    schedule: []const Bus.Wire,
    pub fn require(self: Expected, admitted: *const Admission.Prepared) !void {
        try admitted.validate(admitted.template_id);
        if (!std.meta.eql(self.key.config, admitted.config) or !std.meta.eql(self.key.context.child_config, admitted.config) or
            !std.meta.eql(self.key.context.child_key_id, admitted.template_id) or
            !std.meta.eql(try self.key.identity(), self.key_id) or
            !std.meta.eql(try Bus.scheduleDigest(self.schedule), self.key.public_schedule_digest)) return error.UntrustedReadonlyRangeV2RecursiveExpected;
    }
};
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    expected_key_id: [32]u8,
    schedule: []Bus.Wire,
    native: Native.OpenReceipt,
    public_values: Bus.Values,
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.schedule);
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers every owned Artifact field; failure transfers none.
    put_readonly_global_range: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const SetupCache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForModules(Backend, Bus, Protocol);
        const Producer = @import("block_v5_supplemental_recursive_proving_v1.zig").ForModules(Backend, Bus, Protocol);
        pub const Options = struct {
            expected: Expected,
            on_template: ?TemplateCallback = null,
            profile: Parent.protocol.Profile,
            transcript_capacity: u32 = 2,
            cache: ?*SetupCache = null,
            pub fn validate(self: @This(), admitted: *const Admission.Prepared) !void {
                if (self.transcript_capacity == 0 or !std.meta.eql(self.profile.config(), admitted.config) or self.expected.key.profile != self.profile) return error.ReadonlyRangeV2RecursiveSecurityMismatch;
                if (self.cache) |cache| if (cache.options.profile != self.profile) return error.ReadonlyRangeV2RecursiveSecurityMismatch;
                try self.expected.require(admitted);
            }
        };
        const Preflight = struct {
            admitted: *const Admission.Prepared,
            options: Options,
            fn run(raw: *anyopaque, key: Protocol.Key, id: [32]u8, wires: []const Bus.Wire) !void {
                const self: *const Preflight = @ptrCast(@alignCast(raw));
                try self.options.expected.require(self.admitted);
                if (!std.meta.eql(key, self.options.expected.key) or !std.meta.eql(id, self.options.expected.key_id) or
                    !std.meta.eql(try Bus.scheduleDigest(wires), self.options.expected.key.public_schedule_digest) or
                    !std.meta.eql(wires, self.options.expected.schedule)) return error.UntrustedReadonlyRangeV2RecursiveExpected;
                if (self.options.on_template) |callback| try callback.admit(self.admitted, key, id, wires);
            }
        };
        pub fn publish(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try options.validate(admitted);
            var capture = try Capture.ForBackend(Backend).verifyBorrowed(a, proof, admitted);
            try publishConsumingVerifiedCapture(a, &capture, admitted, options, sink);
        }
        pub fn publishFromVerifiedCapture(a: std.mem.Allocator, capture: *const Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try publishCapture(false, a, capture, admitted, options, sink);
        }
        /// Consumes the actual original proof capture on success and failure.
        pub fn publishConsumingVerifiedCapture(a: std.mem.Allocator, capture: *Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try publishCapture(true, a, capture, admitted, options, sink);
        }
        fn publishCapture(comptime consuming: bool, a: std.mem.Allocator, capture: if (consuming) *Capture.VerifiedCapture else *const Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            var owns_capture = consuming;
            defer if (consuming) {
                if (owns_capture) capture.deinit();
            };
            try options.validate(admitted);
            try capture.validate(admitted, admitted.template_id);
            var rows = try Bus.prepare(a, admitted, capture, options.transcript_capacity);
            var owns_rows = true;
            defer if (owns_rows) rows.deinit();
            const native = capture.receipt;
            if (consuming) {
                capture.deinit();
                owns_capture = false;
            }
            var preflight = Preflight{ .admitted = admitted, .options = options };
            const encoded = try Producer.proveEncoded(a, &rows, options.profile, options.cache, &preflight, Preflight.run);
            var owns_bytes = true;
            defer if (owns_bytes) a.free(encoded.bytes);
            const schedule = try a.dupe(Bus.Wire, rows.wires);
            errdefer a.free(schedule);
            // The consuming producer and proof encoder are finished. Release
            // all page/verifier rows before decoding the independent CPU proof.
            rows.deinit();
            owns_rows = false;
            var fresh = try Leaf.verify(a, encoded.bytes, options.expected.key, options.expected.key_id, schedule, admitted, native);
            defer fresh.deinit();
            const values = fresh.public_values;
            var artifact = Artifact{ .bytes = encoded.bytes, .key = encoded.key, .expected_key_id = encoded.key_id, .schedule = schedule, .native = native, .public_values = values };
            try sink.put_readonly_global_range(sink.context, admitted.pin.index, &artifact);
            owns_bytes = false;
        }
    };
}
