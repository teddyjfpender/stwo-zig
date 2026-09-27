//! Explicit genuine nineteen-component caller arithmetic recursive publication. No canonical receiver or
//! driver/default is switched; parent rows include every actual verifier stage.
const std = @import("std");
const Native = @import("block_v5_precompile_family_proof_v1.zig");
const Admission = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Capture = @import("block_v5_caller_arithmetic_recursive_capture_v1.zig");
const Bus = @import("../recursion/block_v5_caller_arithmetic_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_caller_arithmetic_parent_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_caller_arithmetic_recursive_leaf_v1.zig");
const Proving = @import("block_v5_supplemental_recursive_proving_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const TemplateCallback = @import("block_v5_recursive_template_callback_v1.zig").ForTypes(Admission.Prepared, Protocol.Key, Bus.Wire);
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
    /// Success consumes the owned artifact; error leaves it with this stage.
    put_caller_arithmetic: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Producer = Proving.ForModules(Backend, Bus, Protocol);
        pub const SetupCache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForModules(Backend, Bus, Protocol);
        pub const Options = struct {
            /// Genuine original verifier rows determine this template before publication.
            on_template: ?TemplateCallback = null,
            profile: Parent.protocol.Profile,
            transcript_capacity: u32 = 2,
            /// Borrowed cache and pool remain alive throughout this synchronous
            /// call. All publication data is independently owned on success.
            cache: ?*SetupCache = null,
            pub fn validate(self: @This(), config: @import("stwo_core").pcs.PcsConfig) !void {
                if (!std.meta.eql(self.profile.config(), config)) return error.CallerArithmeticRecursiveSecurityMismatch;
                if (self.cache) |cache| if (cache.options.profile != self.profile) return error.CallerArithmeticRecursiveSecurityMismatch;
            }
        };
        const Preflight = struct {
            admitted: *const Admission.Prepared,
            callback: ?TemplateCallback,
            fn run(raw: *anyopaque, key: Protocol.Key, id: [32]u8, wires: []const Bus.Wire) !void {
                const self: *const Preflight = @ptrCast(@alignCast(raw));
                if (!std.meta.eql(key.config, self.admitted.config) or !std.meta.eql(key.context.child_config, self.admitted.config)) return error.CallerArithmeticRecursiveSecurityMismatch;
                if (!std.meta.eql(try key.identity(), id)) return error.UntrustedSupplementalRecursiveKey;
                if (self.callback) |callback| try callback.admit(self.admitted, key, id, wires);
            }
        };
        pub fn publish(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try options.validate(admitted.config);
            var capture = try Capture.ForBackend(Backend).verifyBorrowed(a, proof, admitted);
            // This method consumes the genuine capture on success and error.
            try publishConsumingVerifiedCapture(a, &capture, admitted, options, sink);
        }
        pub fn publishFromVerifiedCapture(a: std.mem.Allocator, capture: *const Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try publishCapture(false, a, capture, admitted, options, sink);
        }
        /// Consumes on every return. Immutable public receipts/claims are
        /// retained by value before the large original PCS capture is released.
        pub fn publishConsumingVerifiedCapture(a: std.mem.Allocator, capture: *Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try publishCapture(true, a, capture, admitted, options, sink);
        }
        fn publishCapture(comptime consuming: bool, a: std.mem.Allocator, capture: if (consuming) *Capture.VerifiedCapture else *const Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            var owns_capture = consuming;
            defer if (consuming) {
                if (owns_capture) capture.deinit();
            };
            try options.validate(admitted.config);
            try capture.validate(admitted, admitted.template_id);
            var rows = try Bus.prepare(a, admitted, capture, options.transcript_capacity);
            defer rows.deinit();
            const native = capture.receipt;
            const claims = capture.original.claims;
            if (consuming) {
                capture.deinit();
                owns_capture = false;
            }
            var preflight = Preflight{ .admitted = admitted, .callback = options.on_template };
            const encoded = try Producer.proveEncoded(a, &rows, options.profile, options.cache, &preflight, Preflight.run);
            const key = encoded.key;
            const key_id = encoded.key_id;
            const bytes = encoded.bytes;
            var owns_bytes = true;
            defer if (owns_bytes) a.free(bytes);
            var fresh = try Receiver.verify(a, bytes, key, key_id, rows.wires, admitted, native, claims);
            defer fresh.deinit();
            const schedule = try a.dupe(Bus.Wire, rows.wires);
            var owns_schedule = true;
            defer if (owns_schedule) a.free(schedule);
            var artifact = Artifact{ .bytes = bytes, .key = key, .expected_key_id = key_id, .schedule = schedule, .native = native, .public_values = fresh.public_values };
            try sink.put_caller_arithmetic(sink.context, admitted.binding.execution_index, &artifact);
            owns_bytes = false;
            owns_schedule = false;
        }
    };
}
