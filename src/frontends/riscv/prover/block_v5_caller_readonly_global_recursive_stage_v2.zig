//! Genuine caller arithmetic then fused capture, exact recursive parent
//! construction and fresh verification. No production/default activation.
const std = @import("std");
const Fused = @import("block_v5_caller_readonly_global_proof_v2.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Admission = @import("block_v5_caller_readonly_global_recursive_admission_v2.zig");
const Capture = @import("block_v5_caller_readonly_global_recursive_capture_v2.zig");
const Bus = @import("../recursion/block_v5_caller_readonly_global_recursive_public_bus_v2.zig");
const Protocol = @import("../recursion/block_v5_reusable_caller_readonly_global_parent_protocol_v2.zig");
const Leaf = @import("../recursion/block_v5_caller_readonly_global_recursive_leaf_v2.zig");
const Proving = @import("block_v5_supplemental_recursive_proving_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const TemplateCallback = @import("block_v5_recursive_template_callback_v1.zig").ForTypes(Admission.Prepared, Protocol.Key, Bus.Wire);
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    expected_key_id: [32]u8,
    schedule: []Bus.Wire,
    /// Genuine fused exports only. These are not whole-caller/block receipts.
    native: Fused.Verified,
    claims: Fused.ClaimFrames,
    public_values: Bus.Values,
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.schedule);
        self.native.deinit(a);
        self.claims.deinit(a);
        self.public_values.deinit();
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success consumes all owned artifact fields; error consumes none.
    put_caller_readonly_global: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
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
            cache: ?*SetupCache = null,
            pub fn validate(self: @This(), config: @import("stwo_core").pcs.PcsConfig) !void {
                if (!std.meta.eql(self.profile.config(), config)) return error.CallerReadonlyRecursiveSecurityMismatch;
                if (self.cache) |cache| if (cache.options.profile != self.profile) return error.CallerReadonlyRecursiveSecurityMismatch;
            }
        };
        const Preflight = struct {
            admitted: *const Admission.Prepared,
            callback: ?TemplateCallback,
            fn run(raw: *anyopaque, key: Protocol.Key, id: [32]u8, wires: []const Bus.Wire) !void {
                const self: *const Preflight = @ptrCast(@alignCast(raw));
                if (!std.meta.eql(key.config, self.admitted.config) or !std.meta.eql(key.context.child_config, self.admitted.config)) return error.CallerReadonlyRecursiveSecurityMismatch;
                if (!std.meta.eql(try key.identity(), id)) return error.UntrustedCallerReadonlyRecursiveKey;
                if (self.callback) |callback| try callback.admit(self.admitted, key, id, wires);
            }
        };
        fn captureFresh(a: std.mem.Allocator, caller_proof: *const Family.Proof, fused_proof: *const Fused.Proof, admitted: *const Admission.Prepared) !Capture.VerifiedCapture {
            const ArithmeticAdmission = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
            var policy = try ArithmeticAdmission.Prepared.init(a, admitted.statement, admitted.total_steps, admitted.binding, admitted.sealed, admitted.pins, admitted.entries, .{ .max_capture_bytes = admitted.limits.max_capture_bytes });
            defer policy.deinit();
            var caller = try @import("block_v5_caller_arithmetic_recursive_capture_v1.zig").ForBackend(Backend).verifyBorrowed(a, caller_proof, &policy);
            defer caller.deinit();
            return Capture.ForBackend(Backend).verifyAfterFreshCaller(a, fused_proof, &caller.receipt, admitted);
        }
        pub fn publish(a: std.mem.Allocator, caller_proof: *const Family.Proof, fused_proof: *const Fused.Proof, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try options.validate(admitted.config);
            var capture = try captureFresh(a, caller_proof, fused_proof, admitted);
            // The temporary arithmetic capture is released before parent rows.
            try publishConsumingVerifiedCapture(a, &capture, admitted, options, sink);
        }
        pub fn publishFromVerifiedCapture(a: std.mem.Allocator, capture: *const Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try publishCapture(false, a, capture, admitted, options, sink);
        }
        /// Consumes the genuine capture on success and error. Claims and range
        /// exports are copied into their final artifact custody before release.
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
            var claims = try Fused.ClaimFrames.clone(a, &capture.original.claims);
            errdefer claims.deinit(a);
            const ranges = try a.dupe(@import("block_execution_byte_range_v2.zig").Claims, capture.original.receipt.memory.range_claims);
            errdefer a.free(ranges);
            var native = capture.original.receipt;
            native.memory.range_claims = ranges;
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
            var fresh = try Leaf.verify(a, bytes, key, key_id, rows.wires, admitted, claims);
            defer fresh.deinit();
            const schedule = try a.dupe(Bus.Wire, rows.wires);
            errdefer a.free(schedule);
            var values = try fresh.public_values.clone(a);
            errdefer values.deinit();
            var artifact = Artifact{ .bytes = bytes, .key = key, .expected_key_id = key_id, .schedule = schedule, .native = native, .claims = claims, .public_values = values };
            try sink.put_caller_readonly_global(sink.context, admitted.binding.execution_index, &artifact);
            owns_bytes = false;
        }
    };
}
