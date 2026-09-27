//! Explicit genuine full-capacity fused recursive publication. No canonical
//! activation; every capture/rows/proof completes before the next instance.
const std = @import("std");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Admission = @import("block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Capture = @import("block_v5_native_capacity_fused_recursive_capture_v1.zig");
const Bus = @import("../recursion/block_v5_native_capacity_fused_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_native_capacity_fused_parent_protocol_v1.zig");
const Leaf = @import("../recursion/block_v5_native_capacity_fused_recursive_leaf_v1.zig");
const Exports = @import("block_v5_supplemental_recursive_exports_v1.zig");
const Proving = @import("block_v5_supplemental_recursive_proving_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const TemplateCallback = @import("block_v5_recursive_template_callback_v1.zig").ForTypes(Admission.Prepared, Protocol.Key, Bus.Wire);
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    expected_key_id: [32]u8,
    schedule: []Bus.Wire,
    /// Genuine fresh fused exports only; contains no verified-native-base bit.
    native: Fused.Verified,
    projection_claims: []Fused.Claim,
    memory_claims: []Memory.Claim,
    public_values: Bus.Values,
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.schedule);
        self.native.deinit(a);
        a.free(self.projection_claims);
        a.free(self.memory_claims);
        self.public_values.deinit();
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success consumes the independently owned artifact; error retains it.
    put_fused: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
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
                if (!std.meta.eql(self.profile.config(), config)) return error.CapacityFusedRecursiveSecurityMismatch;
                if (self.cache) |cache| if (cache.options.profile != self.profile) return error.CapacityFusedRecursiveSecurityMismatch;
            }
        };
        const Preflight = struct {
            admitted: *const Admission.Prepared,
            callback: ?TemplateCallback,
            fn run(raw: *anyopaque, key: Protocol.Key, id: [32]u8, wires: []const Bus.Wire) !void {
                const self: *const Preflight = @ptrCast(@alignCast(raw));
                if (!std.meta.eql(key.config, self.admitted.config) or !std.meta.eql(key.context.child_config, self.admitted.config)) return error.CapacityFusedRecursiveSecurityMismatch;
                if (!std.meta.eql(try key.identity(), id)) return error.UntrustedReusableCapacityFusedParentKey;
                if (self.callback) |callback| try callback.admit(self.admitted, key, id, wires);
            }
        };
        pub fn publish(a: std.mem.Allocator, proof: *const Fused.Proof, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try options.validate(admitted.config);
            var capture = try Capture.ForBackend(Backend).verifyBorrowed(a, proof, admitted, admitted.template_id);
            var owns_capture = true;
            defer if (owns_capture) capture.deinit();
            var rows = try Bus.prepare(a, admitted, &capture, options.transcript_capacity);
            defer rows.deinit();
            var exports = try Exports.NativeCopies.clone(a, capture.metadata.claims, capture.metadata.memory_claims, if (capture.receipt.memory) |receipt| receipt.range_claims else null);
            errdefer exports.deinit(a);
            const projections = exports.projection_claims;
            const memory = exports.memory_claims;
            var native = capture.receipt;
            if (native.memory) |*receipt| receipt.range_claims = exports.range_claims.?;
            // Preserve genuinely absent access. These are owned exports from
            // the actual capture, never a synthetic ordinary-memory proof.
            capture.deinit();
            owns_capture = false;
            var preflight = Preflight{ .admitted = admitted, .callback = options.on_template };
            const encoded = try Producer.proveEncoded(a, &rows, options.profile, options.cache, &preflight, Preflight.run);
            const key = encoded.key;
            const key_id = encoded.key_id;
            const bytes = encoded.bytes;
            var owns_bytes = true;
            defer if (owns_bytes) a.free(bytes);
            var fresh = try Leaf.verify(a, bytes, key, key_id, rows.wires, admitted, projections, memory);
            defer fresh.deinit();
            const schedule = try a.dupe(Bus.Wire, rows.wires);
            errdefer a.free(schedule);
            var values = try fresh.public_values.clone(a);
            errdefer values.deinit();
            var artifact = Artifact{ .bytes = bytes, .key = key, .expected_key_id = key_id, .schedule = schedule, .native = native, .projection_claims = projections, .memory_claims = memory, .public_values = values };
            try sink.put_fused(sink.context, admitted.native.index, &artifact);
            owns_bytes = false;
        }
    };
}
