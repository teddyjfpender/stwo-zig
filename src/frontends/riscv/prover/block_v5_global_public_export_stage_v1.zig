//! Genuine OPEN public-export parent proof publication. This consumes no source
//! authority and selects no CLI/canonical defaults. The same parent contains
//! every original heterogeneous child verifier plus scoped accounting equations.
const std = @import("std");
const Bus = @import("../recursion/block_v5_global_public_export_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_global_public_export_protocol_v1.zig");
const Rows = @import("../recursion/block_v5_global_public_export_parent_v1.zig");
const Receiver = @import("../recursion/block_v5_global_public_export_receiver_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    key_id: [32]u8,
    schedule: []Bus.Wire,
    coverage_digest: [32]u8,
    pub const complete_block_authority = false;
    pub const source_authorities_pending = @import("block_v5_recursive_coverage_plan_v1.zig").SOURCE_COUNT;
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.schedule);
        self.* = undefined;
    }
};
pub const Sink = struct { context: *anyopaque, put_open: *const fn (*anyopaque, *Artifact) anyerror!void };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Cache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForModules(Backend, Bus, Protocol);
        pub const Options = struct { profile: Parent.protocol.Profile, max_parent_bytes: usize = 512 << 20, public_fields: @import("../recursion/block_v5_global_public_fields_v1.zig").Limits = .{}, cache: ?*Cache = null };
        /// Success consumes ONLY the artifact transferred to sink. Rows/policy
        /// remain owned by caller; setup cache workers rebind dynamic admission.
        /// The supplied cache uses the same outer aggregate-budget allocator.
        pub fn publishPrepared(backing: std.mem.Allocator, rows: *Rows.Prepared, options: Options, sink: Sink) !void {
            if (options.max_parent_bytes == 0 or !std.meta.eql(options.profile.config(), rows.recursive.context.child_config)) return error.GlobalPublicExportResourceLimit;
            try rows.values.validate();
            _ = try Bus.scheduleDigest(rows.wires);
            const a = rows.allocator;
            var key: Protocol.Key = undefined;
            var id: [32]u8 = undefined;
            var bytes: []u8 = undefined;
            if (options.cache) |cache| {
                if (cache.options.profile != options.profile) return error.V5NativeSetupCacheSecurityMismatch;
                var proved = try cache.provePreparedConsuming(rows);
                defer proved.proof.deinit();
                key = proved.key;
                id = proved.key_id;
                const admission = try Protocol.Admission.init(key, id, rows.wires, rows.values);
                bytes = try Parent.codec.encode(a, &proved.proof, &admission);
            } else {
                const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, options.profile);
                key = try Protocol.Key.fromGeometry(geometry, rows.wires);
                id = try key.identity();
                const admission = try Protocol.Admission.init(key, id, rows.wires, rows.values);
                const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
                const plan = try Plan.init(a, &rows.recursive.rows, admission);
                defer plan.deinit();
                var proof = try plan.prove(a, &rows.recursive.rows);
                defer proof.deinit();
                bytes = try Parent.codec.encode(a, &proof, &admission);
            }
            defer a.free(bytes);
            if (bytes.len == 0 or bytes.len > options.max_parent_bytes) return error.GlobalPublicExportResourceLimit;
            // One genuine fresh receiver, including canonical PUBLIC derivation.
            // Publisher never substitutes pre-satisfied host sums for this proof.
            var checked = try Receiver.verify(a, bytes, key, id, rows.wires, rows.public.policy, options.public_fields);
            defer checked.deinit();
            const durable_bytes = try backing.dupe(u8, bytes);
            var own_bytes = true;
            defer if (own_bytes) backing.free(durable_bytes);
            const schedule = try backing.dupe(Bus.Wire, rows.wires);
            var own_schedule = true;
            defer if (own_schedule) backing.free(schedule);
            var artifact = Artifact{ .bytes = durable_bytes, .key = key, .key_id = id, .schedule = schedule, .coverage_digest = rows.public.policy.original.plan.pinned_digest };
            try sink.put_open(sink.context, &artifact);
            own_bytes = false;
            own_schedule = false;
        }
    };
}
