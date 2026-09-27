//! Shared producer lifetime for genuine supplemental verifier rows. This does
//! not derive proof-independent expected keys or validate original captures.
//! Family stages own those exact original authority and publication boundaries.
const std = @import("std");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Producer = @import("../recursion/blake3_native_parent_producer.zig");
pub fn ForModules(comptime Backend: type, comptime Bus: type, comptime Protocol: type) type {
    const Cache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForModules(Backend, Bus, Protocol);
    const Plan = Producer.PlanForProtocol(Backend, Protocol);
    return struct {
        pub const Encoded = struct { bytes: []u8, key: Protocol.Key, key_id: [32]u8 };
        /// The preflight is a synchronous borrowing callback. For cached work
        /// it runs on the original joined lane after real worker/admission
        /// acquisition and before proveConsuming. It must not reenter that
        /// cache. Failure stops proving and retains original error/row cleanup.
        pub fn proveEncoded(a: std.mem.Allocator, rows: *Bus.Prepared, profile: Parent.protocol.Profile, cache: ?*Cache, context: *anyopaque, preflight: *const fn (*anyopaque, Protocol.Key, [32]u8, []const Bus.Wire) anyerror!void) !Encoded {
            var proved = if (cache) |reuse|
                try reuse.provePreparedConsumingWithPreflight(rows, context, preflight)
            else cold: {
                const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, profile);
                const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
                const id = try key.identity();
                try preflight(context, key, id, rows.wires);
                const authority = try Protocol.Admission.init(key, id, rows.wires, rows.values);
                const plan = try Plan.init(a, &rows.recursive.rows, authority);
                defer plan.deinit();
                var workspace = Producer.Workspace.init(a, 0);
                defer workspace.deinit();
                const proof = try plan.proveConsumingWithWorkspace(a, &rows.recursive.rows, &workspace);
                break :cold Cache.Proved{ .key = key, .key_id = id, .proof = proof };
            };
            // Cold plan/workspace are already released here; only the original
            // proof and separately owned public values survive into encoding.
            // Plan.proveWithWorkspace documents independent output ownership;
            // its core uses `a`, checks outputAliasesScratch, and returns
            // artifact.Owned.init(a, extended.proof, ..., claims), never arena
            // pointers. Owned.deinit frees the core proof through that `a`.
            defer proved.proof.deinit();
            if (!std.meta.eql(try proved.key.identity(), proved.key_id)) return error.UntrustedSupplementalRecursiveKey;
            const authority = try Protocol.Admission.init(proved.key, proved.key_id, rows.wires, rows.values);
            const bytes = try Parent.codec.encode(a, &proved.proof, &authority);
            return .{ .bytes = bytes, .key = proved.key, .key_id = proved.key_id };
        }
    };
}
