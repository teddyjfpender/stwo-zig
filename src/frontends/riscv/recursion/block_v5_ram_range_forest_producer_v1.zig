//! Actual original bounded parent worker and strict codec, no receipt factory.
const std = @import("std");
const Bus = @import("block_v5_ram_range_forest_bus_v1.zig");
const Protocol = @import("block_v5_ram_range_forest_protocol_v1.zig");
const Preparation = @import("block_v5_ram_range_forest_preparation_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Workers = @import("blake3_native_parent_worker.zig");
pub const Options = Workers.Options;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Worker = Workers.WorkerForProtocol(Backend, Protocol);
        /// Setup proposal, independently admitted before any receiver uses it.
        pub fn deriveGeometry(a: std.mem.Allocator, prepared: *Preparation.Prepared, public: *const Bus.Owner, profile: Protocol.Profile) !@import("blake3_execution_parent_protocol.zig").Key {
            try public.validateSources();
            if (!std.meta.eql(profile.config(), public.policy.forest.memory.seal.config)) return error.UntrustedRamRangeForestSecurity;
            return Parent.ForBackend(Backend).deriveKeyWithProfile(a, &prepared.recursive, profile);
        }
        pub fn admission(prepared: *const Preparation.Prepared, public: *const Bus.Owner) !Protocol.Admission {
            try public.validate();
            const spec = public.policy.specs[public.policy.index];
            if (!std.meta.eql(spec.geometry.context, prepared.recursive.context) or prepared.wires.len != 0) return error.UntrustedRamRangeForestPreparation;
            const key = try Protocol.Key.fromGeometry(spec.geometry, &.{});
            return Protocol.Admission.init(key, spec.expected_id, &.{}, .{ .public = public });
        }
        pub fn init(a: std.mem.Allocator, prepared: *const Preparation.Prepared, public: *const Bus.Owner, options: Options) !*Worker {
            return Worker.init(a, &prepared.recursive.rows, try admission(prepared, public), options);
        }
        pub fn proveEncodedConsuming(a: std.mem.Allocator, worker: *Worker, prepared: *Preparation.Prepared, public: *const Bus.Owner) ![]u8 {
            defer prepared.recursive.rows.releaseRows();
            const admitted = try admission(prepared, public);
            var proof = try worker.proveAdmittedConsuming(&prepared.recursive.rows, admitted);
            defer proof.deinit();
            return Parent.codec.encode(a, &proof, &admitted);
        }
    };
}
