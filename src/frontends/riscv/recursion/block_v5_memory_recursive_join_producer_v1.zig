//! Actual original parent worker/codec for the distinct OPEN memory grammar.
//! Setup/key derivation is a proposal. Only Receiver.verify grants Fresh.
const std = @import("std");
const Public = @import("block_v5_memory_recursive_join_public_v1.zig");
const Protocol = @import("block_v5_memory_recursive_join_protocol_v1.zig");
const Preparation = @import("block_v5_memory_recursive_join_preparation_v1.zig");
const Original = @import("blake3_execution_parent_proof.zig");
const Workers = @import("blake3_native_parent_worker.zig");
pub const Options = Workers.Options;
pub const complete_block_authority = false;
pub fn admit(prepared: *const Preparation.Prepared, public: *const Public.Owner, key: Protocol.Key, expected_id: [32]u8) !Protocol.Admission {
    if (!std.meta.eql(key.context, prepared.recursive.context)) return error.UntrustedRecursiveMemoryJoinPreparation;
    return Protocol.Admission.init(key, expected_id, prepared.wires, .{ .public = public });
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Worker = Workers.WorkerForProtocol(Backend, Protocol);
        pub fn deriveKey(a: std.mem.Allocator, prepared: *Preparation.Prepared, public: *const Public.Owner, profile: Protocol.Profile) !Protocol.Key {
            try public.validate();
            if (!std.meta.eql(profile.config(), public.policy.memory.seal.config)) return error.UntrustedRecursiveMemoryJoinSecurity;
            const geometry = try Original.ForBackend(Backend).deriveKeyWithProfile(a, &prepared.recursive, profile);
            const key = try Protocol.Key.fromGeometry(geometry, prepared.wires);
            _ = try admit(prepared, public, key, try key.identity());
            return key;
        }
        /// Public owner and its genuine Fresh children/policies outlive worker.
        /// The existing worker owns its bounded setup, shared/joined pool and
        /// scratch. Fresh transcript admission is replaced on every request.
        pub fn init(a: std.mem.Allocator, prepared: *const Preparation.Prepared, public: *const Public.Owner, key: Protocol.Key, expected_id: [32]u8, options: Options) !*Worker {
            return Worker.init(a, &prepared.recursive.rows, try admit(prepared, public, key, expected_id), options);
        }
        /// Original consuming worker releases the source rows before FRI and
        /// on all errors. Wires/owner remain live through strict codec framing.
        pub fn proveEncodedConsuming(a: std.mem.Allocator, worker: *Worker, prepared: *Preparation.Prepared, public: *const Public.Owner, key: Protocol.Key, expected_id: [32]u8) ![]u8 {
            // Even a pre-admission failure consumes this one-shot row owner.
            defer prepared.recursive.rows.releaseRows();
            const admission = try admit(prepared, public, key, expected_id);
            var proof = try worker.proveAdmittedConsuming(&prepared.recursive.rows, admission);
            defer proof.deinit();
            return Original.codec.encode(a, &proof, &admission);
        }
    };
}
