//! Strategy-based shared parent verifier; no original equations duplicated.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return With(@import("block_v8_endpoint_recursive_adapter_v1.zig").For(family));
}
pub fn With(comptime Adapter: type) type {
    return struct {
        // Shared-original -> single recursive proof, with one independently compiled
        // fixed commitment reused for proving. All parent rows are consumed before
        // returning durable bytes. No source receipt substitutes for fresh receiving.
        const std = @import("std");
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        const Profile = Adapter.Profile;
        const Whole = Adapter.Original;
        const Ledger = Adapter.Ledger;
        const Statement = Adapter.Statement;
        const ClaimWire = @import("../prover/block_v7_union_claim_wire_v1.zig");
        const Parent = @import("blake3_execution_parent_proof.zig");
        const Protocol = Adapter.Protocol;
        const Receiver = Adapter.Receiver;
        pub const Limits = struct {
            capacity: u32 = 4,
            profile: @import("blake3_execution_parent_protocol.zig").Profile = .csp_q70_pow26,
            fixed: Adapter.Fixed.Limits = .{},
            preparation: Adapter.Preparation.Limits = .{},
            max_claim_bytes: usize = 8 << 20,
            max_claim_items: usize = 1 << 18,
        };
        pub const Stats = struct {
            fixed_compile_ns: u64 = 0,
            fixed_commit_ns: u64 = 0,
            witness_prepare_ns: u64 = 0,
            fixed_parity_ns: u64 = 0,
            plan_ns: u64 = 0,
            proof_ns: u64 = 0,
            encoding_ns: u64 = 0,
            whole_ns: u64 = 0,
            retained_rows_bytes: usize = 0,
            fixed_commitment_reused: bool = false,
        };
        pub const Artifact = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,
            claims: []u8,
            stats: Stats,
            pub fn deinit(self: *Artifact) void {
                self.allocator.free(self.bytes);
                self.allocator.free(self.claims);
                self.* = undefined;
            }
        };
        pub fn produce(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture, limits: Limits) !Artifact {
            if (limits.capacity == 0 or limits.max_claim_bytes == 0 or limits.max_claim_items == 0 or !std.meta.eql(limits.profile.config(), Adapter.epoch(profile).config)) return error.InvalidEndpointPipelinePolicy;
            var whole = try std.time.Timer.start();
            var phase = try std.time.Timer.start();
            var stats: Stats = .{};
            try profile.requireCapture(capture);
            var cold = try Adapter.Fixed.Owned.derive(a, profile, limits.capacity, limits.fixed);
            var cold_live = true;
            defer if (cold_live) cold.deinit();
            stats.fixed_compile_ns = phase.lap();
            const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
            var committed: ?Fixed.Committed = try Fixed.deriveCommitted(a, cold.fixed, cold.context, limits.profile);
            defer if (committed) |*owned| owned.deinit();
            const roster = [_]Protocol.Bus.Expected{try Receiver.expected(profile)};
            const key = try Protocol.Key.fromGeometry(committed.?.key, cold.wires, &roster);
            stats.fixed_commit_ns = phase.lap();
            var ready = try Adapter.Preparation.prepare(a, profile, capture, limits.capacity, limits.preparation);
            defer ready.deinit();
            stats.witness_prepare_ns = phase.lap();
            try cold.validateLive(&ready);
            stats.retained_rows_bytes = try ready.recursive.rows.retainedBytes();
            cold.deinit();
            cold_live = false;
            stats.fixed_parity_ns = phase.lap();
            const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, .{ .children = &.{ready.values} }, &roster);
            const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
            const plan = try Plan.initFromFixedCommitment(a, &ready.recursive.rows, admission, &committed.?);
            // Plan owns its retained lease. It does not recommit these fixed columns.
            committed.?.deinit();
            committed = null;
            defer plan.deinit();
            stats.fixed_commitment_reused = true;
            stats.plan_ns = phase.lap();
            var proof = try plan.proveConsuming(a, &ready.recursive.rows);
            defer proof.deinit();
            stats.proof_ns = phase.lap();
            const bytes = try Parent.codec.encode(a, &proof, &admission);
            errdefer a.free(bytes);
            var writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(a, limits.max_claim_bytes);
            defer writer.deinit();
            var count = limits.max_claim_items;
            try ClaimWire.encode(Ledger.Claims, &writer, profile.claims, &count);
            const claims = try writer.bytes.toOwnedSlice(a);
            stats.encoding_ns = phase.lap();
            stats.whole_ns = whole.read();
            return .{ .allocator = a, .bytes = bytes, .claims = claims, .stats = stats };
        }
        /// Finite claim decoding and independent key setup. Metadata must come from the
        /// external ELF/endpoints admission path, never a producer-trusted pointer.
        /// The returned equation owns its allocations independently of decode storage.
        pub fn verify(a: std.mem.Allocator, root: []const u8, physical_claims: []const u8, metadata: *const Statement.Owned, original_limits: Profile.Limits, limits: Limits) !Receiver.Verified {
            if (limits.capacity == 0 or limits.max_claim_items == 0 or physical_claims.len > limits.max_claim_bytes or !std.meta.eql(limits.profile.config(), metadata.trusted.config)) return error.InvalidEndpointPipelinePolicy;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = physical_claims };
            var count = limits.max_claim_items;
            const claims = try ClaimWire.decode(Ledger.Claims, arena.allocator(), &cursor, &count);
            if (cursor.position != physical_claims.len) return error.NonCanonicalEndpointClaimSuffix;
            return Receiver.verifyStatement(a, root, metadata, claims, original_limits, limits.capacity, limits.profile, limits.fixed);
        }
    };
}
