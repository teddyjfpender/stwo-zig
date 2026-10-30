const std = @import("std");
const Multi = @import("../../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Driver = @import("../../prover/block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const Producer = @import("../../prover/block_v7_window_union_producer_v1.zig");
const Profile = @import("../block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Capsule = @import("../block_v7_union_compiler_capsule_v1.zig").Capsule;
const Public = @import("../block_v8_union_closed_public_v1.zig");
const Graph = @import("../air/block_v8_union_closed_graph_v1.zig");
const Pipeline = @import("../block_v8_union_closed_pipeline_v1.zig");
const ParentProfile = @import("../blake3_execution_parent_protocol.zig").Profile;
const Q = @import("stwo_core").fields.qm31.QM31;
fn Consumer(comptime recursive: bool, comptime selected: ParentProfile) type {
    return struct {
        pub const config = selected.config();
        pub const Result = *Producer.Artifact;
        pub const limits: Multi.Limits = .{ .max_retained_pcs_bytes = 8 << 30 };
        pub fn consumeStagedWindow(f: Driver.StagedWindowFixture) !Result {
            return Producer.produce(f, .{ .limits = limits });
        }
        pub fn discardStagedResult(artifact: Result) void {
            artifact.deinit();
        }
        pub fn verifyAfterProducersDestroyedWithExternal(artifact: Result, external: @import("../../prover/block_v7_window_union_loader_v1.zig").External) !void {
            const a = artifact.allocator;
            const profile = try Profile.Owned.derive(a, artifact.statement, &artifact.proof.claims, .{ .original = limits });
            defer profile.deinit();
            var capture = try Multi.verifyViewAndCapture(a, artifact.statement.trusted, artifact.statement.input, &artifact.proof.view(), limits);
            var capture_live = true;
            defer if (capture_live) capture.deinit();
            const capsule = try Capsule.derive(a, artifact.statement, &capture.claims, .{ .original = limits });
            defer capsule.deinit();
            var values = try Public.Values.derive(a, capsule);
            defer values.deinit();
            var graph = try Graph.prepare(a, capsule, values);
            defer graph.deinit();
            var cold = try Graph.compile(a, capsule, values);
            defer cold.deinit();
            try std.testing.expectEqualDeep(graph.circuit.identity_digest, cold.circuit.identity_digest);
            // Exactly the original authenticated physical projection claim
            // coordinates: compensate +1/-1 across windows, preserving the
            // aggregate while violating each window's own state closure.
            var physical: [2]usize = undefined;
            var projection_slots: [2]usize = undefined;
            var offset: usize = 0;
            for (capsule.compiler().admission.components.context.natives, 0..) |native, index| {
                var found = false;
                for (native.component.layout.slots, 0..) |slot, projection| if (slot.kind == .lookup and slot.kind.lookup.partition == .registers_state) {
                    physical[index] = offset + 8 + projection;
                    projection_slots[index] = projection;
                    found = true;
                    break;
                };
                try std.testing.expect(found);
                offset += try @import("../air/block_v6_partitioned_composition_v1.zig").publicCount(native.component.layout.slots.len, native.component.slots.len);
            }
            const forged = try a.dupe(Q, graph.inputs);
            defer a.free(forged);
            // The first graph input block is the complete original public
            // operand vector, so these indexes cannot silently name extras.
            forged[physical[0]] = forged[physical[0]].add(Q.one());
            forged[physical[1]] = forged[physical[1]].sub(Q.one());
            const evaluated = try a.alloc(Q, graph.values.len);
            defer a.free(evaluated);
            try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(forged, evaluated));
            if (recursive) {
                const policy = Pipeline.Limits{ .profile = selected, .fixed = .{ .max_bytes = 8 << 30 }, .preparation = .{ .max_bytes = 8 << 30 } };
                var root = try Pipeline.produce(a, profile, &capture, policy);
                defer root.deinit();
                const forged_claims = blk: {
                    const first_claim = &capture.claims.native[0].claims[projection_slots[0]].sum;
                    const second_claim = &capture.claims.native[1].claims[projection_slots[1]].sum;
                    const prior_first = first_claim.*;
                    const prior_second = second_claim.*;
                    defer first_claim.* = prior_first;
                    defer second_claim.* = prior_second;
                    first_claim.* = first_claim.add(Q.one());
                    second_claim.* = second_claim.sub(Q.one());
                    var writer = @import("../../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
                    defer writer.deinit();
                    var remaining: usize = 1 << 18;
                    try @import("../../prover/block_v7_union_claim_wire_v1.zig").encode(Multi.Claims, &writer, capture.claims, &remaining);
                    break :blk try writer.bytes.toOwnedSlice(a);
                };
                defer a.free(forged_claims);
                const Metadata = @import("../../prover/block_v7_multi_union_statement_wire_v1.zig").ForMode(true);
                const Loader = @import("../../prover/block_v7_window_union_loader_v1.zig");
                const encoded = try Metadata.encode(a, artifact.statement, .{});
                defer a.free(encoded);
                const detached = try Loader.admitMetadata(a, encoded, external, .{ .wire = .{ .scope = limits } });
                defer detached.deinit();
                // Original proof, its fresh capture, producer rows and parent
                // plans are destroyed before detached reconstruction.
                artifact.releaseProof();
                capture.deinit();
                capture_live = false;
                var verified = try Pipeline.verify(a, root.bytes, root.claims, detached, limits, policy);
                verified.deinit();
                if (Pipeline.verify(a, root.bytes, forged_claims, detached, limits, policy)) |accepted| {
                    var bad = accepted;
                    bad.deinit();
                    return error.AcceptedCompensatedClosedUnionClaims;
                } else |err| {
                    if (err == error.OutOfMemory) return err;
                    std.debug.print("V8_CLOSED_UNION_FORGERY compensated_state_claims_rejected={s}\n", .{@errorName(err)});
                }
                root.bytes[0] ^= 1;
                if (Pipeline.verify(a, root.bytes, root.claims, detached, limits, policy)) |accepted| {
                    var bad = accepted;
                    bad.deinit();
                    return error.AcceptedChangedClosedUnionProof;
                } else |_| {}
                root.bytes[0] ^= 1;
                std.debug.print("V8_CLOSED_UNION_RECURSION scope=declared_nonterminal_window original_destroyed=true fresh_key=true host_closure=false bytes={d} proof_ns={d}\n", .{ root.bytes.len, root.stats.proof_ns });
            }
        }
    };
}
test "native-only V8 closure graph binds physical claims and rejects compensated window state claims" {
    try @import("../../prover/block_v7_real_window_execution_test_support_v2.zig").runNativeTail(Consumer(false, .diagnostic_q8_pow0));
}
test "native-only V8 single recursive proof constrains complete window closure with fresh receiving" {
    try @import("../../prover/block_v7_real_window_execution_test_support_v2.zig").runNativeTail(Consumer(true, .diagnostic_q8_pow0));
}

test "canonical V8 native-only recursive root constrains global closure after detached metadata reconstruction" {
    try @import("../../prover/block_v7_real_window_execution_test_support_v2.zig").runNativeTail(Consumer(true, .csp_q70_pow26));
}
