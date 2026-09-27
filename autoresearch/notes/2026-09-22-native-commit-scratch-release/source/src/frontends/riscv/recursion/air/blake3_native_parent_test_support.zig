//! Real-proof qualification of the complete native row assembler.
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const std = @import("std");
        const native = @import("blake3_native_parent_rows.zig");
        const protocol = @import("../blake3_native_parent_protocol.zig");
        const f = @import("blake3_proof_fixture.zig").ForBackend(Backend);
        const F = @import("blake3_native_parent_roster.zig").Roster;
        pub fn check(comptime Engine: type, backing: std.mem.Allocator, prepared: *native.Prepared, context: protocol.Context, policy: anytype, jobs: []const @import("../blake3_native_parent_pipeline.zig").Job(Engine)) !void {
            var arena = std.heap.ArenaAllocator.init(backing);
            defer arena.deinit();
            const a = arena.allocator();
            var logs: [F.Airs.len]u32 = undefined;
            inline for (F.Airs, 0..) |_, i| {
                logs[i] = if (prepared.fixed[i].len <= 1) 1 else std.math.log2_int_ceil(usize, prepared.fixed[i].len);
            }
            const trusted = try preprocessing(a, prepared.fixed, logs);
            var key_channel = f.Channel{};
            var key_scheme = try f.Scheme.init(a, protocol.PCS_CONFIG);
            defer key_scheme.deinit(a);
            try key_scheme.commit(a, trusted, &key_channel);
            const key_roots = try key_scheme.roots(a);
            const key = protocol.Key{ .context = context, .log_sizes = logs, .preprocessed_root = key_roots.items[0] };
            const expected = try key.identity();
            const admitted = try protocol.Admission.init(key, expected);
            var wrong_pin = expected;
            wrong_pin[31] ^= 0x80;
            try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(key, wrong_pin));
            var wrong_key = key;
            wrong_key.version = protocol.VERSION - 1;
            try std.testing.expectError(error.InvalidBlake3ParentProfile, protocol.Admission.init(wrong_key, expected));
            wrong_key = key;
            wrong_key.config.fri_config.n_queries += 1;
            try std.testing.expectError(error.InvalidBlake3ParentProfile, protocol.Admission.init(wrong_key, expected));
            wrong_key = key;
            wrong_key.context.graph_ids[0][0] ^= 1;
            try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(wrong_key, expected));
            wrong_key = key;
            wrong_key.context.child_config.lifting_log_size = 0;
            try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(wrong_key, expected));
            var changed_root = key.preprocessed_root;
            changed_root[31] ^= 0x80;
            try std.testing.expectError(error.UntrustedBlake3ParentRoot, admitted.admitRoot(changed_root));
            std.debug.print("V2_BLAKE3_NATIVE_PARENT_KEY id={s} profile=diagnostic_q8_pow0\n", .{std.fmt.bytesToHex(expected, .lower)});
            const Worker = @import("../blake3_native_parent_worker.zig").Worker(Backend);
            try std.testing.expectError(error.InvalidWorkerBudget, Worker.init(backing, prepared, admitted, .{ .worker_count = 0, .host_byte_limit = 1, .retained_scratch_limit = 0 }));
            try std.testing.expectError(error.OutOfMemory, Worker.init(backing, prepared, admitted, .{ .worker_count = 1, .host_byte_limit = 1, .retained_scratch_limit = 0 }));
            const worker = try Worker.init(backing, prepared, admitted, .{ .worker_count = 2, .host_byte_limit = 4 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
            var worker_alive = true;
            defer if (worker_alive) worker.deinit();
            const plan = worker.plan;
            {
                worker.busy.lock();
                defer worker.busy.unlock();
                try std.testing.expectError(error.ParentWorkerAlreadyLeased, worker.prove(prepared));
            }
            {
                const index = native.Airs[0].PHYSICAL_MAIN_COLUMN_COUNT;
                const saved = prepared.fixed[0][0][index];
                defer prepared.fixed[0][0][index] = saved;
                prepared.fixed[0][0][index] = saved.add(f.M31.one());
                try std.testing.expectError(error.InvalidBlake3ParentRows, plan.validateRows(prepared));
            }
            {
                const saved = prepared.main[0];
                defer prepared.main[0] = saved;
                prepared.main[0] = saved[0 .. saved.len - 1];
                try std.testing.expectError(error.InvalidBlake3ParentRows, plan.validateRows(prepared));
            }
            {
                const saved = prepared.main[0][0];
                defer prepared.main[0][0] = saved;
                prepared.main[0][0].log_size += 1;
                try std.testing.expectError(error.InvalidBlake3ParentRows, plan.validateRows(prepared));
                prepared.main[0][0] = saved;
                prepared.main[0][0].values = saved.values[0 .. saved.values.len - 1];
                try std.testing.expectError(error.InvalidBlake3ParentRows, plan.validateRows(prepared));
            }
            const workspace = &worker.workspace;
            {
                _ = try workspace.begin();
                defer workspace.end();
                try std.testing.expectError(error.ParentWorkspaceAlreadyLeased, plan.proveWithWorkspace(backing, prepared, workspace));
            }
            try std.testing.expectError(error.ParentOutputAllocatorAliasesScratch, plan.proveWithWorkspace(workspace.arena.allocator(), prepared, workspace));
            {
                var failing = std.testing.FailingAllocator.init(backing, .{ .fail_index = 0 });
                var failed_workspace = @import("../blake3_native_parent_producer.zig").Workspace.init(failing.allocator(), 0);
                defer failed_workspace.deinit();
                try std.testing.expectError(error.OutOfMemory, plan.proveWithWorkspace(backing, prepared, &failed_workspace));
                _ = try failed_workspace.begin();
                failed_workspace.end();
            }
            const plan_bytes = plan.arena.state.end_index;
            const fixed_columns = plan.fixed_commitment.columns.ptr;
            const fixed_coefficients = plan.fixed_commitment.coefficients;
            const pipeline = @import("../blake3_native_parent_pipeline.zig");
            const sizing = pipeline.Sizing{ .preparation_bytes = 2 * 1024 * 1024 * 1024, .worker_bytes = 4 * 1024 * 1024 * 1024, .queued_bytes = 512 * 1024 * 1024, .external_reserved_bytes = 4 * 1024 * 1024 * 1024 };
            var excessive = sizing;
            excessive.external_reserved_bytes = std.math.maxInt(usize) / 2;
            try std.testing.expectError(error.ParentPipelineMemoryBudgetExceeded, pipeline.admit(Backend, policy, excessive, jobs.len));
            const Policy = @TypeOf(policy.*);
            const cpu_limited = try Policy.init(policy.host, .{ .total_cpu_tokens = 2, .cpu_tokens_per_node = 2, .proof_worker_count = 2, .maximum_parallel_nodes = 1, .total_rss_bytes = policy.total_rss_bytes, .rss_bytes_per_node = policy.rss_bytes_per_node });
            try std.testing.expectError(error.ParentPipelineCpuBudgetExceeded, pipeline.admit(Backend, &cpu_limited, sizing, jobs.len));
            var denied_preparation = sizing;
            denied_preparation.preparation_bytes = 64 * 1024 * 1024;
            try std.testing.expectError(error.PreparationHostBudgetExceeded, pipeline.run(Backend, Engine, backing, policy, denied_preparation, worker, jobs));
            {
                worker.busy.lock();
                defer worker.busy.unlock();
                try std.testing.expectError(error.ParentWorkerAlreadyLeased, pipeline.run(Backend, Engine, backing, policy, sizing, worker, jobs));
            }
            var report = try pipeline.run(Backend, Engine, backing, policy, sizing, worker, jobs);
            defer report.deinit();
            try std.testing.expectEqual(@as(usize, 2), report.outputs.len);
            try std.testing.expect(report.overlapNs() > 0);
            std.debug.print("V2_BLAKE3_NATIVE_PARENT_PIPELINE jobs=2 cpu_tokens={d} reserved_bytes={d} overlap_ns={d}\n", .{ report.admission.cpu_tokens, report.admission.reserved_bytes, report.overlapNs() });
            {
                const first = &report.outputs[0];
                const first_proof = first.proof.?;
                first.proof = null;
                _ = try (GateProtocol{ .admission = admitted }).verifyOwned(first.allocator, first_proof, first.claims);
                first.deinit();
            }
            try std.testing.expect(workspace.arena.queryCapacity() > 0);
            try std.testing.expect(workspace.arena.queryCapacity() <= workspace.retained_limit);
            try std.testing.expectEqual(fixed_columns, plan.fixed_commitment.columns.ptr);
            try std.testing.expectEqual(fixed_coefficients, plan.fixed_commitment.coefficients);
            const produced = &report.outputs[1];
            try std.testing.expectEqual(plan_bytes, plan.arena.state.end_index);
            try std.testing.expect(workspace.arena.queryCapacity() <= workspace.retained_limit);
            const usage = worker.budget.snapshot();
            std.debug.print("V2_BLAKE3_NATIVE_PARENT_WORKER workers=2 peak_routed_bytes={d} host_limit_bytes={d}\n", .{ usage.peak_live_bytes, usage.limit });
            try std.testing.expect(usage.peak_live_bytes <= usage.limit);
            worker_alive = false;
            worker.deinit();
            // Codec copies use an independent allocator. The original proof's
            // budget lease must also survive through verification capture.
            const codec = @import("../blake3_native_parent_codec.zig");
            const bytes = try codec.encode(backing, produced, &admitted);
            defer backing.free(bytes);
            var copied = try codec.decode(backing, bytes, &admitted);
            defer copied.deinit();
            const proof = copied.proof.?;
            copied.proof = null;
            _ = try (GateProtocol{ .admission = admitted }).verifyOwned(backing, proof, copied.claims);
            var verified = try @import("../blake3_native_parent_verifier.zig").verify(produced, &admitted);
            defer verified.deinit();
            produced.deinit();
            try std.testing.expect(verified.allocation_budget != null);
            try std.testing.expectEqual(@as(usize, 8), verified.capture.queries.raw.len);
            std.debug.print("V2_BLAKE3_NATIVE_PARENT_PRODUCER standalone=true worker_released_before_capture=true fixed_commit_reused=true workspace_reused=true workspace_released_before_verify=true proofs=2 plan_released_before_verify=true\n", .{});
            std.debug.print("V2_BLAKE3_NATIVE_PARENT verified\n", .{});
        }
        const GateProtocol = struct {
            admission: protocol.Admission,
            pub fn config(self: @This()) !f.core.pcs.PcsConfig {
                return self.admission.config();
            }
            pub fn mix(self: @This(), channel: *f.Channel) !void {
                return self.admission.mix(channel);
            }
            pub fn mixClaims(self: @This(), channel: *f.Channel, claims: []const f.QM31) !void {
                return self.admission.mixClaims(channel, claims);
            }
            pub fn admitRoot(self: @This(), root: f.Hasher.Hash) !void {
                return self.admission.admitRoot(root);
            }
            pub fn verifyOwned(self: @This(), a: std.mem.Allocator, proof: @import("../blake3_engine_protocol.zig").Proof, claims: @import("../blake3_native_parent_artifact.zig").Claims) !f.Channel {
                const artifact = @import("../blake3_native_parent_artifact.zig");
                var owned = artifact.Owned.init(a, proof, self.admission.expected_id, claims);
                defer owned.deinit();
                try owned.validate(&self.admission);
                owned.key_id[31] ^= 0x80;
                try std.testing.expectError(error.UntrustedBlake3ParentKey, owned.validate(&self.admission));
                owned.key_id[31] ^= 0x80;
                const saved = owned.claims[0];
                owned.claims[0] = saved.add(f.QM31.one());
                try std.testing.expectError(error.InvalidBlake3ParentClaims, owned.validate(&self.admission));
                owned.claims[0] = saved;
                owned.proof.?.commitment_scheme_proof.commitments.items[0][31] ^= 0x80;
                try std.testing.expectError(error.UntrustedBlake3ParentRoot, owned.validate(&self.admission));
                owned.proof.?.commitment_scheme_proof.commitments.items[0][31] ^= 0x80;
                try std.testing.expect(owned.proof != null);
                const codec = @import("../blake3_native_parent_codec.zig");
                const bytes = try codec.encode(a, &owned, &self.admission);
                defer a.free(bytes);
                try std.testing.expectError(error.TruncatedBlake3ParentArtifact, codec.decode(a, bytes[0 .. codec.HEADER_BYTES - 1], &self.admission));
                try std.testing.expectError(error.Blake3ParentArtifactLengthMismatch, codec.decode(a, bytes[0 .. bytes.len - 1], &self.admission));
                const trailing = try std.mem.concat(a, u8, &.{ bytes, &.{0} });
                defer a.free(trailing);
                try std.testing.expectError(error.Blake3ParentArtifactLengthMismatch, codec.decode(a, trailing, &self.admission));
                const changed = try a.dupe(u8, bytes);
                defer a.free(changed);
                changed[8] ^= 1;
                try std.testing.expectError(error.InvalidBlake3ParentArtifactVersion, codec.decode(a, changed, &self.admission));
                @memcpy(changed, bytes);
                changed[12] ^= 0x80;
                try std.testing.expectError(error.UntrustedBlake3ParentKey, codec.decode(a, changed, &self.admission));
                @memcpy(changed, bytes);
                std.mem.writeInt(u32, changed[44..48], f.core.fields.m31.Modulus, .little);
                try std.testing.expectError(error.InvalidBlake3ParentClaims, codec.decode(a, changed, &self.admission));
                @memcpy(changed, bytes);
                std.mem.writeInt(u64, changed[codec.HEADER_BYTES - 8 ..][0..8], std.math.maxInt(u64), .little);
                try std.testing.expectError(error.Blake3ParentArtifactTooLarge, codec.decode(a, changed, &self.admission));
                @memcpy(changed, bytes);
                changed[codec.HEADER_BYTES] = 1; // Wrong PCS PoW configuration.
                try std.testing.expectError(error.InvalidProofConfig, codec.decode(a, changed, &self.admission));
                @memcpy(changed, bytes);
                // All diagnostic config fields are one-byte varints; the next
                // prefix is the commitment count. It cannot authorize growth.
                changed[codec.HEADER_BYTES + 6] = 127;
                try std.testing.expectError(error.InvalidProofShape, codec.decode(a, changed, &self.admission));
                for (0..2) |mode| {
                    var rejected = try codec.decode(a, bytes, &self.admission);
                    defer rejected.deinit();
                    if (mode == 0) {
                        rejected.key_id[0] ^= 1;
                        try std.testing.expectError(error.UntrustedBlake3ParentKey, @import("../blake3_native_parent_verifier.zig").verify(&rejected, &self.admission));
                    } else {
                        rejected.claims[0] = rejected.claims[0].add(f.QM31.one());
                        rejected.claims[1] = rejected.claims[1].sub(f.QM31.one());
                        try rejected.validate(&self.admission); // Cancellation alone still holds.
                        try std.testing.expectError(error.OodsNotMatching, @import("../blake3_native_parent_verifier.zig").verify(&rejected, &self.admission));
                    }
                    try std.testing.expect(rejected.proof == null);
                }
                owned.deinit();
                owned = try codec.decode(a, bytes, &self.admission);
                const reencoded = try codec.encode(a, &owned, &self.admission);
                defer a.free(reencoded);
                try std.testing.expectEqualSlices(u8, bytes, reencoded);
                std.debug.print("V2_BLAKE3_NATIVE_PARENT_CODEC wire_bytes={d} canonical_roundtrip=true\n", .{bytes.len});
                var verified = try @import("../blake3_native_parent_verifier.zig").verify(&owned, &self.admission);
                defer verified.deinit();
                try std.testing.expect(owned.proof == null);
                try std.testing.expectError(error.ConsumedBlake3ParentArtifact, owned.validate(&self.admission));
                try std.testing.expectEqualSlices(u8, &self.admission.expected_id, &verified.key_id);
                try std.testing.expectEqual(@as(usize, 4), verified.capture.commitments.len);
                try std.testing.expectEqual(@as(usize, 8), verified.capture.queries.raw.len);
                std.debug.print("V2_BLAKE3_NATIVE_PARENT_INDEPENDENT verified_capture_queries={d} artifact_consumed=true\n", .{verified.capture.queries.raw.len});
                return verified.channel;
            }
        };
        fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [F.Airs.len]u32) ![]f.Column {
            var columns: std.ArrayList(f.Column) = .empty;
            inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
            for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
            return columns.toOwnedSlice(a);
        }
    };
}
