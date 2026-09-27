//! Real-proof qualification of the complete native row assembler.
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const std = @import("std");
        const native = @import("blake3_native_parent_rows.zig");
        const protocol = @import("../blake3_native_parent_protocol.zig");
        const f = @import("blake3_proof_fixture.zig").ForBackend(Backend);
        const F = @import("blake3_native_parent_roster.zig").Roster;
        pub fn check(backing: std.mem.Allocator, prepared: *native.Prepared, context: protocol.Context) !void {
            var arena = std.heap.ArenaAllocator.init(backing);
            defer arena.deinit();
            const a = arena.allocator();
            var rows: @TypeOf(prepared.rows) = undefined;
            var logs: [18]u32 = undefined;
            inline for (F.Airs, 0..) |Air, i| {
                logs[i] = if (prepared.rows[i].len <= 1) 1 else std.math.log2_int_ceil(usize, prepared.rows[i].len);
                rows[i] = try f.padded(Air, a, prepared.rows[i], logs[i]);
                if (i >= 3 and i <= 5) for (rows[i]) |*row| {
                    row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = native.selectors;
                };
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
            const saved = prepared.fixed[2][0];
            defer prepared.fixed[2][0] = saved;
            prepared.fixed[2][0][8] = saved[8].add(f.M31.one());
            const false_pp = try preprocessing(a, prepared.fixed, logs);
            prepared.fixed[2][0] = saved;
            std.debug.print("V2_BLAKE3_NATIVE_PARENT start inputs={d} g_rows={d} scalar_rows={d} arithmetic_rows={d}\n", .{ prepared.input_count, prepared.rows[0].len, prepared.rows[12].len, prepared.rows[3].len + prepared.rows[4].len + prepared.rows[5].len });
            try @import("blake3_proof_gate_test_support.zig").ForBackend(Backend).runForParametersProtocol(F, a, rows, logs, trusted, false_pp, .{ .{}, .{}, .{}, native.selectors, native.selectors, native.selectors, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{} }, GateProtocol{ .admission = admitted }, void);
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
            pub fn verifyOwned(self: @This(), a: std.mem.Allocator, proof: @import("../blake3_engine_protocol.zig").Proof, claims: [20]f.QM31) !f.Channel {
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
        fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [18]u32) ![]f.Column {
            var columns: std.ArrayList(f.Column) = .empty;
            inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
            for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
            return columns.toOwnedSlice(a);
        }
    };
}
