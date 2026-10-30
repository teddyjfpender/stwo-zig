const std = @import("std");
const core = @import("stwo_core");
const P = @import("../block_v7_window_union_producer_v1.zig");
const Multi = @import("../block_v7_multi_union_proof_v1.zig").ForMode(true);
const Driver = @import("../block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const Codec = @import("../block_v7_multi_union_codec_v1.zig").ForMode(true);
const StatementWire = @import("../block_v7_multi_union_statement_wire_v1.zig").ForMode(true);
const ClaimWire = @import("../block_v7_union_claim_wire_v1.zig");
const BoundedWriter = @import("../bounded_artifact_writer_v1.zig").Writer;
fn claimDigest(a: std.mem.Allocator, claims: Multi.Claims) ![32]u8 {
    var writer = BoundedWriter.init(a, 8 << 20);
    defer writer.deinit();
    var remaining: usize = 1 << 18;
    try ClaimWire.encode(Multi.Claims, &writer, claims, &remaining);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(writer.bytes.items, &digest, .{});
    return digest;
}
const Consumer = struct {
    pub const Result = *P.Artifact;
    pub const limits: Multi.Limits = .{ .max_retained_pcs_bytes = 8 << 30 };
    pub const OracleConsumer = struct {
        pub const Result = struct { claims: [32]u8, verified: @import("../block_v7_execution_receiver_v1.zig").Verified };
        pub fn consume(f: Driver.Fixture) !OracleConsumer.Result {
            const natives = try f.allocator.alloc(Multi.NativeClaims, f.input.natives.len);
            defer f.allocator.free(natives);
            for (natives, f.input.natives) |*out, source| out.* = .{ .claims = source.proof.claims, .access = source.proof.memory_claims };
            const callers = try f.allocator.alloc(Multi.CallerClaims, f.input.active_callers.len);
            defer f.allocator.free(callers);
            for (callers, f.input.active_callers) |*out, source| out.* = .{ .arithmetic = source.proof.arithmetic, .relations = source.proof.relations };
            const memory = f.input.memory.window_joint.claims();
            const ram = try f.allocator.dupe(@TypeOf(memory.ram[0]), memory.ram);
            defer f.allocator.free(ram);
            const claims = Multi.Claims{ .native = natives, .callers = callers, .program = f.input.program.claim, .lookup = f.input.lookup.compact.proof.claims, .ram = ram, .interval = memory.interval, .range16 = memory.range16, .terminal = {} };
            return .{ .claims = try claimDigest(f.allocator, claims), .verified = f.original };
        }
    };
    pub fn compareOriginal(artifact: Result, oracle: OracleConsumer.Result) !void {
        try std.testing.expectEqualDeep(oracle.claims, try claimDigest(artifact.allocator, artifact.proof.claims));
        try std.testing.expectEqualDeep(oracle.verified, try artifact.verify(limits));
    }
    pub fn consumeStagedWindow(f: Driver.StagedWindowFixture) !Result {
        const artifact = try P.produce(f, .{ .limits = limits });
        errdefer artifact.deinit();
        try std.testing.expect(artifact.statement.trusted.elf.ptr != f.trusted.elf.ptr);
        try std.testing.expect(artifact.statement.trusted.window.? != f.trusted.window.?);
        try std.testing.expect(artifact.statement.input.natives[0].shape != f.natives[0].pin().shape);
        try std.testing.expectEqual(@as(usize, 2), artifact.statement.input.natives.len);
        try std.testing.expectEqual(@as(usize, if (artifact.statement.trusted.window.?.boundary.skip_cycles == 9) 0 else 1), artifact.statement.input.callers.len);
        return artifact;
    }
    pub fn discardStagedResult(value: Result) void {
        value.deinit();
    }
    pub fn verifyAfterProducersDestroyedWithExternal(artifact: Result, external: @import("../block_v7_window_union_loader_v1.zig").External) !void {
        const Recursive = @import("block_v7_union_recursive_support.zig");
        var recursive: ?Recursive.Evidence = null;
        defer if (recursive) |*root| root.deinit();
        const good = try artifact.verify(limits);
        try std.testing.expectEqual(.declared_window, good.scope);
        try std.testing.expectEqual(@as(u64, external.trusted.window.cycles), good.cycles);
        {
            const Profile = @import("../../recursion/block_v7_union_fixed_profile_v1.zig").ForMode(true);
            const profile = try Profile.Owned.derive(artifact.allocator, artifact.statement, &artifact.proof.claims, .{ .original = limits });
            defer profile.deinit();
            try std.testing.expect(profile.trace_count > 5);
            try std.testing.expectEqualDeep(profile.fixed_root, artifact.proof.stark.commitment_scheme_proof.commitments.items[0]);
            try profile.validateAgainst(&artifact.proof.claims);
            const view = artifact.proof.view();
            var captured = try Multi.verifyViewAndCapture(artifact.allocator, artifact.statement.trusted, artifact.statement.input, &view, limits);
            defer captured.deinit();
            try std.testing.expectEqualDeep(good, captured.closed);
            var deep = try @import("../../recursion/pcs_arithmetic_capture.zig").Owned.init(artifact.allocator, profile.shape.deepProfile(), &captured.proof);
            defer deep.deinit();
            const Transcript = @import("../../recursion/air/block_v7_union_transcript_v1.zig");
            var transcript = Transcript.replay(artifact.allocator, profile, &captured, 4) catch |err| {
                std.debug.print("UNION_RECURSION_GATE stage=union transcript replay error={}\n", .{err});
                return err;
            };
            defer transcript.deinit();
            var fixed_transcript = Transcript.fixed(artifact.allocator, profile, &captured.claims, 4, .{}) catch |err| {
                std.debug.print("UNION_RECURSION_GATE stage=union fixed transcript error={}\n", .{err});
                return err;
            };
            defer fixed_transcript.deinit();
            try std.testing.expectEqualDeep(fixed_transcript.id, transcript.plan.id);
            var pcs = @import("../../recursion/block_v7_union_pcs_preparation_v1.zig").prepare(artifact.allocator, profile, &captured, &transcript) catch |err| {
                std.debug.print("UNION_RECURSION_GATE stage=union PCS preparation error={}\n", .{err});
                return err;
            };
            defer pcs.deinit();
            var composition = try @import("../../recursion/air/block_v7_union_composition_v1.zig").prepare(artifact.allocator, profile, &captured);
            defer composition.deinit();
            {
                const Public = @import("../../recursion/block_v7_union_public_v1.zig");
                var values = try Public.reconstruct(artifact.allocator, profile, &captured.claims);
                defer values.deinit();
                const wires = try Public.collect(artifact.allocator, profile, &captured, &composition, &transcript, values, 1 << 20);
                defer artifact.allocator.free(wires);
                try std.testing.expect(wires.len > 0);
                if (std.process.hasEnvVarConstant("STWO_V7_UNION_RECURSIVE_TEST")) {
                    recursive = try Recursive.produce(artifact.allocator, profile, &captured);
                } else {
                    const UnionPreparation = @import("../../recursion/block_v7_union_preparation_v1.zig");
                    var prepared = try UnionPreparation.prepare(artifact.allocator, profile, &captured, 4, .{});
                    defer prepared.deinit();
                    try std.testing.expectEqualDeep(transcript.plan.id, prepared.recursive.context.transcript_plan_id);
                    var cold = try @import("../../recursion/block_v7_union_fixed_roster_v1.zig").Owned.derive(artifact.allocator, profile, &captured.claims, 4, .{});
                    defer cold.deinit();
                    try cold.validateLive(&prepared);
                }
            }
            const seal = profile.seal;
            profile.seal[0] ^= 1;
            try std.testing.expectError(error.MutatedUnionFixedProfile, profile.validateAgainst(&captured.claims));
            profile.seal = seal;
        }
        const saved = artifact.proof.claims.ram[0];
        artifact.proof.claims.ram[0].sums[29] = saved.sums[29].add(core.fields.qm31.QM31.one());
        artifact.proof.claims.ram[0].sums[30] = saved.sums[30].sub(core.fields.qm31.QM31.one());
        if (artifact.verify(limits)) |_| return error.AcceptedForgedWindowUnionClaims else |err| {
            try std.testing.expect(err == error.OodsNotMatching or err == error.ConstraintsNotSatisfied);
        }
        artifact.proof.claims.ram[0] = saved;
        const terminal_scope = @import("../block_v7_multi_union_scope_v1.zig");
        // The legacy terminal scope must not reinterpret a window epoch.
        const i = artifact.statement.input;
        const terminal_input = terminal_scope.Input{ .epoch = i.epoch, .entries = i.entries, .natives = i.natives, .callers = i.callers, .program_plan = i.program_plan, .program_roots = i.program_roots, .lookup_plan = i.lookup_plan, .lookup_layout = i.lookup_layout, .lookup_roots = i.lookup_roots, .memory_roots = i.memory_roots, .memory_geometry = i.memory_geometry, .interval_log = i.interval_log };
        try std.testing.expectError(error.InvalidMultiUnionTheorem, terminal_scope.Owned.init(artifact.allocator, artifact.statement.trusted, terminal_input, .{ .max_retained_pcs_bytes = 8 << 30 }));
        const wire_limits = Codec.Limits{ .scope = limits };
        const metadata = try StatementWire.encode(artifact.allocator, artifact.statement, .{});
        defer artifact.allocator.free(metadata);
        const detached = try StatementWire.decode(artifact.allocator, metadata, artifact.statement.trusted, .{});
        defer detached.deinit();
        try std.testing.expect(detached.input.natives[0].shape != i.natives[0].shape);
        try std.testing.expect(detached.trusted.window.? != artifact.statement.trusted.window.?);
        try std.testing.expectError(error.UnionMetadataSizeLimit, StatementWire.decode(artifact.allocator, metadata, artifact.statement.trusted, .{ .bytes = 1 }));
        const bytes = try Codec.encode(artifact.allocator, artifact.proof.view(), i, wire_limits);
        defer artifact.allocator.free(bytes);
        // A fresh byte receiver must carry the theorem with no producer proof,
        // trace owners, or checkpoint files left alive.
        artifact.releaseProof();
        // The original STARK, verifier capture, live rows and producer plans
        // have all been destroyed before this detached recursive receiver.
        if (recursive) |*root| try root.verify(detached);
        const decoded = try Codec.verifyBytes(artifact.allocator, bytes, detached.trusted, detached.input, wire_limits);
        try std.testing.expectEqualDeep(good, decoded);
        const Loader = @import("../block_v7_window_union_loader_v1.zig");
        const loaded = try Loader.verify(artifact.allocator, bytes, metadata, external, .{ .wire = wire_limits });
        try std.testing.expectEqualDeep(good, loaded);
        var wrong = external;
        wrong.trusted.outgoing_sha256[0] ^= 1;
        try std.testing.expectError(error.UntrustedV7WindowState, Loader.verify(artifact.allocator, bytes, metadata, wrong, .{ .wire = wire_limits }));
        bytes[0] ^= 1;
        try std.testing.expectError(error.UntrustedMultiUnionEnvelope, Codec.verifyBytes(artifact.allocator, bytes, artifact.statement.trusted, i, wire_limits));
        bytes[0] ^= 1;
        if (Codec.verifyBytes(artifact.allocator, bytes[0 .. bytes.len - 1], artifact.statement.trusted, i, wire_limits)) |_| return error.AcceptedTruncatedWindowUnion else |_| {}
        const claim_bytes = std.mem.readInt(u32, bytes[Codec.HEADER_BYTES - 12 ..][0..4], .little);
        const last_claim_byte = Codec.HEADER_BYTES + claim_bytes - 1;
        bytes[last_claim_byte] ^= 1;
        if (Codec.verifyBytes(artifact.allocator, bytes, artifact.statement.trusted, i, wire_limits)) |_| return error.AcceptedTamperedWindowUnionClaims else |_| {}
        bytes[last_claim_byte] ^= 1;
    }
};
test "window union proves genuine native Keccak ROM lookup and state delta in one STARK" {
    try @import("../block_v7_real_window_execution_test_support_v2.zig").runTiny(Consumer);
}
test "sparse window union preserves the complete independently selected endpoints" {
    try @import("../block_v7_real_window_execution_test_support_v2.zig").runTinyWithSparse(Consumer, true);
}
test "native RAM window union records the single shared original composition" {
    try @import("../block_v7_real_window_execution_test_support_v2.zig").runNativeTail(Consumer);
}
