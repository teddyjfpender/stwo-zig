//! Source-derived complete recursive proof of opt-in truth-local GKR+P2.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Frame = @import("../full_p2_frame.zig");
const Full = @import("statement.zig");
const Native = @import("worker.zig");
const Local = @import("native.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
pub const View = struct {
    key: *const Native.Key,
    span: Native.Span,
    expected: Manifest.Expected,
    manifest: [36]u8,
    main: [36]u8,
    receipt: [36]u8,
    claims: [2]C.O,
    local: *const @import("stwo_prover_engine").lookups.gkr_verifier.ForField(C.O).GkrBatchProof,
    shape: *const V.Shape,
    values: *const V.Captured,
    pub fn expectedOutput(self: View, a: std.mem.Allocator) ![9]C.Q {
        const words = try Full.expectedWords(a, self.key, self.span, self.expected, self.manifest, self.main, self.receipt, self.claims);
        defer a.free(words);
        const hash = @import("../pure_p2_native.zig").hashWords(words);
        var out: [9]C.Q = undefined;
        for (&out, try core.crypto.poseidon2_m31_sponge.decode(hash)) |*wire, value| wire.* = C.Q.fromBase(value);
        return out;
    }
    pub fn build(self: View, a: std.mem.Allocator, trace_only: bool) !C.PoseidonContext {
        return self.buildMode(a, trace_only, true);
    }
    pub fn buildForProving(self: View, a: std.mem.Allocator) !C.PoseidonContext {
        return self.buildMode(a, false, false);
    }
    fn buildMode(self: View, a: std.mem.Allocator, trace_only: bool, diagnostics: bool) !C.PoseidonContext {
        var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var owner = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
        errdefer owner.deinit();
        C.begin(&owner);
        var active = true;
        defer if (active) C.finish() catch {};
        const ctx = owner.algebra();
        const proof = try V.proof.guess(ctx, self.values, self.shape);
        var frame = Frame.Frame.init(ctx);
        var statement = try Full.Statement.init(&frame, self.key, self.span, self.expected, self.manifest, self.receipt, self.claims, .{ .fixed = proof.commitments[0], .main = proof.commitments[1] }, self.local);
        defer statement.deinit(ctx);
        _ = try V.verify(ctx, self.shape, &proof, &statement);
        const output = try frame.finish();
        if (!trace_only) for (output, try self.expectedOutput(a)) |wire, want| try std.testing.expect(ctx.get(wire).eql(want));
        try C.finish();
        active = false;
        try owner.setOutputs(&output);
        try owner.finalize();
        if (!trace_only and diagnostics) {
            try std.testing.expect(try owner.isCircuitValid());
            for ([_]C.Var{ statement.pending.artifact.claims_to_verify_by_instance[0][0].c0.v, proof.sampled_values[1][0][0].c0.v, statement.claims[0].c0.v, output[8] }) |port| {
                const old = ctx.get(port);
                ctx.value_table.items[port.idx] = old.add(C.Q.one());
                const accepted = try owner.isCircuitValid();
                ctx.value_table.items[port.idx] = old;
                try std.testing.expect(!accepted);
            }
        }
        return owner;
    }
};

const Hook = struct {
    pub fn run(a: std.mem.Allocator, key: *const Native.Key, span: Native.Span, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Native.Encoded, capture: anytype) !void {
        var proof = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        var local = try Local.decode(a, try key.geometry(span), encoded.local);
        defer local.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try Full.geometry(arena.allocator(), key, span);
        const values = try V.proof.fromNative(arena.allocator(), &proof, capture, &shape);
        const view = View{ .key = key, .span = span, .expected = expected, .manifest = pending.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .receipt = encoded.receipt, .claims = encoded.claims, .local = &local.proof, .shape = &shape, .values = &values };
        var scope = @import("../native_omul/scope.zig").begin();
        defer scope.deinit();
        var owner = try view.build(a, false);
        defer owner.deinit();
        std.debug.print("OP_MILLER_GKR_RECURSION raw={any} cells={any} native_om={d} p2={d} frame9=true source_terminal=true physical_pcs=true global_wire_pending=true\n", .{ try owner.rawCounts(), try owner.census(false), owner.native_mul_calls.items.len, owner.calls.items.len });
        const out = std.posix.getenv("STWO_OP_MILLER_R6_OUT") orelse return;
        try std.fs.cwd().makeDir(out);
        var dir = try std.fs.cwd().openDir(out, .{});
        defer dir.close();
        const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
        const envelope = try Native.encode(a, encoded);
        defer a.free(envelope);
        try write(dir, "native-envelope.bin", envelope);
        const Authority = @import("../native_omul/authority.zig").Key;
        const Proof = @import("../native_omul/proof.zig");
        var source_trace = try view.build(a, true);
        defer source_trace.deinit();
        var authority = try Authority.init(a, &source_trace, key.base.profile);
        defer authority.deinit();
        const output = try view.expectedOutput(a);
        var recorder = @import("stwo_prover_engine").stage_profile.Recorder.initWithOptions(a, "cpu", "op_miller_gkr_r6_leaf", .{ .capture_tasks = false, .capture_process_usage = true });
        defer recorder.deinit();
        const bytes = try Proof.proveProfiled(a, &owner, &authority, &output, &recorder);
        defer a.free(bytes);
        try write(dir, "leaf.bin", bytes);
        var stages = try recorder.snapshot(a);
        defer stages.deinit(a);
        const stage_bytes = try std.json.Stringify.valueAlloc(a, stages, .{});
        defer a.free(stage_bytes);
        try write(dir, "stages.json", stage_bytes);
        // Artifacts are durable before constructing an independent source key.
        var fresh_trace = try view.build(a, true);
        defer fresh_trace.deinit();
        var fresh = try Authority.init(a, &fresh_trace, key.base.profile);
        defer fresh.deinit();
        @import("../native_omul/verifier_key.zig").retireProverData(&fresh);
        try std.testing.expectEqualSlices(u8, &authority.base.identity, &fresh.base.identity);
        try Proof.verify(a, &fresh, &output, bytes);
        var wrong = output;
        wrong[8] = wrong[8].add(C.Q.one());
        try std.testing.expect(std.meta.isError(Proof.verify(a, &fresh, &wrong, bytes)));
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        const receipt = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-miller-local-gkr-r6-physical-v1", .calls = span.calls, .frontier_log = key.base.frontier_log, .arithmetic_log = key.base.arithmetic_log, .bytes = bytes.len, .sha256 = std.fmt.bytesToHex(digest, .lower), .source_identity = std.fmt.bytesToHex(fresh.base.identity, .lower), .raw = try owner.rawCounts(), .native_om_calls = owner.native_mul_calls.items.len, .mul_rows = fresh.mul_rows, .fresh_source = true, .ninth_word_mutation_rejected = true, .execution_accepted = false, .production_admission = false }, .{});
        defer a.free(receipt);
        try write(dir, "receipt.json", receipt);
        try std.posix.fsync(dir.fd);
        std.debug.print("OP_MILLER_GKR_R6_PHYSICAL {s}\n", .{receipt});
    }
};
test "Miller local GKR complete recursive source statement and mutations" {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 8 << 30);
    defer budget.destroy();
    try Native.runWithHook(budget.allocator(), Hook);
}
