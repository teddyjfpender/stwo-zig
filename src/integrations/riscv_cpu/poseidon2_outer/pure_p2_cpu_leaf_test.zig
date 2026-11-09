//! Actual source CPU proof, checked local child and pure-P2 verifier graph.
//! Physical qualification is explicit opt-in while execution admission is closed.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Public = @import("full_p2_frame.zig");
const Full = @import("pure_p2_cpu_statement.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const Native = @import("pure_p2_native.zig");
const Manifest = @import("pure_p2_manifest.zig");
const Phase = @import("phase_census.zig");
pub const CompleteCounts = struct { proof_inputs: Phase.Counts = .{}, statement: Phase.Parts = .{}, frame: Phase.Counts = .{}, finalization: Phase.Counts = .{} };
pub const ShapeView = struct {
    op_span: ?@import("../word16_global_execution/services/types.zig").OpTowerSpan = null,
    setup: *const @import("../word16_global_execution/services/roster.zig").CpuSetup,
    request: @import("../word16_global_execution/services/protocol.zig").Request,
    first: [@import("../word16_global_execution/services/types.zig").FAMILIES]u32,
    expected: Manifest.Expected,
    key: *const @import("pure_p2_fixed_key.zig").Key,
    manifest: Native.Digest,
    main: Native.Digest,
    receipt: Native.Digest,
    claims: []const C.O,
    child: *const @import("stwo_prover_engine").lookups.gkr_verifier.ForField(C.O).GkrBatchProof,
    shape: *const V.Shape,
    values: *const V.Captured,
    pub fn expectedOutput(self: @This(), a: std.mem.Allocator) ![9]C.Q {
        const words = if (self.op_span) |span| try Full.expectedWordsForOp(a, self.setup, self.request, self.first, span, self.expected, self.manifest, self.main, self.receipt, self.claims) else try Full.expectedWords(a, self.setup, self.request, self.first, self.expected, self.manifest, self.main, self.receipt, self.claims);
        defer a.free(words);
        var outputs: [9]C.Q = undefined;
        for (&outputs, try core.crypto.poseidon2_m31_sponge.decode(Native.hashWords(words))) |*output, value| output.* = C.Q.fromBase(value);
        return outputs;
    }
    pub fn build(self: @This(), a: std.mem.Allocator, trace_only: bool, census: ?*CompleteCounts) !C.PoseidonContext {
        var structural = @import("../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var owner = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
        errdefer owner.deinit();
        C.begin(&owner);
        var active = true;
        defer if (active) C.finish() catch {};
        const ctx = owner.algebra();
        const before_proof = Phase.Counts.take(&owner);
        const proof = try V.proof.guess(ctx, self.values, self.shape);
        const after_proof = Phase.Counts.take(&owner);
        var frame = Public.Frame.init(ctx);
        const physical = Full.Physical{ .fixed = proof.commitments[0], .main = proof.commitments[1], .fixed_source = self.key.root };
        const binding = @import("pure_p2_worker_circuit.zig").Binding{ .identity = self.key.identity, .root = self.key.root, .profile = self.key.profile };
        var statement = if (self.op_span) |span| try Full.Statement.initForOp(&frame, self.setup, self.request, self.first, span, self.expected, self.manifest, self.claims, physical, self.child, self.key.profile.config(), binding) else try Full.Statement.init(&frame, self.setup, self.request, self.first, self.expected, self.manifest, self.claims, physical, self.child, self.key.profile.config(), binding);
        defer statement.deinit(ctx);
        _ = try V.verify(ctx, self.shape, &proof, &statement);
        const before_frame = Phase.Counts.take(&owner);
        const output = try frame.finish();
        if (census) |counts| counts.* = .{ .proof_inputs = after_proof.sub(before_proof), .statement = statement.phase, .frame = Phase.Counts.take(&owner).sub(before_frame) };
        if (!trace_only) for (output, try self.expectedOutput(a)) |port, value| try std.testing.expect(ctx.get(port).eql(value));
        try C.finish();
        active = false;
        const before_finalization = Phase.Counts.take(&owner);
        try owner.setOutputs(&output);
        try owner.finalize();
        if (census) |counts| counts.finalization = Phase.Counts.take(&owner).sub(before_finalization);
        if (!trace_only) {
            try std.testing.expect(try owner.isCircuitValid());
            const mutants = [_]C.Var{ proof.sampled_values[1][0][0].c0.v, statement.pending.artifact.claims_to_verify_by_instance[0][0].c0.v, output[8] };
            for (mutants) |port| {
                const old = ctx.get(port);
                ctx.value_table.items[port.idx] = old.add(C.Q.one());
                const accepted = try owner.isCircuitValid();
                ctx.value_table.items[port.idx] = old;
                try std.testing.expect(!accepted);
            }
        }
        try std.testing.expectEqual(@as(usize, 0), ctx.circuit.blake_g_gate.items.len);
        try std.testing.expectEqual(@as(usize, 0), ctx.circuit.triple_xor.items.len);
        return owner;
    }
};
fn physicalRequested() !bool {
    const value = std.posix.getenv("STWO_OP_P2_FULL_CPU_PHYSICAL") orelse return false;
    if (value.len == 0 or std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidOpP2PhysicalGateSelection;
}
/// Takes ownership of `produced` even on failure; releases producer context
/// before independently reconstructing and checking receiver source authority.
pub fn proveSourcePhysical(a: std.mem.Allocator, source: ShapeView, produced: C.PoseidonContext, build_ns: u64, prefix: []const u8) !void {
    var owner = produced;
    var owns_owner = true;
    defer if (owns_owner) owner.deinit();
    var timer = try std.time.Timer.start();
    const Authority = @import("authority.zig").Authority;
    const Proof = @import("proof.zig");
    const outputs = try source.expectedOutput(a);
    var identity: [32]u8 = undefined;
    var recorder = @import("stwo_prover_engine").stage_profile.Recorder.initWithOptions(a, "cpu", "op_pure_p2_actual_cpu_leaf", .{ .capture_tasks = false, .capture_process_usage = true });
    defer recorder.deinit();
    const outer = blk: {
        var key = try Authority.initForProfile(a, &owner, source.key.profile);
        defer key.deinit();
        identity = key.identity;
        break :blk try Proof.proveProfiled(a, &owner, &key, &outputs, &recorder);
    };
    defer a.free(outer);
    owner.deinit();
    owns_owner = false;
    const prove_ns = timer.lap();
    var receiver_source = try source.build(a, true, null);
    defer receiver_source.deinit();
    var receiver = try Authority.initForProfile(a, &receiver_source, source.key.profile);
    defer receiver.deinit();
    try std.testing.expectEqualSlices(u8, &identity, &receiver.identity);
    try Proof.verify(a, &receiver, &outputs, outer);
    const receive_ns = timer.lap();
    var wrong = outputs;
    wrong[8] = wrong[8].add(C.Q.one());
    try std.testing.expectError(error.PoseidonGlobalLookupSum, Proof.verify(a, &receiver, &wrong, outer));
    const corrupted = try a.dupe(u8, outer);
    defer a.free(corrupted);
    corrupted[40] ^= 1;
    try std.testing.expectError(error.PoseidonGlobalLookupSum, Proof.verify(a, &receiver, &outputs, corrupted));
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(outer, &hash, .{});
    var profile = try recorder.snapshot(a);
    defer profile.deinit(a);
    const profile_json = try std.json.Stringify.valueAlloc(a, profile, .{});
    defer a.free(profile_json);
    std.debug.print("{s}_STAGES {s}\n", .{ prefix, profile_json });
    std.debug.print("{s}_PHYSICAL bytes={} build_ns={} prove_ns={} fresh_receive_ns={} sha256={s} production_admission_open=false\n", .{ prefix, outer.len, build_ns, prove_ns, receive_ns, std.fmt.bytesToHex(hash, .lower) });
}
const Hook = struct {
    pub fn run(a: std.mem.Allocator, setups: anytype, requests: anytype, keys: anytype, inventory: anytype, pending: anytype, encoded: anytype, capture: anytype, stages: anytype) !void {
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded[0].bytes);
        defer native.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometry(arena.allocator(), setups[0], keys[0].profile.config());
        const values = try V.proof.fromNative(arena.allocator(), &native, capture, &shape);
        const source = ShapeView{ .setup = setups[0], .request = requests[0], .first = inventory.first_ids[0], .expected = inventory.workers[0], .key = &keys[0], .manifest = pending.digest, .main = native.commitment_scheme_proof.commitments.items[1], .receipt = stages[0].local.?.receipt, .claims = encoded[0].claims, .child = stages[0].local.?.proof, .shape = &shape, .values = &values };
        const physical = try physicalRequested();
        var timer = try std.time.Timer.start();
        var phases: CompleteCounts = .{};
        var owner = try source.build(a, false, &phases);
        var owns_owner = true;
        defer if (owns_owner) owner.deinit();
        const build_ns = timer.lap();
        const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "actualCPU_source_AIR_OODS_masks_terminal_PCS_GKR_FS_publicframe", .arithmetic_mode = "immutable_structural_v1", .phases = phases, .raw = try owner.rawCounts(), .cells = try owner.census(false), .permutations = owner.calls.items.len, .variables = owner.algebra().circuit.n_vars, .native_assignment_exact = true, .production_admission_open = false, .recursive_execution_acceptance = false }, .{});
        defer a.free(json);
        std.debug.print("OP_PURE_P2_COMPLETE_CPU_CIRCUIT {s}\n", .{json});
        if (!physical) return;
        owns_owner = false;
        try proveSourcePhysical(a, source, owner, build_ns, "OP_PURE_P2_COMPLETE_CPU");
    }
};
test "OP pure P2 complete CPU circuit matches actual native proof and expected public frame" {
    try @import("pure_p2_cpu_fixture.zig").exercise(Hook);
}
