//! Nonproving caller capture custody/admission. Malformed proof objects are
//! rejected before any commitment or core verifier; none are accepted captures.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Family = @import("../block_v5_precompile_family_proof_v1.zig");
const Fused = @import("../block_v5_caller_fused_proof_v1.zig");
const Composite = @import("../block_v5_composite_pcs_v1.zig");
const Combined = @import("../block_v5_caller_verified_capture_v1.zig");
const Receiver = @import("../block_v5_caller_fused_receiver_v1.zig");
const Protocol = @import("../block_v5_precompile_protocol_v1.zig");
const Profile = @import("../blake3_ethereum_sha_profile.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Schedule = @import("../block_v5_caller_fused_schedule_v1.zig").Schedule;
const Frame = @import("../../air/block/memory_event.zig").Frame;
const TreeVec = core.pcs.TreeVec;
const config = @import("../../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
fn malformed(a: std.mem.Allocator) !suite.Proof {
    const roots = try a.dupe(suite.Hasher.Hash, &.{@splat(77)});
    errdefer a.free(roots);
    const samples = try a.alloc([][]Q, 0);
    errdefer a.free(samples);
    const queries = try a.alloc([][]M, 0);
    errdefer a.free(queries);
    const paths = try a.alloc(core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher), 0);
    errdefer a.free(paths);
    const fri = try a.dupe(Q, &.{Q.one()});
    errdefer a.free(fri);
    const hashes = try a.dupe(suite.Hasher.Hash, &.{@splat(78)});
    errdefer a.free(hashes);
    const layers = try a.alloc(core.fri.FriLayerProof(suite.Hasher), 0);
    errdefer a.free(layers);
    const last = try a.dupe(Q, &.{Q.one()});
    return .{ .commitment_scheme_proof = .{ .config = config, .commitments = TreeVec(suite.Hasher.Hash).initOwned(roots), .sampled_values = TreeVec([][]Q).initOwned(samples), .queried_values = TreeVec([][]M).initOwned(queries), .decommitments = TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher)).initOwned(paths), .proof_of_work = 0, .fri_proof = .{ .first_layer = .{ .fri_witness = fri, .decommitment = .{ .hash_witness = hashes }, .commitment = @splat(79) }, .inner_layers = layers, .last_layer_poly = core.poly.line.LinePoly.initOwned(last) } } };
}
fn digest(proof: *const suite.Proof) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    const p = &proof.commitment_scheme_proof;
    hash.update(std.mem.sliceAsBytes(p.commitments.items));
    for (p.sampled_values.items) |tree| for (tree) |values| hash.update(std.mem.sliceAsBytes(values));
    for (p.queried_values.items) |tree| for (tree) |values| hash.update(std.mem.sliceAsBytes(values));
    for (p.decommitments.items) |path| hash.update(std.mem.sliceAsBytes(path.hash_witness));
    hash.update(std.mem.sliceAsBytes(p.fri_proof.first_layer.fri_witness));
    hash.update(std.mem.sliceAsBytes(p.fri_proof.first_layer.decommitment.hash_witness));
    hash.update(std.mem.sliceAsBytes(p.fri_proof.last_layer_poly.coefficients()));
    return hash.finalResult();
}
fn smallClaims(a: std.mem.Allocator) !Fused.ClaimFrames {
    const program = try a.dupe(@import("../block_v5_program_extension_proof_v1.zig").Claim, &.{.{ .sum = Q.one(), .fetch_count = 2 }});
    errdefer a.free(program);
    const state = try a.dupe(@import("../block_v5_program_extension_proof_v1.zig").Claim, &.{.{ .sum = Q.fromU32Unchecked(2, 3, 4, 5), .fetch_count = 2 }});
    errdefer a.free(state);
    const tables = try a.dupe(@import("../block_v5_precompile_lookup_algebra_v1.zig").Claim, &.{.{ .sum = Q.one(), .row_count = 3 }});
    errdefer a.free(tables);
    const memory = try a.dupe(@import("../block_v5_external_memory_sidecar_proof_v1.zig").Claim, &.{.{ .transition_sum = Q.one(), .universal_sum = Q.one(), .range_claims = @splat(Q.one()), .active_count = 4 }});
    return .{ .program_claims = program, .state_claims = state, .table_claims = tables, .memory_claims = memory };
}
fn cloneCase(a: std.mem.Allocator, source: *const Fused.ClaimFrames) !void {
    var cloned = try Fused.ClaimFrames.clone(a, source);
    defer cloned.deinit(a);
    try std.testing.expect(cloned.program_claims.ptr != source.program_claims.ptr);
    try std.testing.expect(cloned.state_claims.ptr != source.state_claims.ptr);
    try std.testing.expect(cloned.table_claims.ptr != source.table_claims.ptr);
    try std.testing.expect(cloned.memory_claims.ptr != source.memory_claims.ptr);
    cloned.program_claims[0].sum = Q.zero();
    cloned.state_claims[0].fetch_count += 1;
    cloned.table_claims[0].row_count += 1;
    cloned.memory_claims[0].range_claims[0] = Q.zero();
    try std.testing.expect(source.program_claims[0].sum.eql(Q.one()));
    try std.testing.expectEqual(@as(u64, 2), source.state_claims[0].fetch_count);
    try std.testing.expectEqual(@as(u64, 3), source.table_claims[0].row_count);
    try std.testing.expect(source.memory_claims[0].range_claims[0].eql(Q.one()));
}
test "caller capture: four claim arrays copy independently and release every allocation failure" {
    var source = try smallClaims(std.testing.allocator);
    defer source.deinit(std.testing.allocator);
    try cloneCase(std.testing.allocator, &source);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneCase, .{&source});
}
pub const Fixture = struct {
    statement: Profile.admission.Statement,
    binding: Protocol.CallerBinding,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    entries: [8]Seal.Entry,
    frame: Frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1 << 40, .cycle_count = 1 },
    witness: [32]u8 = @splat(91),
    rw: u64,
    pub fn init(a: std.mem.Allocator) !Fixture {
        return initWithKeccak(a, 0);
    }
    pub fn initWithKeccak(a: std.mem.Allocator, keccak_calls: u32) !Fixture {
        const steps = try std.math.add(u32, keccak_calls, 1);
        // Derive the empty signer recipe from its original producer. Padding
        // one physical row does not authorize one logical signer call.
        var extension = try @import("../guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, &.{}, &.{}, &.{}, &.{}, steps, Protocol.circuit_profile);
        defer extension.deinit();
        const shapes = extension.shapes();
        var self: Fixture = undefined;
        self.frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1 << 40, .cycle_count = steps };
        self.witness = @splat(91);
        self.statement = try @import("../block_v5_precompile_witness_v1.zig").canonicalStatement(a, keccak_calls, 0, 1, shapes);
        const key = try Protocol.keyId(&self.statement, steps, config, @splat(21));
        self.binding = .{ .execution_index = 0, .caller_entry_index = 0, .execution_instance_id = @splat(20), .caller_key_id = key, .caller_instance_id = Protocol.instanceId(key, @splat(20), 0, .{ @splat(21), @splat(22) }), .first_roots = .{ @splat(21), @splat(22) }, .sealed_digest = @splat(0) };
        const mode: u32 = if (Protocol.execution_recipe == .local_zero_v1) 1 else 0;
        var schedule = try Schedule.init(a, &self.statement, steps, self.frame, mode);
        defer schedule.deinit();
        self.rw = schedule.rw_events;
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = self.binding.execution_instance_id, .roots = .{ @splat(13), @splat(14) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
            .{ .family = .precompile, .index = 0, .instance_id = self.binding.caller_instance_id, .roots = self.binding.first_roots },
            Fused.entry(self.binding, self.witness, self.frame, mode, &schedule),
            @import("../block_v5_external_memory_sidecar_proof_v1.zig").packedEntry(self.binding.execution_instance_id, self.binding.caller_instance_id, self.binding.caller_key_id, self.binding.first_roots, self.witness, 0, schedule.memory),
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        self.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = mode, .config = config, .counts = counts };
        self.sealed = try Seal.seal(self.pins, &self.entries);
        self.binding.sealed_digest = self.sealed.digest;
        return self;
    }
    pub fn pin(self: *const Fixture) Combined.Pin {
        return .{ .statement = &self.statement, .total_steps = self.frame.cycle_count, .execution_instance_id = self.binding.execution_instance_id, .expected_key_id = self.binding.caller_key_id, .expected_caller_instance_id = self.binding.caller_instance_id, .roots = self.binding.first_roots, .witness_root = self.witness, .frame = self.frame, .expected_rw_events = self.rw };
    }
};
fn rejectFamily(a: std.mem.Allocator, proof: *const Family.Proof, fixture: *const Fixture) !void {
    const before = digest(&proof.stark);
    const outcome = Family.ForBackend(Cpu).verifyCaptureBorrowed(a, proof, &fixture.statement, 1, fixture.binding.caller_key_id, fixture.binding.execution_instance_id, 0, fixture.sealed, fixture.pins, &fixture.entries);
    try std.testing.expectEqualDeep(before, digest(&proof.stark));
    if (outcome) |captured| {
        var unexpected = captured;
        unexpected.deinit();
        return error.AcceptedMalformedCallerCapture;
    } else |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(error.InvalidBlockV5PrecompileProofShape, err);
    }
}
test "caller capture: arithmetic borrowed early rejection preserves source and owned rejection consumes it" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var proof = Family.Proof{ .stark = try malformed(a), .claims = try Profile.ExtensionClaim.zeroForStatement(&fixture.statement), .key_id = fixture.binding.caller_key_id, .instance_id = fixture.binding.caller_instance_id };
    defer proof.deinit(a);
    try rejectFamily(a, &proof, &fixture);
    try rejectFamily(a, &proof, &fixture);
    try std.testing.checkAllAllocationFailures(a, rejectFamily, .{ &proof, &fixture });
    const owned = Family.Proof{ .stark = try malformed(a), .claims = proof.claims, .key_id = proof.key_id, .instance_id = proof.instance_id };
    try std.testing.expectError(error.InvalidBlockV5PrecompileProofShape, Family.ForBackend(Cpu).verifyCaptureOwned(a, owned, &fixture.statement, 1, fixture.binding.caller_key_id, fixture.binding.execution_instance_id, 0, fixture.sealed, fixture.pins, &fixture.entries));
}
test "caller capture: shared composite root rejection preserves borrowed arrays and frees owned vectors" {
    const a = std.testing.allocator;
    var proof = try malformed(a);
    defer proof.deinit(a);
    const before = digest(&proof);
    var channel = suite.Channel{};
    const initial = channel;
    try std.testing.expectError(error.UntrustedV5CompositeRoots, Composite.verifyCaptureBorrowed(a, &proof, .{ @splat(1), @splat(2), @splat(3) }, config, &.{1}, &.{1}, &.{1}, &.{1}, &.{}, .{}, &channel));
    try std.testing.expectEqualDeep(before, digest(&proof));
    try std.testing.expectEqualDeep(initial, channel);
    try std.testing.expectError(error.UntrustedV5CompositeRoots, Composite.verifyCaptureOwned(a, try malformed(a), .{ @splat(1), @splat(2), @splat(3) }, config, &.{1}, &.{1}, &.{1}, &.{1}, &.{}, .{}, &channel));
}
test "caller capture: combined independent census rejection never retains either input proof" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var caller = Family.Proof{ .stark = try malformed(a), .claims = try Profile.ExtensionClaim.zeroForStatement(&fixture.statement), .key_id = fixture.binding.caller_key_id, .instance_id = fixture.binding.caller_instance_id };
    defer caller.deinit(a);
    var frames = try smallClaims(a);
    var owns_frames = true;
    errdefer if (owns_frames) frames.deinit(a);
    var fused = Fused.Proof{ .stark = try malformed(a), .program_claims = frames.program_claims, .state_claims = frames.state_claims, .table_claims = frames.table_claims, .memory_claims = frames.memory_claims };
    owns_frames = false; // real owned transfer into the rejected proof envelope
    defer fused.deinit(a);
    var wrong = fixture.pin();
    wrong.expected_rw_events += 1;
    const before = .{ digest(&caller.stark), digest(&fused.stark), fused.memory_claims[0] };
    try std.testing.expectError(error.UntrustedV5CallerCompositeEventCensus, Combined.ForBackend(Cpu).verifyBorrowed(a, &caller, &fused, 0, wrong, fixture.sealed, fixture.pins, &fixture.entries));
    try std.testing.expectEqualDeep(before, .{ digest(&caller.stark), digest(&fused.stark), fused.memory_claims[0] });
    var moved = try Fused.ClaimFrames.clone(a, &fused);
    var owns_moved = true;
    defer if (owns_moved) moved.deinit(a);
    var owned_caller = Family.Proof{ .stark = try malformed(a), .claims = caller.claims, .key_id = caller.key_id, .instance_id = caller.instance_id };
    var owns_caller = true;
    defer if (owns_caller) owned_caller.deinit(a);
    const owned_fused = Fused.Proof{ .stark = try malformed(a), .program_claims = moved.program_claims, .state_claims = moved.state_claims, .table_claims = moved.table_claims, .memory_claims = moved.memory_claims };
    owns_moved = false;
    owns_caller = false;
    try std.testing.expectError(error.UntrustedV5CallerCompositeEventCensus, Combined.ForBackend(Cpu).verifyOwned(a, owned_caller, owned_fused, 0, wrong, fixture.sealed, fixture.pins, &fixture.entries));
}
test "caller capture: original caller arithmetic and fused channels retain separate exact reset geometry" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var first = suite.Channel{};
    first.mixRoot(fixture.binding.first_roots[0]);
    first.mixRoot(fixture.binding.first_roots[1]);
    const arithmetic = try Protocol.pcsChannel(a, fixture.sealed, fixture.binding);
    const fused = try Fused.proofChannel(a, fixture.sealed);
    try std.testing.expect(!std.meta.eql(first, arithmetic));
    try std.testing.expect(!std.meta.eql(arithmetic, fused));
    var manual = fixture.sealed.sharedChannel();
    const vm = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &manual);
    manual.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, @intFromEnum(Protocol.circuit_profile) });
    _ = try Profile.Relations.drawAfterVm(a, &manual, vm);
    manual.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, fixture.binding.execution_index });
    manual.mixRoot(fixture.binding.execution_instance_id);
    manual.mixRoot(fixture.binding.caller_key_id);
    manual.mixRoot(fixture.binding.caller_instance_id);
    for (fixture.binding.first_roots) |root| manual.mixRoot(root);
    try std.testing.expectEqualDeep(arithmetic, manual);
    manual = fixture.sealed.sharedChannel();
    _ = try @import("../block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &manual);
    manual.mixU32s(&.{ Fused.TAG, Fused.VERSION, 3 });
    manual.mixRoot(fixture.sealed.digest);
    try std.testing.expectEqualDeep(fused, manual);
    inline for ([_]Protocol.Tree{ .fixed, .main, .interaction }) |tree| {
        const logs = try Protocol.columnLogs(a, &fixture.statement, tree);
        defer a.free(logs);
        var width: usize = 0;
        for (Profile.descriptors(&fixture.statement)) |desc| {
            const count = switch (tree) {
                .fixed => desc.preprocessed_columns,
                .main => desc.main_columns,
                .interaction => desc.interaction_columns,
            };
            for (logs[width..][0..count]) |log| try std.testing.expectEqual(desc.log_size, log);
            width += count;
        }
        try std.testing.expectEqual(width, logs.len);
    }
}
test "caller capture: actual owned borrowed and combined verifier bodies retained without invocation" {
    const Base = Family.ForBackend(Cpu);
    const Access = Fused.ForBackend(Cpu);
    const Both = Combined.ForBackend(Cpu);
    inline for (.{ &Base.verifyOwned, &Base.verifyCaptureOwned, &Base.verifyCaptureBorrowed, &Family.VerifiedCapture.validate, &Access.verifyAfterFreshCaller, &Access.verifyCaptureOwnedAfterFreshCaller, &Access.verifyCaptureBorrowedAfterFreshCaller, &Fused.VerifiedCapture.validateAfterFreshCaller, &Both.verifyOwned, &Both.verifyBorrowed, &Combined.Verified.validate }) |function| {
        std.mem.doNotOptimizeAway(function);
        try std.testing.expect(@intFromPtr(function) != 0);
    }
}
