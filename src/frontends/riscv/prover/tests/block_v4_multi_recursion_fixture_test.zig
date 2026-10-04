//! Canonical two-leaf v3 recursion over fresh v4 execution-sidecar receipts.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Native = @import("../blake3_ethereum_sha_proof.zig");
const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const exact = @import("../../recursion/blake3_exact_root_aggregate.zig");
const linked = @import("../../recursion/blake3_exact_root_receiver_v3.zig");
const v3 = @import("../../recursion/blake3_block_execution_span_v3.zig");

pub const Proofs = struct {
    leaf_bytes: [2][]u8,
    leaf_admissions: [2]parent.protocol.Admission,
    dyadic_bytes: []u8,
    dyadic_admission: parent.protocol.Admission,
    outer_bytes: []u8,
    outer_admission: parent.protocol.Admission,
    forest_digest: [32]u8,
    peak_live_bytes: usize,
    leaf_prove_ns: [2]u64,
    dyadic_prove_ns: u64,
    outer_prove_ns: u64,
    elapsed_ns: u64,

    pub fn deinit(self: *Proofs, a: std.mem.Allocator) void {
        for (self.leaf_bytes) |bytes| a.free(bytes);
        a.free(self.dyadic_bytes);
        a.free(self.outer_bytes);
        self.* = undefined;
    }
};

pub fn prove(a: std.mem.Allocator, view: anytype) !Proofs {
    return proveWithProfile(a, view, .csp_q70_pow26);
}

pub fn proveWithProfile(a: std.mem.Allocator, view: anytype, profile: parent.protocol.Profile) !Proofs {
    if (!std.meta.eql(view.config, profile.config()) or
        view.wire.execution.len != 2 or view.receipts.len != 2)
        return error.UnexpectedBlockRecursiveSecurity;
    const budget = try Budget.create(a, 24 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const work = budget.allocator();
    var total_timer = try std.time.Timer.start();
    const job = view.statement.complete_pins.?.expected_job;
    const Api = parent.ForBackend(Cpu);
    var nodes: [2]parent.tree.Node = undefined;
    var node_count: usize = 0;
    defer for (nodes[0..node_count]) |*node| node.deinit();
    var descriptors: [2]linked.Descriptor = undefined;
    var leaf_wires: [2][]u8 = undefined;
    var wire_count: usize = 0;
    defer for (leaf_wires[0..wire_count]) |bytes| work.free(bytes);
    var leaf_admissions: [2]parent.protocol.Admission = undefined;
    var leaf_prove_ns: [2]u64 = undefined;

    for (&nodes, &descriptors, &leaf_wires, &leaf_admissions, 0..) |*node, *descriptor, *wire, *admission, i| {
        const execution = &view.executions[i];
        const native_proof = try Native.codec.decode(work, view.wire.execution[i].native_artifact, execution.prepared, execution.prepared.id);
        var capture = try Native.ForBackend(Cpu).verifyCaptureOwned(work, native_proof, execution.prepared, execution.prepared.id);
        defer capture.deinit();
        const statement = try v3.leaf(job, &view.segments[i].base);
        if (!std.meta.eql(statement, view.execution_pins[i].statement)) return error.InconsistentBlockV3Leaf;
        var prepared = try v3.prepare(work, execution.prepared, &capture, execution.prepared.id, 2, statement, view.statement.seal, view.receipts[i].witness_root, &view.receipts[i]);
        defer prepared.deinit();
        const key = try Api.deriveKeyWithProfile(work, &prepared, profile);
        admission.* = try parent.protocol.Admission.init(key, try key.identity());
        const plan = try Api.Plan.init(work, &prepared.rows, admission.*);
        defer plan.deinit();
        var stage_timer = try std.time.Timer.start();
        var artifact = try plan.prove(work, &prepared.rows);
        leaf_prove_ns[i] = stage_timer.read();
        wire.* = parent.codec.encode(work, &artifact, admission) catch |err| {
            artifact.deinit();
            return err;
        };
        wire_count += 1;
        node.* = try parent.tree.Node.verifyOwned(&artifact, admission.*, admission.expected_id, statement);
        node_count += 1;
        descriptor.* = try linked.verifyLeafBytes(work, wire.*, admission.*, admission.expected_id, statement, &execution.prepared.native.public_data, view.config, view.statement.seal, execution.prepared.id, view.receipts[i].native_roots, view.receipts[i].witness_root, &view.receipts[i]);
    }

    var pair = try parent.tree.preparePair(work, &nodes[0], &nodes[1], 2);
    defer pair.deinit();
    const pair_key = try Api.deriveKeyWithProfile(work, &pair.prepared, profile);
    const pair_admission = try parent.protocol.Admission.init(pair_key, try pair_key.identity());
    const pair_plan = try Api.Plan.init(work, &pair.prepared.rows, pair_admission);
    defer pair_plan.deinit();
    var stage_timer = try std.time.Timer.start();
    var pair_proof = try pair_plan.prove(work, &pair.prepared.rows);
    const dyadic_prove_ns = stage_timer.read();
    const pair_wire = parent.codec.encode(work, &pair_proof, &pair_admission) catch |err| {
        pair_proof.deinit();
        return err;
    };
    defer work.free(pair_wire);
    var pair_node = try parent.tree.Node.verifyOwned(&pair_proof, pair_admission, pair_admission.expected_id, pair.statement);
    defer pair_node.deinit();
    const pair_descriptor = try linked.verifyDyadicBytes(work, pair_wire, pair_admission, pair_admission.expected_id, descriptors[0], descriptors[1]);
    const roots = [_]linked.Descriptor{pair_descriptor};
    const digest = try linked.verifiedForestDigest(job, &roots);
    const children = [_]*const parent.tree.Node{&pair_node};
    var folded = if (profile == .diagnostic_q8_pow0)
        try exact.prepareDiagnostic(work, job, &children, digest, 2)
    else
        try exact.prepare(work, job, &children, digest, 2);
    defer folded.deinit();
    const outer_key = try Api.deriveKeyWithProfile(work, &folded.prepared, profile);
    const outer_admission = try parent.protocol.Admission.init(outer_key, try outer_key.identity());
    const outer_plan = try Api.Plan.init(work, &folded.prepared.rows, outer_admission);
    defer outer_plan.deinit();
    stage_timer.reset();
    var outer_proof = try outer_plan.prove(work, &folded.prepared.rows);
    const outer_prove_ns = stage_timer.read();
    defer outer_proof.deinit();
    const outer_wire = try parent.codec.encode(work, &outer_proof, &outer_admission);
    defer work.free(outer_wire);
    var outer = if (profile == .diagnostic_q8_pow0)
        try linked.verifyDiagnosticExactBytes(work, outer_wire, outer_admission, outer_admission.expected_id, job, &roots)
    else
        try linked.verifyExactBytes(work, outer_wire, outer_admission, outer_admission.expected_id, job, &roots);
    defer outer.deinit();
    _ = try outer.root();

    const leaf_bytes = [_][]u8{ try a.dupe(u8, leaf_wires[0]), try a.dupe(u8, leaf_wires[1]) };
    errdefer for (leaf_bytes) |bytes| a.free(bytes);
    const dyadic_bytes = try a.dupe(u8, pair_wire);
    errdefer a.free(dyadic_bytes);
    return .{
        .leaf_bytes = leaf_bytes,
        .leaf_admissions = leaf_admissions,
        .dyadic_bytes = dyadic_bytes,
        .dyadic_admission = pair_admission,
        .outer_bytes = try a.dupe(u8, outer_wire),
        .outer_admission = outer_admission,
        .forest_digest = digest,
        .peak_live_bytes = budget.snapshot().peak_live_bytes,
        .leaf_prove_ns = leaf_prove_ns,
        .dyadic_prove_ns = dyadic_prove_ns,
        .outer_prove_ns = outer_prove_ns,
        .elapsed_ns = total_timer.read(),
    };
}
