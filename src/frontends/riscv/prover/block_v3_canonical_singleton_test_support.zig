//! Reuses a coherent, freshly verified Ethereum-SHA core fixture to produce
//! canonical block-v3 recursion artifacts without reproducing native proofs.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const fixture = @import("block_memory_core_sha_fixture_test.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const exact = @import("../recursion/blake3_exact_root_aggregate.zig");
const receiver = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");

pub const Proofs = struct {
    leaf_bytes: []u8,
    leaf_admission: parent.protocol.Admission,
    outer_bytes: []u8,
    outer_admission: parent.protocol.Admission,
    forest_digest: [32]u8,
    peak_live_bytes: usize,
    leaf_prove_ns: u64,
    outer_prove_ns: u64,

    pub fn deinit(self: *Proofs, a: std.mem.Allocator) void {
        a.free(self.leaf_bytes);
        a.free(self.outer_bytes);
        self.* = undefined;
    }
};

/// `view` is borrowed from the coherent fixture callback. Its sidecar receipt
/// came from `verifyCoreOwned`; its native artifact is decoded and captured
/// again here so the recursive AIR consumes an actual verified child proof.
pub fn prove(a: std.mem.Allocator, view: fixture.FixtureView) !Proofs {
    return proveWithProfile(a, view, .csp_q70_pow26);
}

/// Diagnostic q8 callers use the same native-root and recursive binding path
/// without relaxing the separate canonical complete receiver's q70 guard.
pub fn proveWithProfile(a: std.mem.Allocator, view: fixture.FixtureView, profile: parent.protocol.Profile) !Proofs {
    if (!std.meta.eql(view.config, profile.config()) or
        view.wire.execution.len != 1 or
        view.execution_pin.statement.job.segment_count != 1)
        return error.ExpectedCanonicalBlockSecurity;
    const budget = try Budget.create(a, 24 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const work = budget.allocator();
    const native_bytes = view.wire.execution[0].native_artifact;
    const native_proof = try Native.codec.decode(
        work,
        native_bytes,
        view.prepared,
        view.prepared.id,
    );
    var capture = try Native.ForBackend(Cpu).verifyCaptureOwned(
        work,
        native_proof,
        view.prepared,
        view.prepared.id,
    );
    defer capture.deinit();
    const statement = try v3.leaf(
        view.execution_pin.statement.job,
        &view.segment.base,
    );
    if (!std.meta.eql(statement, view.execution_pin.statement))
        return error.InconsistentBlockV3Leaf;
    var prepared = try v3.prepare(
        work,
        view.prepared,
        &capture,
        view.prepared.id,
        2,
        statement,
        view.statement.seal,
        view.execution_receipt.witness_root,
        view.execution_receipt,
    );
    defer prepared.deinit();
    const Api = parent.ForBackend(Cpu);
    const leaf_key = try Api.deriveKeyWithProfile(
        work,
        &prepared,
        profile,
    );
    const leaf_admission = try parent.protocol.Admission.init(
        leaf_key,
        try leaf_key.identity(),
    );
    const leaf_plan = try Api.Plan.init(work, &prepared.rows, leaf_admission);
    defer leaf_plan.deinit();
    var timer = try std.time.Timer.start();
    var leaf_artifact = try leaf_plan.prove(work, &prepared.rows);
    const leaf_prove_ns = timer.read();
    const leaf_wire = parent.codec.encode(work, &leaf_artifact, &leaf_admission) catch |err| {
        leaf_artifact.deinit();
        return err;
    };
    defer work.free(leaf_wire);
    var leaf = try parent.tree.Node.verifyOwned(
        &leaf_artifact,
        leaf_admission,
        leaf_admission.expected_id,
        statement,
    );
    defer leaf.deinit();
    const linked = try receiver.verifyLeafBytes(
        work,
        leaf_wire,
        leaf_admission,
        leaf_admission.expected_id,
        statement,
        &view.prepared.native.public_data,
        view.config,
        view.statement.seal,
        view.prepared.id,
        view.execution_receipt.native_roots,
        view.execution_receipt.witness_root,
        view.execution_receipt,
    );
    const roots = [_]receiver.Descriptor{linked};
    const digest = try receiver.verifiedForestDigest(statement.job, &roots);
    const children = [_]*const parent.tree.Node{&leaf};
    var folded = if (profile == .diagnostic_q8_pow0)
        try exact.prepareDiagnostic(work, statement.job, &children, digest, 2)
    else
        try exact.prepare(work, statement.job, &children, digest, 2);
    defer folded.deinit();
    const outer_key = try Api.deriveKeyWithProfile(
        work,
        &folded.prepared,
        profile,
    );
    const outer_admission = try parent.protocol.Admission.init(
        outer_key,
        try outer_key.identity(),
    );
    const outer_plan = try Api.Plan.init(
        work,
        &folded.prepared.rows,
        outer_admission,
    );
    defer outer_plan.deinit();
    timer.reset();
    var outer_artifact = try outer_plan.prove(work, &folded.prepared.rows);
    defer outer_artifact.deinit();
    const outer_prove_ns = timer.read();
    const outer_wire = try parent.codec.encode(
        work,
        &outer_artifact,
        &outer_admission,
    );
    defer work.free(outer_wire);
    var outer = if (profile == .diagnostic_q8_pow0)
        try receiver.verifyDiagnosticExactBytes(work, outer_wire, outer_admission,
            outer_admission.expected_id, statement.job, &roots)
    else
        try receiver.verifyExactBytes(work, outer_wire, outer_admission,
            outer_admission.expected_id, statement.job, &roots);
    defer outer.deinit();
    _ = try outer.root();
    const leaf_bytes = try a.dupe(u8, leaf_wire);
    errdefer a.free(leaf_bytes);
    const outer_bytes = try a.dupe(u8, outer_wire);
    return .{
        .leaf_bytes = leaf_bytes,
        .leaf_admission = leaf_admission,
        .outer_bytes = outer_bytes,
        .outer_admission = outer_admission,
        .forest_digest = digest,
        .peak_live_bytes = budget.snapshot().peak_live_bytes,
        .leaf_prove_ns = leaf_prove_ns,
        .outer_prove_ns = outer_prove_ns,
    };
}
