const std = @import("std");
const core = @import("stwo_core");
const Whole = @import("../../prover/block_v8_endpoint_whole_proof_v1.zig");
const Observer = struct {
    pub fn observe(a: std.mem.Allocator, trusted: @import("../../prover/block_v7_execution_receiver_v1.zig").Trusted, input: @import("../../prover/block_v8_endpoint_whole_scope_v1.zig").Input, stark: *const core.proof_suites.Blake3.Proof, claims: @import("../../prover/block_v8_endpoint_whole_ledger_v1.zig").Claims) !void {
        const metadata = try @import("../../prover/block_v8_endpoint_whole_statement_v1.zig").Owned.init(a, trusted, input);
        defer metadata.deinit();
        const profile = try @import("../block_v8_endpoint_original_profile_v1.zig").Owned.derive(a, metadata, claims, .{});
        defer profile.deinit();
        try checkClosure(a, profile);
        var capture = try Whole.verifyAndCapture(a, trusted, input, stark, claims, .{});
        defer capture.deinit();
        var composition = try @import("../air/block_v8_endpoint_composition_v1.zig").prepare(a, profile, &capture);
        defer composition.deinit();
        var transcript = try @import("../air/block_v8_endpoint_transcript_v1.zig").replay(a, profile, &capture, 4);
        defer transcript.deinit();
        var cold = try @import("../air/block_v8_endpoint_transcript_v1.zig").fixed(a, profile, 4, .{});
        defer cold.deinit();
        try std.testing.expectEqualDeep(cold.id, transcript.plan.id);
        var pcs = try @import("../block_v8_endpoint_pcs_preparation_v1.zig").prepare(a, profile, &capture, &transcript);
        defer pcs.deinit();
        std.debug.print("B8_ENDPOINT_RECURSIVE_ADAPTER constraints={d} nodes={d} transcript={d} queries={d} pow={d}\n", .{ profile.constraint_count, composition.circuit.nodes.len, transcript.plan.fixed.root_reads.len, trusted.config.fri_config.n_queries, trusted.config.pow_bits });
    }
};
test "diagnostic B8 endpoint recursive composition transcript and PCS match fresh original" {
    try @import("../../prover/tests/block_v8_endpoint_whole_proof_test.zig").qualifyWithObserver(@import("../blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(), Observer);
}
const Pipeline = @import("../block_v8_endpoint_pipeline_v1.zig");
const RecursiveObserver = struct {
    var pending: ?Pipeline.Artifact = null;
    pub fn discard() void {
        if (pending) |*root| root.deinit();
        pending = null;
    }
    pub fn observe(a: std.mem.Allocator, trusted: @import("../../prover/block_v7_execution_receiver_v1.zig").Trusted, input: @import("../../prover/block_v8_endpoint_whole_scope_v1.zig").Input, stark: *const core.proof_suites.Blake3.Proof, claims: @import("../../prover/block_v8_endpoint_whole_ledger_v1.zig").Claims) !void {
        if (pending != null) return error.UnreleasedEndpointRecursiveTestArtifact;
        const metadata = try @import("../../prover/block_v8_endpoint_whole_statement_v1.zig").Owned.init(a, trusted, input);
        defer metadata.deinit();
        const Selected = @import("../blake3_execution_parent_protocol.zig").Profile;
        const selected: Selected = if (trusted.config.fri_config.n_queries == 70) .csp_q70_pow26 else .diagnostic_q8_pow0;
        const profile = try @import("../block_v8_endpoint_original_profile_v1.zig").Owned.derive(a, metadata, claims, .{});
        defer profile.deinit();
        try checkClosure(a, profile);
        var capture = try Whole.verifyAndCapture(a, trusted, input, stark, claims, .{});
        defer capture.deinit();
        pending = try Pipeline.produce(a, profile, &capture, .{ .profile = selected });
    }
    /// Called only after the fixture has destroyed the original proof and all
    /// producer metadata. This receiver sees durable root/claim bytes and a new
    /// statement independently admitted from complete external snapshot pins.
    pub fn afterOriginalDestroyed(a: std.mem.Allocator, metadata: *const @import("../../prover/block_v8_endpoint_whole_statement_v1.zig").Owned) !void {
        const root = if (pending) |*owned| owned else return error.MissingEndpointRecursiveTestArtifact;
        defer discard();
        const Selected = @import("../blake3_execution_parent_protocol.zig").Profile;
        const config = metadata.trusted.config;
        const selected: Selected = if (config.fri_config.n_queries == 70) .csp_q70_pow26 else .diagnostic_q8_pow0;
        const limits = Pipeline.Limits{ .profile = selected };
        var verified = try Pipeline.verify(a, root.bytes, root.claims, metadata, .{}, limits);
        defer verified.deinit();
        root.bytes[0] ^= 1;
        if (Pipeline.verify(a, root.bytes, root.claims, metadata, .{}, limits)) |accepted| {
            var bad = accepted;
            bad.deinit();
            return error.AcceptedChangedEndpointRecursiveProof;
        } else |_| {}
        root.bytes[0] ^= 1;
        try saveArtifacts(a, root, metadata);
        std.debug.print("B8_ENDPOINT_CLOSED_RECURSION bytes={d} proof_ns={d} queries={d} pow={d} original_destroyed=true detached_metadata=true fresh_key=true host_closure_authority=false\n", .{ root.bytes.len, root.stats.proof_ns, config.fri_config.n_queries, config.pow_bits });
    }
};
test "diagnostic B8 endpoint real recursive proof closes native endpoint and global ledger" {
    defer RecursiveObserver.discard();
    try @import("../../prover/tests/block_v8_endpoint_whole_proof_test.zig").qualifyWithObserver(@import("../blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(), RecursiveObserver);
}
test "canonical B8 endpoint real recursive proof closes native endpoint and global ledger" {
    defer RecursiveObserver.discard();
    try @import("../../prover/tests/block_v8_endpoint_whole_proof_test.zig").qualifyWithObserver(@import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(), RecursiveObserver);
}

fn checkClosure(a: std.mem.Allocator, profile: *const @import("../block_v8_endpoint_original_profile_v1.zig").Owned) !void {
    const G = @import("../air/composition_graph_recorder.zig");
    const Q = core.fields.qm31.QM31;
    const public = try @import("../air/block_v8_endpoint_composition_v1.zig").publicValues(a, profile);
    defer a.free(public);
    const drawn = try @import("../air/block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(a, profile.scope.epoch);
    const inputs = try a.alloc(Q, public.len + drawn.len);
    defer a.free(inputs);
    @memcpy(inputs[0..public.len], public);
    @memcpy(inputs[public.len..], &drawn);
    var builder = G.Builder.init(a);
    defer builder.deinit();
    const symbols = try a.alloc(G.Scalar, inputs.len);
    defer a.free(symbols);
    for (symbols) |*v| v.* = (try builder.input()).value;
    var draws: [53][2]G.Scalar = undefined;
    for (&draws, 0..) |*pair, index| pair.* = symbols[public.len + 2 * index ..][0..2].*;
    const boundary_bytes = 4 * (104 + 3 * profile.statement.trusted.window.?.changes.len);
    const physical = public.len - boundary_bytes;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try @import("../air/block_v8_endpoint_closure_v1.zig").record(a, &builder, profile, symbols[0..physical], symbols[physical..public.len], draws);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    defer a.free(evaluated);
    try circuit.evaluateInto(inputs, evaluated);
    // A false endpoint request census cannot be supplied as a successful host
    // receipt: the circuit enforces the exact independent 13-per-endpoint count.
    const range_count = 8 + profile.claims.native.len + 11 + 1;
    inputs[range_count] = inputs[range_count].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs, evaluated));
    inputs[range_count] = inputs[range_count].sub(Q.one());
    // A changed CPU boundary is an equation operand, not a residual supplied
    // by a host closure call.
    inputs[physical] = inputs[physical].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs, evaluated));
    inputs[physical] = inputs[physical].sub(Q.one());
    try circuit.evaluateInto(inputs, evaluated);
}

fn saveArtifacts(a: std.mem.Allocator, root: *const Pipeline.Artifact, metadata: *const @import("../../prover/block_v8_endpoint_whole_statement_v1.zig").Owned) !void {
    if (metadata.trusted.config.fri_config.n_queries != 70 or metadata.trusted.config.pow_bits != 26) return;
    const path = std.process.getEnvVarOwned(a, "STWO_B8_ENDPOINT_RECURSION_ARTIFACT_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer a.free(path);
    var directory = try std.fs.cwd().makeOpenPath(path, .{});
    defer directory.close();
    try directory.writeFile(.{ .sub_path = "root.proof", .data = root.bytes });
    try directory.writeFile(.{ .sub_path = "physical-claims.bin", .data = root.claims });
    const metadata_bytes = try @import("../../prover/block_v8_endpoint_whole_statement_wire_v1.zig").encode(a, metadata.trusted, metadata.input, .{});
    defer a.free(metadata_bytes);
    try directory.writeFile(.{ .sub_path = "metadata.json", .data = metadata_bytes });
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(root.bytes, &proof_digest, .{});
    const report = try std.json.Stringify.valueAlloc(a, .{
        .source = "B8 endpoint original plus symbolic complete ledger",
        .scope = "declared_nonterminal_window",
        .layout_version = @import("../../prover/block_v8_native_endpoint_layout_v1.zig").VERSION,
        .queries = metadata.trusted.config.fri_config.n_queries,
        .pow_bits = metadata.trusted.config.pow_bits,
        .cycles = metadata.input.shape.public_data.clock,
        .endpoint_count = metadata.input.endpoint_count,
        .proof_sha256 = std.fmt.bytesToHex(proof_digest, .lower),
        .elf_sha256 = std.fmt.bytesToHex(metadata.trusted.elf_sha256, .lower),
        .incoming_snapshot_sha256 = std.fmt.bytesToHex(metadata.trusted.window.?.boundary.incoming_sha256, .lower),
        .outgoing_snapshot_sha256 = std.fmt.bytesToHex(metadata.trusted.window.?.boundary.outgoing_sha256, .lower),
        .proof_bytes = root.bytes.len,
        .claims_bytes = root.claims.len,
        .original_destroyed = true,
        .detached_metadata = true,
        .fresh_key = true,
        .host_closure_authority = false,
        .stats = root.stats,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try directory.writeFile(.{ .sub_path = "qualification.json", .data = report });
}
