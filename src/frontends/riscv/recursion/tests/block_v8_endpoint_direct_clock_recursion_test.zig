const std = @import("std");
const core = @import("stwo_core");
const Family = @import("../block_v8_endpoint_local_recursive_v1.zig");
const Metadata = @import("../../prover/block_v8_endpoint_local_statement_wire_v1.zig");
const Codec = @import("../../prover/block_v8_endpoint_local_codec_v1.zig");
const Original = @import("../../prover/block_v8_endpoint_local_proof_v1.zig");
const Statement = @import("../../prover/block_v8_endpoint_local_statement_v1.zig");
comptime {
    const Scope = @import("../../prover/block_v8_endpoint_local_scope_v1.zig");
    if (@hasField(Scope.Trusted, "window") or @hasField(Scope.Input, "memory_geometry")) @compileError("Local recursive theorem must not acquire snapshot or global RAM inputs");
}
const Observer = struct {
    pub fn observe(a: std.mem.Allocator, metadata: *const Statement.Owned, source_bytes: []const u8) !void {
        const selected: @import("../blake3_execution_parent_protocol.zig").Profile = if (metadata.trusted.config.fri_config.n_queries == 70) .csp_q70_pow26 else .diagnostic_q8_pow0;
        const encoded_metadata = try Metadata.encode(a, metadata.trusted, metadata.input, .{});
        defer a.free(encoded_metadata);
        var source_report: Family.SourceReport.Report = undefined;
        var root = blk: {
            var decoded = try Codec.decode(a, source_bytes, metadata.trusted, metadata.input, .{});
            var decoded_live = true;
            defer if (decoded_live) decoded.deinit();
            var capture = try Original.verifyAndCapture(a, metadata.trusted, metadata.input, &decoded.stark, decoded.claims, .{});
            defer capture.deinit();
            const profile = try Family.Profile.Owned.derive(a, metadata, decoded.claims, .{});
            defer profile.deinit();
            try std.testing.expectEqual(@as(usize, 11), Family.Profile.TRACE_TREES);
            try std.testing.expectEqual(@as(usize, 6), Family.Profile.FIRST_ROOTS);
            const public = try Family.Composition.publicValues(a, profile);
            defer a.free(public);
            try std.testing.expectEqual(8 + profile.claims.native.len + 11 + 2 + 1 + 6 + 416, public.len);
            try checkClosure(a, profile, public);
            source_report = try Family.SourceReport.derive(profile);
            try std.testing.expectEqual(@as(usize, 0), source_report.snapshot_delta_public_byte_ports);
            try std.testing.expectEqual(public.len, source_report.total_public_operands);
            decoded.deinit();
            decoded_live = false;
            break :blk try Family.Pipeline.produce(a, profile, &capture, .{ .profile = selected });
        };
        defer root.deinit();
        const fresh = try Metadata.decode(a, encoded_metadata, metadata.trusted, .{});
        defer fresh.deinit();
        var verified = try Family.Pipeline.verify(a, root.bytes, root.claims, fresh, .{}, .{ .profile = selected });
        defer verified.deinit();
        try std.testing.expectEqual(.local_execution_global_ram_open, verified.summary.scope);
        try std.testing.expectEqualDeep(fresh.input.native_roots[2], verified.summary.source.endpoint_root);
        try std.testing.expectEqual(fresh.input.endpoint_count, verified.summary.source.endpoint_count);
        root.bytes[0] ^= 1;
        if (Family.Pipeline.verify(a, root.bytes, root.claims, fresh, .{}, .{ .profile = selected })) |accepted| {
            var bad = accepted;
            bad.deinit();
            return error.AcceptedChangedLocalRecursiveProof;
        } else |_| {}
        root.bytes[0] ^= 1;
        try saveArtifacts(a, &root, fresh, source_report);
        std.debug.print("B8_LOCAL11_RECURSION queries={d} pow={d} bytes={d} proof_ns={d} cpu_boundary_byte_ports=416 snapshot_ports=0 global_ram=open same_endpoint_root=true fresh_key=true\n", .{ metadata.trusted.config.fri_config.n_queries, metadata.trusted.config.pow_bits, root.bytes.len, root.stats.proof_ns });
    }
};
fn checkClosure(a: std.mem.Allocator, profile: *const Family.Profile.Owned, public: []const core.fields.qm31.QM31) !void {
    const G = @import("../air/composition_graph_recorder.zig");
    const Q = core.fields.qm31.QM31;
    const drawn = try @import("../air/block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(a, profile.scope.epoch);
    const inputs = try a.alloc(Q, public.len + drawn.len);
    defer a.free(inputs);
    @memcpy(inputs[0..public.len], public);
    @memcpy(inputs[public.len..], &drawn);
    var b = G.Builder.init(a);
    defer b.deinit();
    const symbols = try a.alloc(G.Scalar, inputs.len);
    defer a.free(symbols);
    for (symbols) |*value| value.* = (try b.input()).value;
    var draws: [53][2]G.Scalar = undefined;
    for (&draws, 0..) |*pair, index| pair.* = symbols[public.len + 2 * index ..][0..2].*;
    const physical = public.len - 416;
    try b.activate();
    defer if (b.active) b.deactivate();
    try @import("../air/block_v8_endpoint_recursive_closure_v1.zig").For(.local_open).record(a, &b, profile, symbols[0..physical], symbols[physical..public.len], draws);
    b.deactivate();
    var circuit = try b.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    try circuit.evaluateInto(inputs, values);
    const projections = profile.context.local.?.native.layout.slots.len;
    if (profile.context.local.?.native.clock_v3.len != 0) {
        const gap = 8 + projections;
        inputs[gap] = inputs[gap].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs, values));
        inputs[gap] = inputs[gap].sub(Q.one());
    }
    const endpoint = 8 + profile.claims.native.len;
    // The later global draw is a different theorem. Local closure must not
    // smuggle its open plane into a completed global RAM equality.
    inputs[endpoint + 1] = inputs[endpoint + 1].add(Q.one());
    try circuit.evaluateInto(inputs, values);
    inputs[endpoint + 1] = inputs[endpoint + 1].sub(Q.one());
    inputs[endpoint] = inputs[endpoint].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs, values));
    inputs[endpoint] = inputs[endpoint].sub(Q.one());
    inputs[physical] = inputs[physical].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs, values));
    inputs[physical] = inputs[physical].sub(Q.one());
    try circuit.evaluateInto(inputs, values);
}
test "canonical DirectRAM V3 wide profile4 recursive source retains all gap range and closure equations" {
    _ = try @import("../../prover/tests/block_v8_endpoint_local_direct_clock_v3_test.zig").qualifyWithObserver(true, false, Observer);
}

fn saveArtifacts(a: std.mem.Allocator, root: *const Family.Pipeline.Artifact, metadata: *const Statement.Owned, source: Family.SourceReport.Report) !void {
    if (metadata.trusted.config.fri_config.n_queries != 70 or metadata.trusted.config.pow_bits != 26) return;
    const path = std.process.getEnvVarOwned(a, "STWO_B8_LOCAL_RECURSION_ARTIFACT_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer a.free(path);
    var output = try std.fs.cwd().makeOpenPath(path, .{});
    defer output.close();
    try output.writeFile(.{ .sub_path = "root.proof", .data = root.bytes });
    try output.writeFile(.{ .sub_path = "physical-claims.bin", .data = root.claims });
    const encoded = try Metadata.encode(a, metadata.trusted, metadata.input, .{});
    defer a.free(encoded);
    try output.writeFile(.{ .sub_path = "metadata.json", .data = encoded });
    const manifest = try std.json.Stringify.valueAlloc(a, Family.SourceReport.manifest(), .{ .whitespace = .indent_2 });
    defer a.free(manifest);
    try output.writeFile(.{ .sub_path = "source-exact-manifest.json", .data = manifest });
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(root.bytes, &proof_digest, .{});
    const report = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-b8-direct-ram-clock-wide-recursive-qualification-v4",
        .scope = "local_execution_global_ram_open",
        .native_profile = metadata.input.native_profile,
        .native_shard_version = metadata.input.shape.native_shard_version,
        .queries = metadata.trusted.config.fri_config.n_queries,
        .pow_bits = metadata.trusted.config.pow_bits,
        .global_ram_closed = false,
        .same_endpoint_main_root = true,
        .decoded_original_destroyed = true,
        .detached_metadata = true,
        .fresh_key = true,
        .cpu_boundary_byte_ports = 416,
        .snapshot_byte_ports = 0,
        .source_geometry = source,
        .proof_bytes = root.bytes.len,
        .proof_sha256 = std.fmt.bytesToHex(proof_digest, .lower),
        .stats = root.stats,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "qualification.json", .data = report });
}
