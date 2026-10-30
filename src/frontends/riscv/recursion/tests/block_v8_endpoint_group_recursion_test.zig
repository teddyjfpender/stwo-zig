const std = @import("std");
const core = @import("stwo_core");
const Family = @import("../block_v8_endpoint_group_recursive_v1.zig");
const Metadata = @import("../../prover/block_v8_endpoint_group_statement_wire_v1.zig");
const Codec = @import("../../prover/block_v8_endpoint_group_codec_v1.zig");
const Original = @import("../../prover/block_v8_endpoint_group_proof_v1.zig");
const Bundle = @import("../../prover/block_v8_endpoint_group_bundle_v1.zig");
const Observer = struct {
    pub const budget_bytes: usize = 32 << 30;
    pub fn observeFiles(a: std.mem.Allocator, directory: std.fs.Dir, external: Bundle.External) !void {
        const trusted = @import("../../prover/block_v8_endpoint_group_scope_v1.zig").Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = 2 };
        const encoded = try directory.readFileAlloc(a, "group-0.json", 16 << 20);
        defer a.free(encoded);
        const source = try directory.readFileAlloc(a, "group-0.proof", 128 << 20);
        var source_live = true;
        defer if (source_live) a.free(source);
        const selected: @import("../blake3_execution_parent_protocol.zig").Profile = if (external.config.fri_config.n_queries == 70) .csp_q70_pow26 else .diagnostic_q8_pow0;
        var root = blk: {
            const metadata = try Metadata.decode(a, encoded, trusted, .{});
            defer metadata.deinit();
            var decoded = try Codec.decode(a, source, trusted, metadata.input, .{});
            var decoded_live = true;
            defer if (decoded_live) decoded.deinit();
            var capture = try Original.verifyAndCapture(a, trusted, metadata.input, &decoded.stark, decoded.claims, .{});
            defer capture.deinit();
            const profile = try Family.Profile.Owned.derive(a, metadata, decoded.claims, .{});
            defer profile.deinit();
            try std.testing.expectEqual(@as(usize, 15), profile.layout.traces());
            try std.testing.expectEqual(@as(usize, 8), profile.layout.firstRoots());
            try checkClosure(a, profile);
            // Pipeline independently compiles cold equations/transcript/PCS,
            // prepares their live witnesses and checks exact fixed/live parity.
            decoded.deinit();
            decoded_live = false;
            a.free(source);
            source_live = false;
            break :blk try Family.Pipeline.produce(a, profile, &capture, .{ .profile = selected });
        };
        defer root.deinit();
        // No original STARK, capture, context, native witness or producer key
        // survives into this receiver. It uses only root/claim/public bytes.
        const fresh = try Metadata.decode(a, encoded, trusted, .{});
        defer fresh.deinit();
        var verified = try Family.Pipeline.verify(a, root.bytes, root.claims, fresh, .{}, .{ .profile = selected });
        defer verified.deinit();
        try std.testing.expectEqual(.group_execution_global_ram_open, verified.summary.scope);
        try std.testing.expectEqual(@as(u32, 2), verified.summary.cohorts);
        for (fresh.input.members, verified.summary.sources[0..2]) |member, received| try std.testing.expectEqualDeep(member.endpoint_main_root, received.endpoint_root);
        root.bytes[0] ^= 1;
        if (Family.Pipeline.verify(a, root.bytes, root.claims, fresh, .{}, .{ .profile = selected })) |accepted| {
            var bad = accepted;
            bad.deinit();
            return error.AcceptedChangedGroupRoot;
        } else |_| {}
        root.bytes[0] ^= 1;
        std.debug.print("B8_GROUP_RECURSION members=2 trees=15 roots=8 q={d} pow={d} bytes={d} parent_proof_ns={d} same_endpoint_roots=true fresh_key=true original_destroyed=true global_ram=open\n", .{ external.config.fri_config.n_queries, external.config.pow_bits, root.bytes.len, root.stats.proof_ns });
    }
};
fn checkClosure(a: std.mem.Allocator, p: *const Family.Profile.Owned) !void {
    const G = @import("../air/composition_graph_recorder.zig");
    const Q = core.fields.qm31.QM31;
    const public = try Family.Composition.publicValues(a, p);
    defer a.free(public);
    const drawn = try @import("../air/block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(a, p.scope.epoch);
    const inputs = try a.alloc(Q, public.len + drawn.len);
    defer a.free(inputs);
    @memcpy(inputs[0..public.len], public);
    @memcpy(inputs[public.len..], &drawn);
    var builder = G.Builder.init(a);
    defer builder.deinit();
    const symbols = try a.alloc(G.Scalar, inputs.len);
    defer a.free(symbols);
    for (symbols) |*value| value.* = (try builder.input()).value;
    var draws: [53][2]G.Scalar = undefined;
    for (&draws, 0..) |*pair, i| pair.* = symbols[public.len + 2 * i ..][0..2].*;
    const physical = public.len - p.layout.n * 416;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try @import("../air/block_v8_endpoint_group_closure_v1.zig").record(a, &builder, p, symbols[0..physical], symbols[physical..public.len], draws);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    try circuit.evaluateInto(inputs, values);
    // Equal and opposite member RAM residuals preserve their aggregate but
    // fail the actual per-member circuit equations.
    const ep0 = 8 + p.claims.members[0].native.len;
    const ep1 = ep0 + 11 + 8 + p.claims.members[1].native.len;
    inputs[ep0] = inputs[ep0].add(Q.one());
    inputs[ep1] = inputs[ep1].sub(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs, values));
    inputs[ep0] = inputs[ep0].sub(Q.one());
    inputs[ep1] = inputs[ep1].add(Q.one());
    // Each local-draw global plane stays OPEN; later bridge/global equations
    // must authenticate the same committed endpoint columns under their draw.
    inputs[ep0 + 1] = inputs[ep0 + 1].add(Q.one());
    try circuit.evaluateInto(inputs, values);
    inputs[ep0 + 1] = inputs[ep0 + 1].sub(Q.one());
    inputs[physical] = inputs[physical].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs, values));
    inputs[physical] = inputs[physical].sub(Q.one());
    try circuit.evaluateInto(inputs, values);
}
test "canonical Group original recursive proof closes members and preserves endpoint roots" {
    try @import("../../prover/tests/block_v8_endpoint_group_execution_test.zig").qualifyPipelineWithObserver(.compact_v1, Observer);
}
