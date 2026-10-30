const std = @import("std");
const core = @import("stwo_core");
const L = @import("../block_v8_endpoint_recursive_adapter_v1.zig").For(.local_open);
const B = @import("../block_v8_endpoint_bridge_recursive_v1.zig");
const G = @import("../block_v8_compact_ram_recursive_v1.zig");
const Source = @import("../block_v8_endpoint_join_source_v1.zig");
const Pipeline = @import("../block_v8_endpoint_join_pipeline_v1.zig");
const Run = @import("../../prover/block_v8_endpoint_local_compact_execution_v1.zig");
const Metadata = @import("../../prover/block_v8_endpoint_local_statement_wire_v1.zig");
const Codec = @import("../../prover/block_v8_endpoint_local_codec_v1.zig");
const Window = @import("../../prover/block_v7_real_window_policy_v2.zig");
const BridgeScope = @import("../../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const External = @import("../../prover/block_v8_endpoint_local_bundle_v1.zig").External;
const Observer = struct {
    pub fn observeTrain(a: std.mem.Allocator, dir: std.fs.Dir, external: External, result: *const Run.Result) !void {
        if (result.verified.cohorts != 2 or result.bridges.len != 1) return error.ExpectedTinyTwoCohorts;
        var window = try Window.Owned.deriveCohortsForAddresses(a, external.elf, external.incoming, external.outgoing, external.trusted, result.cohort_policy, result.selected_initial_addresses, .{});
        defer window.deinit();
        const trusted = @import("../../prover/block_v8_endpoint_local_scope_v1.zig").Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = 2 };
        const provider = Run.FileProvider{ .directory = dir, .bridges = result.bridges, .source_count = 2, .metadata_bytes = 16 << 20, .proof_bytes = 128 << 20 };
        var first = try provider.loadLocal(a, 0);
        defer first.deinit();
        var second = try provider.loadLocal(a, 1);
        defer second.deinit();
        const meta0 = try Metadata.decode(a, first.metadata, trusted, .{});
        var meta0_live = true;
        defer if (meta0_live) meta0.deinit();
        const meta1 = try Metadata.decode(a, second.metadata, trusted, .{});
        var meta1_live = true;
        defer if (meta1_live) meta1.deinit();
        var decoded0 = try Codec.decode(a, first.proof, trusted, meta0.input, .{});
        var decoded0_live = true;
        defer if (decoded0_live) decoded0.deinit();
        var decoded1 = try Codec.decode(a, second.proof, trusted, meta1.input, .{});
        var decoded1_live = true;
        defer if (decoded1_live) decoded1.deinit();
        const p0 = try L.Profile.Owned.derive(a, meta0, decoded0.claims, .{});
        var p0_live = true;
        defer if (p0_live) p0.deinit();
        const p1 = try L.Profile.Owned.derive(a, meta1, decoded1.claims, .{});
        var p1_live = true;
        defer if (p1_live) p1.deinit();
        const s0 = p0.scope.source();
        const s1 = p1.scope.source();
        const pins = [_]BridgeScope.Source{ .{ .local_identity = s0.local_identity, .local_epoch = s0.local_epoch, .endpoint_root = s0.endpoint_root, .endpoint_count = s0.endpoint_count, .policy = s0.policy }, .{ .local_identity = s1.local_identity, .local_epoch = s1.local_epoch, .endpoint_root = s1.endpoint_root, .endpoint_count = s1.endpoint_count, .policy = s1.policy } };
        const policy = G.Original.Policy{ .window = &window, .config = external.config, .event_count = result.global_memory.event_count };
        const bm = try B.Statement.Owned.init(a, .{ .config = external.config, .block_statement = try policy.digest() }, .{ .sources = &pins, .global_memory = try policy.entry(result.global_memory.roots), .batch_first = 0, .batch_count = 2 });
        var bm_live = true;
        defer if (bm_live) bm.deinit();
        const gm = try G.Statement.Owned.init(a, .{ .config = external.config, .policy = policy }, .{ .epoch = bm.scope.epoch, .entries = bm.scope.entries, .roots = result.global_memory.roots });
        var gm_live = true;
        defer if (gm_live) gm.deinit();
        const bp = try B.Profile.Owned.derive(a, bm, result.bridges[0].claims, .{});
        var bp_live = true;
        defer if (bp_live) bp.deinit();
        const gp = try G.Profile.Owned.derive(a, gm, result.global_memory.claims, .{});
        var gp_live = true;
        defer if (gp_live) gp.deinit();
        const sources = [_]Source.Source{ .{ .local = p0 }, .{ .local = p1 }, .{ .bridge = bp }, .{ .global = gp } };
        var extra: [264]core.fields.qm31.QM31 = undefined;
        const initial = window.boundary.initial_cpu;
        const final = window.boundary.final_cpu;
        var words: [66]u32 = undefined;
        words[0] = initial.pc;
        @memcpy(words[1..33], &initial.regs);
        words[33] = final.pc;
        @memcpy(words[34..66], &final.regs);
        for (words, 0..) |word, i| for (0..4) |byte| {
            extra[4 * i + byte] = core.fields.qm31.QM31.fromBase(core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(8 * byte))) & 255));
        };
        const Claims = struct { local0: L.Ledger.Claims, local1: L.Ledger.Claims, bridge: []const core.fields.qm31.QM31, global: G.Original.Claims };
        const claims = Claims{ .local0 = decoded0.claims, .local1 = decoded1.claims, .bridge = result.bridges[0].claims, .global = result.global_memory.claims };
        var claim_writer = @import("../../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
        defer claim_writer.deinit();
        var remaining: usize = 1 << 20;
        try @import("../../prover/block_v7_union_claim_wire_v1.zig").encode(Claims, &claim_writer, claims, &remaining);
        var claim_arena = std.heap.ArenaAllocator.init(a);
        defer claim_arena.deinit();
        var cursor = @import("../../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = claim_writer.bytes.items };
        remaining = 1 << 20;
        const received_claims = try @import("../../prover/block_v7_union_claim_wire_v1.zig").decode(Claims, claim_arena.allocator(), &cursor, &remaining);
        try std.testing.expectEqual(claim_writer.bytes.items.len, cursor.position);
        const global_g_repartition = std.posix.getenv("STWO_B8_JOIN_GLOBAL_G") != null;
        var root = blk: {
            var c0 = try L.Original.verifyAndCapture(a, trusted, meta0.input, &decoded0.stark, decoded0.claims, .{});
            defer c0.deinit();
            var c1 = try L.Original.verifyAndCapture(a, trusted, meta1.input, &decoded1.stark, decoded1.claims, .{});
            defer c1.deinit();
            var bc = try B.Original.verifyConditionalAndCapture(a, bm.scope, &result.bridges[0].stark, result.bridges[0].claims, .{});
            defer bc.deinit();
            var gc = try G.Original.verifyAndCaptureConditional(a, policy, bm.scope.epoch, bm.scope.entries, &result.global_memory, .{});
            defer gc.deinit();
            const captures = [_]Source.Capture{ .{ .local = &c0 }, .{ .local = &c1 }, .{ .bridge = &bc }, .{ .global = &gc } };
            const source_workers: u8 = if (std.posix.getenv("STWO_B8_JOIN_SOURCE_WORKERS")) |text| try std.fmt.parseInt(u8, text, 10) else 1;
            if (source_workers > 1) {
                const bad = [_]Source.Capture{ .{ .local = &c0 }, .{ .bridge = &bc } };
                try std.testing.expectError(error.JoinCaptureFamilyMismatch, Source.prepareBatch(a, sources[0..2], &bad, source_workers));
            }
            break :blk try Pipeline.produceWithOptions(a, &sources, &captures, &extra, .csp_q70_pow26, .{ .source_workers = source_workers, .global_g_repartition = global_g_repartition });
        };
        defer root.deinit();
        var golden: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&golden, "8865bd8fc37c492862ca52ec473514738140075a076da78871720c9d93a6b50e");
        var actual: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(root.bytes, &actual, .{});
        if (!global_g_repartition) try std.testing.expectEqualDeep(golden, actual);
        const fresh0 = try Metadata.decode(a, first.metadata, trusted, .{});
        defer fresh0.deinit();
        const fresh1 = try Metadata.decode(a, second.metadata, trusted, .{});
        defer fresh1.deinit();
        const freshbm = try B.Statement.Owned.init(a, bm.trusted, bm.input);
        defer freshbm.deinit();
        var freshwindow = try Window.Owned.deriveCohortsForAddresses(a, external.elf, external.incoming, external.outgoing, external.trusted, result.cohort_policy, result.selected_initial_addresses, .{});
        defer freshwindow.deinit();
        const freshgm = try G.Statement.Owned.init(a, .{ .config = external.config, .policy = .{ .window = &freshwindow, .config = external.config, .event_count = result.global_memory.event_count } }, gm.input);
        defer freshgm.deinit();
        p0.deinit();
        p0_live = false;
        p1.deinit();
        p1_live = false;
        bp.deinit();
        bp_live = false;
        gp.deinit();
        gp_live = false;
        decoded0.deinit();
        decoded0_live = false;
        decoded1.deinit();
        decoded1_live = false;
        meta0.deinit();
        meta0_live = false;
        meta1.deinit();
        meta1_live = false;
        bm.deinit();
        bm_live = false;
        gm.deinit();
        gm_live = false;
        const admitted = [_]Source.Admission{ .{ .local = .{ .statement = fresh0, .claims = received_claims.local0 } }, .{ .local = .{ .statement = fresh1, .claims = received_claims.local1 } }, .{ .bridge = .{ .statement = freshbm, .claims = received_claims.bridge } }, .{ .global = .{ .statement = freshgm, .claims = received_claims.global } } };
        var verified = try Pipeline.verifyAdmittedWithOptions(a, root.bytes, &admitted, &extra, .csp_q70_pow26, .{ .global_g_repartition = global_g_repartition });
        defer verified.deinit();
        try archive(a, root.bytes, claim_writer.bytes.items, external, first.metadata, second.metadata, result, root.whole_ns, root.proof_ns);
        std.debug.print("B8_ENDPOINT_SINGLE_DAG queries=70 pow=26 cohorts=2 local_bodies=2 bridge_bodies=1 compact_global_bodies=1 bytes={d} proof_ns={d} whole_ns={d} snapshot_delta_public_ports=0 freshly_verified=true\\n", .{ root.bytes.len, root.proof_ns, root.whole_ns });
    }
};
test "canonical two cohort actual one DAG root verifies local bridge compact global and CPU chain" {
    try @import("../../prover/tests/block_v8_endpoint_local_execution_test.zig").qualifyWithObserver(true, Observer);
}

fn archive(a: std.mem.Allocator, root: []const u8, claims: []const u8, external: External, meta0: []const u8, meta1: []const u8, result: *const Run.Result, whole_ns: u64, proof_ns: u64) !void {
    const dest = std.process.getEnvVarOwned(a, "STWO_B8_ENDPOINT_JOIN_ARTIFACT_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer a.free(dest);
    try std.fs.cwd().makePath(dest);
    var dir = try std.fs.cwd().openDir(dest, .{});
    defer dir.close();
    if (dir.access("root.proof", .{})) |_| return error.RefuseOverwriteEndpointJoinArtifact else |err| if (err != error.FileNotFound) return err;
    try dir.writeFile(.{ .sub_path = "root.proof", .data = root });
    try dir.writeFile(.{ .sub_path = "physical-claims.bin", .data = claims });
    try dir.writeFile(.{ .sub_path = "local-0.json", .data = meta0 });
    try dir.writeFile(.{ .sub_path = "local-1.json", .data = meta1 });
    try dir.writeFile(.{ .sub_path = "guest.elf", .data = external.elf });
    const incoming = try external.incoming.encode(a);
    defer a.free(incoming);
    const outgoing = try external.outgoing.encode(a);
    defer a.free(outgoing);
    try dir.writeFile(.{ .sub_path = "incoming.b7win", .data = incoming });
    try dir.writeFile(.{ .sub_path = "outgoing.b7win", .data = outgoing });
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(root, &hash, .{});
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-v8-endpoint-single-dag-qualification-v1", .scope = "declared_nonterminal_window_recursive_closed", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .cohorts = @as(u32, 2), .cycles = @as(u32, 8), .local_original_bodies = @as(u32, 2), .bridge_original_bodies = @as(u32, 1), .compact_global_original_bodies = @as(u32, 1), .snapshot_delta_public_ports = @as(u32, 0), .root_bytes = root.len, .root_sha256 = std.fmt.bytesToHex(hash, .lower), .proof_ns = proof_ns, .production_whole_ns = whole_ns, .timing_isolated = false, .fresh_receiver = true, .producer_profiles_original_local_proofs_destroyed = true, .external = external.trusted, .selected_addresses = result.selected_initial_addresses, .global_roots = result.global_memory.roots, .cohort_policy = result.cohort_policy }, .{});
    defer a.free(report);
    try dir.writeFile(.{ .sub_path = "qualification.json", .data = report });
}

test "endpoint join closure graph rejects changed transition root and CPU coordinates" {
    const Public = @import("../block_v8_endpoint_join_public_v1.zig");
    const Graph = @import("../block_v8_endpoint_join_graph_v1.zig");
    const a = std.testing.allocator;
    var children: [4]Source.Value = undefined;
    var count: usize = 0;
    defer for (children[0..count]) |*child| child.deinit();
    for (&children, [_]usize{ 6, 6, 3, 4 }, 0..) |*child, roots, i| {
        const words = try a.alloc(u32, 8 * roots);
        @memset(words, 0);
        const public = try a.alloc(core.fields.qm31.QM31, if (i < 2) 416 else if (i == 2) 3 else 10);
        @memset(public, core.fields.qm31.QM31.zero());
        child.* = .{ .allocator = a, .template = @splat(1), .statement = .{ .allocator = a, .words = words, .felts = &.{}, .first = &.{}, .claims = &.{}, .sealed_offset = 0, .roots_offset = @splat(0) }, .public = public, .roots_count = roots };
        count += 1;
    }
    const extra: [264]core.fields.qm31.QM31 = @splat(core.fields.qm31.QM31.zero());
    const values = Public.Values{ .children = &children, .extra = &extra };
    var graph = try Graph.Owned.compile(a, values, 2);
    defer graph.deinit();
    const inputs = try a.alloc(core.fields.qm31.QM31, graph.sources.len);
    defer a.free(inputs);
    const evaluation = try a.alloc(core.fields.qm31.QM31, graph.circuit.nodes.len);
    defer a.free(evaluation);
    try graphInputs(values, graph.sources, inputs);
    try graph.circuit.evaluateInto(inputs, evaluation);
    children[3].public[0] = core.fields.qm31.QM31.one();
    try graphInputs(values, graph.sources, inputs);
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, evaluation));
    children[3].public[0] = core.fields.qm31.QM31.zero();
    children[0].statement.words[16] = 1;
    try graphInputs(values, graph.sources, inputs);
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, evaluation));
    children[0].statement.words[16] = 0;
    children[0].public[4 * 35] = core.fields.qm31.QM31.one();
    try graphInputs(values, graph.sources, inputs);
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, evaluation));
}
fn graphInputs(values: @import("../block_v8_endpoint_join_public_v1.zig").Values, sources: []const @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire, inputs: []core.fields.qm31.QM31) !void {
    for (sources, inputs) |wire, *value| value.* = core.fields.qm31.QM31.fromM31Array(try (@import("../block_v8_endpoint_join_public_v1.zig").View{ .values = values }).at(wire));
}
