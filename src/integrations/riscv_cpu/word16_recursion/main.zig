//! Native-verified shapes, never recursive acceptance or a circuit cost claim.
const std = @import("std");
const core = @import("stwo_core");
const wire = @import("stwo_proof_wire");
const Request = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Program = @import("../word16_execution/program.zig").Program;
const Suite = @import("../word16_execution/pcs_suite.zig").Suite;
const Metrics = @import("../word16_execution/pcs_metrics.zig");
const G = @import("../word16_global_execution/protocol.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const W = @import("../word16_global_execution/services/wire.zig");
const Adapters = @import("../word16_global_execution/services/air_components.zig");
const Components = @import("../word16_execution/components.zig").Components;
const Keys = @import("../word16_global_execution/ethereum/keys.zig").Owner;
const Receiver = @import("../word16_global_execution/ethereum/receiver.zig");
const Describe = @import("shape.zig");
const Row = struct { ordinal: usize, kind: []const u8, shape: Describe.Report, serialized: Metrics.Report };
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const report_allocator = arena.allocator();
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 5) return error.ExpectedConfigBundleFullOrPrefixAndF1OrF4;
    const full = if (std.mem.eql(u8, args[3], "full")) true else if (std.mem.eql(u8, args[3], "prefix")) false else return error.InvalidDiagnosticCompletionMode;
    const suite = if (std.mem.eql(u8, args[4], "f1")) Suite.production() else if (std.mem.eql(u8, args[4], "f4")) Suite.experimentalFold4() else return error.InvalidDiagnosticSuite;
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer config.deinit();
    var image = try Image.Owner.init(a, config.value);
    defer image.deinit();
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    var loaded = try W.read(a, dir, .{ .max_cpus = 32, .max_truths = 32, .max_metadata_bytes = 4 << 20, .max_total_proof_bytes = 256 << 20, .max_native_row_sum = 1 << 28, .max_total_steps = config.value.max_steps });
    defer loaded.deinit(a);
    const bundle = &loaded.bundle;
    if (bundle.cpus.len + bundle.truths.len > 64) return error.DiagnosticPhysicalProofLimit;
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const expected = try Receiver.expected(&image, program.identity, bundle, config.value.max_steps, config.value.batch_steps, full);
    var keys = try Keys.initWithSuite(a, &image, loaded.cpu_declarations, loaded.truth_declarations, true, suite);
    defer keys.deinit();
    // All roots, local and global claims, genesis, boundaries and completion
    // are independently checked before any shape is reported as native-verified.
    _ = try Receiver.verify(a, &image, &keys, bundle, config.value.max_steps, config.value.batch_steps, full);
    const rows = try report_allocator.alloc(Row, bundle.cpus.len + bundle.truths.len);
    const requests = try a.alloc(P.Request, bundle.cpus.len);
    defer a.free(requests);
    for (requests, bundle.cpus) |*r, c| r.* = c.request;
    const common = try P.shared(&bundle.manifest);
    var before: u64 = 0;
    for (keys.cpus, bundle.cpus, 0..) |s, encoded, index| {
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, suite.config());
        defer verifier.deinit(a);
        var channel = G.T.P.Channel{};
        const first_ids = try P.firstIds(requests, index);
        try P.beginCpu(&channel, s, encoded.request, expected, index, before, first_ids);
        before += encoded.request.base.cpu.steps;
        for (0..2) |tree| {
            const logs = try s.logs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[tree], logs, &channel);
        }
        const ch = try P.drawCpu(&channel, &bundle.manifest, index);
        var base = try Components.init(&s.materials, encoded.request.base, ch, encoded.claims.base);
        var bridges = Adapters.Bridges.init(s, encoded.request.calls, first_ids, ch, common, encoded.claims.extras);
        const handles = try Adapters.cpuVerifierHandles(a, &base, &bridges);
        defer a.free(handles);
        rows[index] = .{ .ordinal = index, .kind = "cpu_with_bridges", .shape = try Describe.describe(report_allocator, handles, suite.config(), &proof), .serialized = try Metrics.inspect(a, encoded.bytes) };
    }
    for (keys.truths, bundle.truths, 0..) |truth, encoded, k| {
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, suite.config());
        defer verifier.deinit(a);
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, expected, k);
        for (0..2) |tree| {
            const logs = try truth.logs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[tree], logs, &channel);
        }
        const ch = try P.drawTruth(&channel, &bundle.manifest, truth, k);
        var components = try Adapters.TruthComponents.init(truth, ch, encoded.claims);
        const handles = components.verifiers();
        rows[keys.cpus.len + k] = .{ .ordinal = keys.cpus.len + k, .kind = @tagName(truth.family()), .shape = try Describe.describe(report_allocator, &handles, suite.config(), &proof), .serialized = try Metrics.inspect(a, encoded.bytes) };
    }
    const json = try std.json.Stringify.valueAlloc(report_allocator, .{ .scope = "Native-verified Word16 proof metadata; no recursive circuit, gates, acceptance or security estimate", .native_full_or_prefix_verified = true, .completed_ethereum_block = full, .recursive_proof_verified = false, .circuit_built = false, .gate_counts_measured = false, .suite = suite.config(), .physical_proofs = rows }, .{ .whitespace = .indent_2 });
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
