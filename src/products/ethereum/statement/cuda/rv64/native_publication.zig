//! Publication after every device verdict passed. Only transport metadata,
//! claims/frame slicing and file writes: no proof production or verification.
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const LF = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_leaf_wire;
const S2 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const TF = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.truth_factory;
const NCB = @import("jobs/native_class_build.zig");
const RC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.recursion_classes;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Bundle = CPU.rv64_gkr_coordinator.Bundle;
const CpuEncoded = std.meta.Child(@FieldType(Bundle, "cpus"));
const TruthEncoded = std.meta.Child(@FieldType(Bundle, "truths"));
const Truth = std.meta.Child(@FieldType(ProductCPU.rv64_ethereum_keys.Owner, "truths"));
const Root = CPU.rv64_om31_services_root;
const Wrap = CPU.rv64_om31_execution_wrap;
const Bounds = CPU.rv64_gkr_source_bounds;

pub const Authority = struct {
    native: *const NCB.Inventory,
    truths: []const Truth,
    inventory: *const CPU.rv64_gkr_execution.Inventory,
    native_inputs: []const S2.RequestInputs,
    truth_inputs: []const TF.Request,
    recursion: RC.Classes,
    bounds: *const Bounds.Report,
    profile: CPU.rv64_om31_security_candidate.Profile,
    keccak_uniform_throughput: bool,
};

fn find(p: G.Publication, kind: G.ProofKind, ordinal: usize) !G.Published {
    for (p.proofs) |proof| if (proof.id.kind == kind and proof.id.ordinal == ordinal) return proof;
    return error.GpuNativePublicationProofMissing;
}
fn felts(a: std.mem.Allocator, words: []const u32) ![]O {
    if (words.len % 8 != 0) return error.GpuNativePublicationClaimsShape;
    const out = try a.alloc(O, words.len / 8);
    errdefer a.free(out);
    for (out, 0..) |*value, i| {
        var coordinates: [8]M = undefined;
        for (&coordinates, words[8 * i ..][0..8]) |*m, word| {
            if (word >= LF.modulus) return error.GpuNativePublicationNoncanonical;
            m.* = M.fromCanonical(word);
        }
        value.* = O.fromM31Array(coordinates);
    }
    return out;
}
fn slot(p: G.Publication, s: G.Exchange.Slot, words: usize) ![]const u32 {
    if (words > s.words or @as(u64, s.offset) + words > p.exchange.len) return error.GpuNativePublicationExchangeBounds;
    return p.exchange[s.offset..][0..words];
}
fn frame(a: std.mem.Allocator, program: *const LF.Program, proof: G.Published, digest: []const u32, receipt: []const u32) !struct { words: []u32, claims: []O } {
    const claims = try LF.claimWords(program, proof.region);
    const image = proof.region[program.words[10]..][0..program.words[11]];
    return .{ .words = try LF.frameWords(a, program, .{ &.{}, &.{}, digest, receipt, claims, image }), .claims = try felts(a, claims) };
}
fn json(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const text = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(text);
    try dir.writeFile(.{ .sub_path = name, .data = text });
}
/// Eight QM31 raw-u32 outputs in the canonical outer proof envelope. Read
/// only public framing after the device encoder and all node checks passed.
fn nodeDigest(bytes: []const u8) ![32]u8 {
    if (bytes.len < (19 + 32) * 4 or std.mem.readInt(u32, bytes[72..76], .little) != 8) return error.GpuNativePublicationNodeShape;
    var digest: [32]u8 = undefined;
    for (0..8) |i| {
        const b = bytes[76 + 16 * i ..][0..16];
        const lo = std.mem.readInt(u32, b[0..4], .little);
        const hi = std.mem.readInt(u32, b[4..8], .little);
        if (lo > 65535 or hi > 65535 or std.mem.readInt(u64, b[8..16], .little) != 0) return error.GpuNativePublicationNodeShape;
        std.mem.writeInt(u32, digest[4 * i ..][0..4], lo | hi << 16, .little);
    }
    return digest;
}

test "node metadata reads raw-u32 outputs and rejects malformed public envelopes" {
    const t = std.testing;
    var bytes: [204]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[72..76], 8, .little);
    var expected: [32]u8 = undefined;
    for (0..8) |i| {
        const word: u32 = 0x89ab_1234 + @as(u32, @intCast(i));
        std.mem.writeInt(u32, bytes[76 + 16 * i ..][0..4], word & 65535, .little);
        std.mem.writeInt(u32, bytes[80 + 16 * i ..][0..4], word >> 16, .little);
        std.mem.writeInt(u32, expected[4 * i ..][0..4], word, .little);
    }
    try t.expectEqualSlices(u8, &expected, &try nodeDigest(&bytes));
    try t.expectError(error.GpuNativePublicationNodeShape, nodeDigest(bytes[0..203]));
    std.mem.writeInt(u32, bytes[84..88], 1, .little);
    try t.expectError(error.GpuNativePublicationNodeShape, nodeDigest(&bytes));
    std.mem.writeInt(u32, bytes[84..88], 0, .little);
    std.mem.writeInt(u32, bytes[76..80], 65536, .little);
    try t.expectError(error.GpuNativePublicationNodeShape, nodeDigest(&bytes));
}

pub fn write(a: std.mem.Allocator, authority: Authority, ctx: *const G.RequestContext, original: G.Publication, output: [43]u8) !void {
    // Linux O_PATH directory descriptors (the spool's default) cannot be
    // fsync'd. The canonical bundle writer requires a readable descriptor.
    var durable = try original.dir.openDir(".", .{ .iterate = true });
    defer durable.close();
    var p = original;
    p.dir = durable;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ar = arena.allocator();
    const inv = authority.native;
    const n = inv.count();
    const cpus = try ar.alloc(CpuEncoded, n);
    const truths = try ar.alloc(TruthEncoded, authority.truths.len);
    const setups = try ar.alloc(*const NCB.Setup, n);
    const cpu_frames = try ar.alloc(Root.CpuFrame, n);
    const truth_frames = try ar.alloc([]const u32, truths.len);
    const digest = try slot(p, ctx.exchange.seal(), 8);
    for (cpus, setups, cpu_frames, authority.native_inputs, 0..) |*encoded, *setup, *public, input, i| {
        const proof = try find(p, .native_segment, i);
        const program = input.leaf_program orelse return error.NativeLeafProgramNotWarmed;
        const receipt = try slot(p, try ctx.exchange.receipt(@intCast(i)), 8);
        const data = try frame(ar, program, proof, digest, receipt);
        const count = authority.inventory.workers[i].local_instances.?.len;
        const raw = try slot(p, try ctx.exchange.claims(@intCast(i)), 16 * count);
        const flat = try felts(ar, raw);
        const marginals = try ar.alloc([]const O, count);
        for (marginals, 0..) |*pair, j| pair.* = flat[2 * j ..][0..2];
        encoded.* = .{ .bytes = @constCast(proof.bytes), .claims = data.claims };
        setup.* = inv.setup(i);
        public.* = .{ .words = data.words, .physical_claims = data.claims, .terminal_marginals = marginals };
    }
    for (truths, truth_frames, authority.truth_inputs, 0..) |*encoded, *public, request, i| {
        const proof = try find(p, .truth, i);
        const program = request.leaf_program orelse return error.NativeLeafProgramNotWarmed;
        const data = try frame(ar, program, proof, digest, &.{});
        encoded.* = .{ .bytes = @constCast(proof.bytes), .claims = data.claims };
        public.* = data.words;
    }
    // Borrowed views; never call Bundle.deinit on the shared request authority
    // or the readback mirrors. Only this publication arena owns the containers.
    const bundle = Bundle{ .requests = @constCast(inv.requests), .stage_one_bytes = @constCast((try find(p, .request, 0)).bytes), .cpus = cpus, .truths = truths };
    try CPU.rv64_gkr_bundle_wire.write(ar, p.dir, setups, authority.truths, &bundle);

    const plan = try CPU.rv64_om31_ready_dag.Plan.initArity(n + truths.len, 4);
    const nodes = try ar.alloc(Wrap.Node, plan.count);
    for (nodes, plan.nodes[0..plan.count], 0..) |*node, spec, i| {
        const kind: G.ProofKind = if (spec.isLeaf()) .leaf else if (i == plan.root) .root else .fold;
        const proof = try find(p, kind, i);
        node.* = .{ .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .left = spec.left(), .right = spec.right(), .authority = try authority.recursion.identity(p.block, i), .digest = try nodeDigest(proof.bytes) };
    }
    try p.dir.makePath("recursion-om31");
    var recursive = try p.dir.openDir("recursion-om31", .{});
    defer recursive.close();
    const tree = try Wrap.treeJson(ar, &plan, nodes, .{ .cpus = cpu_frames, .truths = truth_frames });
    try recursive.writeFile(.{ .sub_path = "tree.json", .data = tree });
    const b = authority.bounds;
    try json(ar, p.dir, "candidate-source-bounds.json", .{ .profile = ProductCPU.rv64_ethereum_gkr_main.candidateLabel(authority.profile), .security_qualified = false, .accounting_profile = b.accounting_profile, .shape = b.shape, .cpu_scopes = b.cpu_scopes, .truth_scopes = b.truth_scopes, .global_signed = b.global_signed, .global_denominator_slots = b.global_denominator_slots, .lookup_only_conditional_degrees = b.conditional_degrees, .transcript_round_bound_qualified = b.transcript_round_bound_qualified, .secp_polynomial_error_budget_qualified = b.secp_polynomial_error_budget_qualified });
    try json(ar, p.dir, "report.json", .{ .profile = ProductCPU.rv64_ethereum_gkr_main.candidateLabel(authority.profile), .security_profile = authority.profile.name(), .security_qualified = false, .completed_ethereum_block = true, .capture_source = "in_process_execution", .keccak_uniform_throughput = authority.keccak_uniform_throughput, .retained_main = @as(?u64, null), .output = output, .cpu_proofs = n, .truth_proofs = truths.len, .capture_ns = @as(?u64, null), .setup_ns = @as(u64, 0), .prove_ns = @as(?u64, null), .same_process_verify_ns = @as(?u64, null), .total_before_report_ns = @as(?u64, null), .device_checks_accepted = true, .verification = "fresh CPU receiver runs off path", .timing_scope = "request wall and GPU spans are in m8-jobs.json; unavailable legacy stage partitions remain null" });
    try json(ar, p.dir, "combined-report.json", .{ .schema = 1, .accepted = true, .completed_ethereum_block = true, .acceptance_basis = "all request-slab device verdicts; fresh CPU receiver required for qualification", .security_qualified = false, .profile = ProductCPU.rv64_ethereum_gkr_main.candidateLabel(authority.profile), .recursion_streamed = true, .native_bundle_reload = false, .restored_recursive_proofs = false, .recursion_ns = @as(?u64, null), .native_prove_ns = @as(?u64, null), .native_verify_ns = @as(?u64, null), .setup_breakdown = .{ .scope = "all class construction is charged to service initialization" }, .recursive = .{ .leaf_proofs = n + truths.len, .fold_proofs = plan.count - n - truths.len, .fold_arity = 4, .root_node = plan.root, .root_digest = nodes[plan.root].digest, .root_authority = nodes[plan.root].authority } });
    try std.posix.fsync(p.dir.fd);
}
