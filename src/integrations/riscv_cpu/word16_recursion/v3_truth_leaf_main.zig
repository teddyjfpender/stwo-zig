//! Wraps every admitted v3 truth proof (SHA-256, arith256_mod) of a native
//! verified Word16 services bundle into an in-circuit leaf: native receiver
//! first, then per truth native capture, circuit build, and optionally the
//! pad to the production target and a CPU circuit proof. Reports gate counts
//! and timings as JSON. The cross-leaf Wire35 sum is closed with the CPU
//! bridge claims taken from the natively verified bundle (CPU leaves for the
//! Word16 lane do not exist yet), so `wire35_closed_with_native_cpu_terms`
//! is not a recursive acceptance claim.
//!
//!   rv64-v3-truth-leaf TRUSTED_CONFIG BUNDLE_DIR full|prefix [prove]
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_proof_wire");
const Request = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Program = @import("../word16_execution/program.zig").Program;
const W = @import("../word16_global_execution/services/wire.zig");
const G = @import("../word16_global_execution/protocol.zig");
const Keys = @import("../word16_global_execution/ethereum/keys.zig").Owner;
const Receiver = @import("../word16_global_execution/ethereum/receiver.zig");
const Leaf = @import("../rv64_recursion/services_truth_leaf.zig");
const fold_root = @import("../rv64_recursion/fold_root.zig");
const Q = core.fields.qm31.QM31;
const Context = circuit.builder.Context(Q);
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

const Row = struct {
    ordinal: usize,
    family: []const u8,
    log: u32,
    calls: u32,
    native_verify_ms: f64,
    build_ms: f64,
    raw_gates: circuit.builder.context.GateCounts,
    n_vars: u32,
    valid: bool,
    channel_matches_native: bool,
    output_digest: [8]u32,
    pad_ms: ?f64 = null,
    prove_ms: ?f64 = null,
    proof_bytes: ?usize = null,
};

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1e6;
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4 and args.len != 5) return error.ExpectedConfigBundleFullOrPrefixAndOptionalProve;
    const full = if (std.mem.eql(u8, args[3], "full")) true else if (std.mem.eql(u8, args[3], "prefix")) false else return error.InvalidCompletionMode;
    const prove = args.len == 5 and std.mem.eql(u8, args[4], "prove");
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer config.deinit();
    var image = try Image.Owner.init(a, config.value);
    defer image.deinit();
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    var loaded = try W.read(a, dir, .{ .max_cpus = 64, .max_truths = 32, .max_metadata_bytes = 4 << 20, .max_total_proof_bytes = 512 << 20, .max_native_row_sum = 1 << 29, .max_total_steps = config.value.max_steps });
    defer loaded.deinit(a);
    const bundle = &loaded.bundle;
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const expected = try Receiver.expected(&image, program.identity, bundle, config.value.max_steps, config.value.batch_steps, full);
    var keys = try Keys.init(a, &image, loaded.cpu_declarations, loaded.truth_declarations);
    defer keys.deinit();
    var timer = try std.time.Timer.start();
    _ = try Receiver.verify(a, &image, &keys, bundle, config.value.max_steps, config.value.batch_steps, full);
    const receiver_ns = timer.lap();
    const assets: ?*fold_root.Assets = if (prove) try fold_root.Assets.init(a) else null;
    defer if (assets) |x| x.deinit();
    var rows = std.ArrayListUnmanaged(Row).empty;
    var leaf_wire = Q.zero();
    var all_v3 = true;
    for (keys.truths, bundle.truths, 0..) |truth, encoded, k| {
        if (truth != .sha256 and truth != .arith256_mod) {
            all_v3 = false;
            continue;
        }
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        timer.reset();
        var verified = try Leaf.verifyNative(a, truth, k, keys.cpus.len, expected, &bundle.manifest, encoded.claims, &proof);
        defer verified.deinit(a);
        const native_ns = timer.lap();
        const public = try Leaf.Public.fromTruth(truth, k, expected, &bundle.manifest, encoded.claims);
        var ctx = try Context.init(a, circuit.common.component_list.N_RESERVED);
        var ctx_owned = true;
        defer if (ctx_owned) ctx.deinit();
        const built = try Leaf.build(arena, &ctx, public, truth.key().root, truth.key().suite.config(), &proof, &verified.capture);
        try ctx.finalize(false);
        const build_ns = timer.lap();
        if (!built.valid or !try ctx.isCircuitValid()) return error.TruthLeafCircuitRejectsProof;
        leaf_wire = leaf_wire.add(try Leaf.checkStatement(built.words, truth, k, keys.cpus.len, expected, &bundle.manifest));
        var row = Row{ .ordinal = k, .family = @tagName(truth.family()), .log = public.log, .calls = public.calls, .native_verify_ms = ms(native_ns), .build_ms = ms(build_ns), .raw_gates = built.gate_counts, .n_vars = built.n_vars, .valid = built.valid, .channel_matches_native = std.mem.eql(u8, &built.channel_digest, &verified.channel.digestBytes()), .output_digest = built.output };
        if (assets) |x| {
            timer.reset();
            try circuit.common.finalize.padToTargets(Q, &ctx, try x.target());
            if (!try ctx.isCircuitValid()) return error.PaddedLeafRejectsProof;
            row.pad_ms = ms(timer.lap());
            var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
            defer pp.deinit(a);
            const pcs_config = PcsConfigV2.fromFriAndTraceSize(try x.circuitFri(), pp.traceLogSize());
            const values = try ctx.intoValues();
            ctx_owned = false;
            defer a.free(values);
            timer.reset();
            var circuit_proof = try circuit_cpu.prove.cpu_provers.internal(a, values, &pp, &x.bundle, pcs_config, circuit_cpu.recursion.fold.default_options);
            defer circuit_proof.deinit();
            row.prove_ms = ms(timer.lap());
            var prepared = try circuit_cpu.verifier_proof.prepare(a, &circuit_proof);
            defer prepared.deinit();
            const bytes = try prepared.serialize(a);
            defer a.free(bytes);
            row.proof_bytes = bytes.len;
        }
        try rows.append(arena, row);
    }
    var cpu_wire = Q.zero();
    for (bundle.cpus) |cpu| cpu_wire = cpu_wire.add(cpu.claims.wire());
    // Secp truths are not wrapped yet; their native claims complete the sum.
    var native_secp_truth = Q.zero();
    for (keys.truths, bundle.truths) |truth, encoded| if (truth == .secp) for (encoded.claims) |q| {
        native_secp_truth = native_secp_truth.add(q);
    };
    const json = try std.json.Stringify.valueAlloc(arena, .{
        .scope = "v3 truth leaves (SHA-256, arith256_mod) built over natively verified proofs; CPU/bridge and v2 truth leaves do not exist yet",
        .native_receiver_accepted = true,
        .native_receiver_ms = ms(receiver_ns),
        .completed_ethereum_block = full,
        .all_truths_wrapped = all_v3,
        .wire35_closed_with_native_cpu_and_secp_terms = leaf_wire.add(cpu_wire).add(native_secp_truth).isZero(),
        .leaves = rows.items,
    }, .{ .whitespace = .indent_2 });
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
