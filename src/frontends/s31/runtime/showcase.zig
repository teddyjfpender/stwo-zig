//! One compiled S31 program and its native host verifier. The source is
//! embedded in this binary, so `verify` cannot substitute another program.
//! This first slice uses the existing value-mode circuit verifier; a lean
//! core-verifier adapter is a later milestone.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const s31 = @import("stwo_s31_prototype");

const QM31 = core.fields.qm31.QM31;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const preprocessed = circuit.common.preprocessed;
const N_COLUMNS = preprocessed.N_PREPROCESSED_COLUMNS;
const embedded_source = @embedFile("s31_program_source");
const projection_bytes = @embedFile("s31_air_projection");
const air_program_bytes = @embedFile("s31_air_programs");
const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";

const VerifierData = struct {
    projection: circuit.air_eval.projection.Projection,
    table: circuit.air_eval.component_table.Table,

    fn init(self: *VerifierData, allocator: std.mem.Allocator) !void {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(projection_bytes, &digest, .{});
        if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), projection_sha256)) return error.VerifierProjectionMismatch;
        self.projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
        errdefer self.projection.deinit();
        self.table = try circuit.air_eval.circuit_components.build(allocator, &self.projection);
    }

    fn deinit(self: *VerifierData) void {
        self.table.deinit();
        self.projection.deinit();
    }
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len > 3) return usage();
    const command = if (args.len >= 2) args[1] else "prove";
    var parsed = try parsedProgram(allocator);
    defer parsed.deinit();
    const default_path = try std.fmt.allocPrint(allocator, "zig-out/s31/{s}.proof", .{parsed.value.name});
    defer allocator.free(default_path);
    const path = if (args.len == 3) args[2] else default_path;
    if (std.mem.eql(u8, command, "prove")) {
        try prove(allocator, path);
    } else if (std.mem.eql(u8, command, "verify")) {
        try verify(allocator, path, &.{ 1, 2, 3, 65535 });
    } else return usage();
}

/// Entry point of the separately installed verifier binary. Its accepted
/// program is fixed by `embedded_source` at compile time.
pub fn verifierMain() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 2 and args.len != 6) {
        std.debug.print("usage: s31-PROGRAM-verifier PROOF [x0 x1 x2 x3]\n", .{});
        return error.InvalidArguments;
    }
    var input = [_]u16{ 1, 2, 3, 65535 };
    if (args.len == 6) {
        for (&input, args[2..]) |*slot, arg| slot.* = try std.fmt.parseInt(u16, arg, 10);
    }
    try verify(allocator, args[1], &input);
}

fn usage() error{InvalidArguments} {
    std.debug.print("usage: s31-showcase [prove|verify] [proof-path]\n", .{});
    return error.InvalidArguments;
}

fn parsedProgram(allocator: std.mem.Allocator) !s31.program.Parsed {
    return s31.program.parse(allocator, embedded_source);
}

fn showcasePcsConfig(trace_log_size: u32) !PcsConfigV2 {
    // Match the Cairo proof's visible FRI settings: 26 PoW bits, blowup 2,
    // last-layer degree bound 1, 70 queries and fold step 1. Other protocol differences
    // remain, so timings are a directional showcase, not a controlled ratio.
    return PcsConfigV2.fromFriAndTraceSize(try FriConfigV2.init(26, 0, 1, 70, 1), trace_log_size);
}

fn sameTopology(a: *const circuit.builder.Circuit, b: *const circuit.builder.Circuit) bool {
    if (a.n_vars != b.n_vars) {
        std.debug.print("topology var count differs: {d} vs {d}\n", .{ a.n_vars, b.n_vars });
        return false;
    }
    inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "triple_xor", "m31_to_u32", "blake_g_gate", "output" }) |field| {
        if (!sameItems(@field(a, field).items, @field(b, field).items)) {
            std.debug.print("topology gate list differs: {s} ({d} vs {d})\n", .{ field, @field(a, field).items.len, @field(b, field).items.len });
            return false;
        }
    }
    return sameItems(a.permutation.ends.items, b.permutation.ends.items) and
        sameItems(a.permutation.inputs.items, b.permutation.inputs.items) and
        sameItems(a.permutation.outputs.items, b.permutation.outputs.items);
}

fn sameItems(a: anytype, b: @TypeOf(a)) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (!std.meta.eql(left, right)) return false;
    return true;
}

fn topology(allocator: std.mem.Allocator, source: s31.program.Program) !preprocessed.PreprocessedCircuit {
    var ctx = try s31.compiler.compile(circuit.builder.NoValue, allocator, source, &.{ 0, 0, 0, 0 });
    defer ctx.deinit();
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &ctx);
    try preprocessed.CircuitView.fromBuilder(&ctx.circuit).validate();
    return preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &ctx.circuit);
}

fn requestFor(
    source: s31.program.Program,
    allocator: std.mem.Allocator,
    pp: *const preprocessed.PreprocessedCircuit,
    input: []const u16,
    columns: *[N_COLUMNS]wire.verify_request.Column,
) !wire.verify_request.VerifyRequest {
    const layout = pp.layout();
    for (layout.entries, columns) |entry, *column| column.* = .{ .id = entry.id, .log_size = entry.log_size };
    const pcs = try showcasePcsConfig(pp.traceLogSize());
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const public_words = try s31.program.expectedPublicWords(allocator, source, input);
    return .{
        .pcs_config = pcs,
        .preprocessed_column_log_sizes = columns,
        .preprocessed_root = core.vcs.blake2_hash.digestToU32s(root),
        .output_digest = public_words,
    };
}

fn prove(allocator: std.mem.Allocator, path: []const u8) !void {
    var total_timer = try std.time.Timer.start();
    var parsed = try parsedProgram(allocator);
    defer parsed.deinit();
    const input = [_]u16{ 1, 2, 3, 65535 };
    var value_ctx = try s31.compiler.compile(QM31, allocator, parsed.value, &input);
    defer value_ctx.deinit();
    var topology_ctx = try s31.compiler.compile(circuit.builder.NoValue, allocator, parsed.value, &.{ 0, 0, 0, 0 });
    defer topology_ctx.deinit();
    if (!sameTopology(&value_ctx.circuit, &topology_ctx.circuit)) return error.ValueDependentTopology;
    const raw = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit));
    try circuit.common.finalize.padContext(QM31, &value_ctx);
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
    if (!sameTopology(&value_ctx.circuit, &topology_ctx.circuit)) return error.ValueDependentTopology;
    if (!try value_ctx.isCircuitValid()) return error.UnsatisfiedCircuit;
    var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    defer pp.deinit(allocator);

    var air_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(air_program_bytes, &air_digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(air_digest, .lower), cpu.air.bundle_sha256)) return error.AirBundleMismatch;
    var bundle = try cpu.air.parse(allocator, air_program_bytes);
    defer bundle.deinit();

    const pcs = try showcasePcsConfig(pp.traceLogSize());
    var committed = try cpu.prove.PreprocessedCommitment.build(allocator, &pp, pcs, .{});
    defer committed.deinit(allocator);
    const setup_ns = total_timer.read();
    var timer = try std.time.Timer.start();
    var proof = try cpu.Internal.prove(allocator, value_ctx.values(), &pp, &bundle, pcs, .{ .preprocessed_commitment = &committed }, {});
    defer proof.deinit();
    const prove_ns = timer.read();
    var prepared = try cpu.verifier_proof.prepare(allocator, &proof);
    defer prepared.deinit();
    const encoded = try prepared.serialize(allocator);
    defer allocator.free(encoded);

    const parent = std.fs.path.dirname(path) orelse ".";
    try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = encoded });
    try verifyBytes(allocator, parsed.value, &pp, &input, encoded);
    const total_ns = total_timer.read();
    const padded = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit));
    const public_words = try s31.program.expectedPublicWords(allocator, parsed.value, &input);
    std.debug.print("public words:", .{});
    for (public_words) |word| std.debug.print(" {d}", .{word});
    std.debug.print("\n", .{});
    std.debug.print("S31 {s}: lanes={d}, field-ops={d}->{d}, Blake-G={d}->{d}, proof={d} bytes, setup={d:.3}s, prove={d:.3}s, total through verification={d:.3}s\n", .{
        parsed.value.name,
        parsed.value.lanes,
        raw.qm31_ops,
        padded.qm31_ops,
        raw.blake_g_gate,
        padded.blake_g_gate,
        encoded.len,
        @as(f64, @floatFromInt(setup_ns)) / std.time.ns_per_s,
        @as(f64, @floatFromInt(prove_ns)) / std.time.ns_per_s,
        @as(f64, @floatFromInt(total_ns)) / std.time.ns_per_s,
    });
    std.debug.print("proof: {s}\n", .{path});
}

fn verify(allocator: std.mem.Allocator, path: []const u8, input: []const u16) !void {
    var parsed = try parsedProgram(allocator);
    defer parsed.deinit();
    var pp = try topology(allocator, parsed.value);
    defer pp.deinit(allocator);
    const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 16 << 20);
    defer allocator.free(encoded);
    try verifyBytes(allocator, parsed.value, &pp, input, encoded);
    std.debug.print("S31 {s}: native verification accepted {s}\n", .{ parsed.value.name, path });
}

fn verifyBytes(allocator: std.mem.Allocator, source: s31.program.Program, pp: *const preprocessed.PreprocessedCircuit, input: []const u16, encoded: []const u8) !void {
    var columns: [N_COLUMNS]wire.verify_request.Column = undefined;
    const request = try requestFor(source, allocator, pp, input, &columns);
    var verifier: VerifierData = undefined;
    try verifier.init(allocator);
    defer verifier.deinit();
    const verdict = try cpu.verify.verifyProofBytes(allocator, &verifier.table, &request, encoded);
    if (!verdict.isAccepted()) return error.ProofRejected;
}
