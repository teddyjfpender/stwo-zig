//! One compiled S31 relation and its separately built native host verifier.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const s31 = @import("stwo_s31_prototype");
const native = @import("native_verifier.zig");
const recursion_gate = @import("recursion_gate.zig");
const relation = s31.relation;

const QM31 = core.fields.qm31.QM31;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const preprocessed = circuit.common.preprocessed;
const embedded_source = @embedFile("s31_program_source");
const projection_bytes = @embedFile("s31_air_projection");
const air_program_bytes = @embedFile("s31_air_programs");
const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";
const chip_mode = @import("s31_options").chip_mode;
const sparse_mode = @import("s31_options").sparse_mode;
const wide_mode = @import("s31_options").wide_mode;
const direct_mode = @import("s31_options").direct_mode;
const M31 = core.fields.m31.M31;

const ChipKey = struct {
    rounds: u32,
    constant: u32,
    relation_id: u32,
};

const Key = struct {
    schema: []const u8,
    profile: []const u8 = "circuit-v1",
    chip: ?ChipKey = null,
    name: []const u8,
    program_sha256: []const u8,
    canonical_ir_sha256: []const u8,
    preprocessed_root: []const u8,
    circuit_hash: []const u8,
    padded: Rows,
    trace_log_size: u32,
    projection_sha256: []const u8,
    air_bundle_sha256: []const u8,
    stdlib_lock_sha256: ?[]const u8 = null,
    fri: struct {
        pow_bits: u32,
        log_blowup_factor: u32,
        last_layer_degree_bound: u32,
        queries: u32,
        fold_step: u32,
    },
};

const RecursiveStatement = struct {
    schema: []const u8,
    child_key_sha256: []const u8,
    child_public_words: [8]u32,
    outer_public_words: [8]u32,
    outer_preprocessed_root: []const u8,
    outer_circuit_hash: []const u8,
};

const Rows = struct { eq: usize, qm31_ops: usize, triple_xor: usize, m31_to_u32: usize, blake_g: usize };
const SourceSpan = struct {
    name: []const u8,
    canonical_id: u32,
    qm31_start: usize,
    qm31_end: usize,
    eq_start: usize,
    eq_end: usize,
    triple_xor_start: usize,
    triple_xor_end: usize,
    m31_to_u32_start: usize,
    m31_to_u32_end: usize,
    blake_g_start: usize,
    blake_g_end: usize,
};
const InputPacking = struct { name: []const u8, lanes: u32, qm31_wires: usize };
const Report = struct {
    name: []const u8,
    profile: []const u8,
    chip: ?ChipKey,
    program_sha256: []const u8,
    canonical_ir_sha256: []const u8,
    preprocessed_root: []const u8,
    circuit_hash: []const u8,
    raw: Rows,
    padded: Rows,
    preprocessed_columns: usize,
    preprocessed_cells: usize,
    fixed_table_max_log_size: u32,
    trace_log_size: u32,
    input_packing: []const InputPacking,
    source_map: []const SourceSpan,
    assertion_map: []const s31.relation_compiler.AssertionSpan,
    public_binding: []const s31.relation_compiler.BindingSpan,
    finalization: s31.relation_compiler.FinalizationSpan,
    fri: struct { pow_bits: u32, log_blowup_factor: u32, last_layer_degree_bound: u32, queries: u32, fold_step: u32 },
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) return usage();
    const command = args[1];
    var parsed = try parsedProgram(allocator);
    defer parsed.deinit();
    if (chip_mode and parsed.value.repeatedStepChip() == null)
        return error.UnsupportedChipRelation;
    if (direct_mode) for (parsed.value.inputs) |input| {
        if (input.kind != .m31) return error.UnsupportedDirectRelation;
    };
    if (std.mem.eql(u8, command, "check") and args.len == 2) {
        std.debug.print("S31 {s}: relation valid\n", .{parsed.value.name});
    } else if (std.mem.eql(u8, command, "run") and args.len == 3) {
        var assignment = try readAssignment(allocator, args[2]);
        defer assignment.deinit();
        const words = try relation.evaluate(allocator, parsed.value, assignment.value);
        printWords(words);
    } else if (std.mem.eql(u8, command, "inspect") and args.len == 2) {
        try inspect(allocator, parsed.value);
    } else if (std.mem.eql(u8, command, "prove") and args.len == 4) {
        try prove(allocator, parsed.value, args[2], args[3], null, false, null, null);
    } else if (std.mem.eql(u8, command, "recurse-check") and args.len == 4 and !chip_mode and !sparse_mode and !direct_mode) {
        try prove(allocator, parsed.value, args[2], args[3], null, true, null, null);
    } else if (std.mem.eql(u8, command, "recurse-prove") and args.len == 6 and !chip_mode and !sparse_mode and !direct_mode) {
        try prove(allocator, parsed.value, args[2], args[3], null, true, args[4], args[5]);
    } else if (std.mem.eql(u8, command, "recurse-wrap") and args.len == 6 and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapExisting(allocator, parsed.value, args[2], args[3], args[4], args[5]);
    } else if (std.mem.eql(u8, command, "prove-adversarial") and args.len == 5 and (sparse_mode or direct_mode) and chip_mode) {
        const mutation = std.meta.stringToEnum(cpu.sparse_arithmetic.Mutation, args[4]) orelse
            return error.InvalidMutation;
        try prove(allocator, parsed.value, args[2], args[3], mutation, false, null, null);
    } else return usage();
}

/// Entry point of the separately installed verifier binary. Its accepted
/// program is fixed by `embedded_source` at compile time.
pub fn verifierMain(embedded_key: []const u8) !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "recurse-verify"))
        return verifyOuter(allocator, args[2], args[3], embedded_key);
    if (args.len != 4) {
        std.debug.print("usage: s31-PROGRAM-native-verifier PROOF PUBLIC-STATEMENT.json VERIFICATION-KEY.json | recurse-verify OUTER-PROOF OUTER-STATEMENT.json\n", .{});
        return error.InvalidArguments;
    }
    try verify(allocator, args[1], args[2], args[3], embedded_key);
}

fn usage() error{InvalidArguments} {
    std.debug.print("usage: s31-program check | inspect | run ASSIGNMENT.json | prove ASSIGNMENT.json PROOF | recurse-check ASSIGNMENT.json CHILD-PROOF | recurse-prove ASSIGNMENT.json CHILD-PROOF OUTER-PROOF CHILD-KEY.json | recurse-wrap CHILD-PROOF CHILD-STATEMENT.json OUTER-PROOF CHILD-KEY.json\n", .{});
    return error.InvalidArguments;
}

fn parsedProgram(allocator: std.mem.Allocator) !relation.ParsedProgram {
    return relation.parseProgram(allocator, embedded_source);
}

fn readAssignment(allocator: std.mem.Allocator, path: []const u8) !relation.ParsedAssignment {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 20);
    defer allocator.free(source);
    return relation.parseAssignment(allocator, source);
}

fn printWords(words: [8]u32) void {
    std.debug.print("public words:", .{});
    for (words) |word| std.debug.print(" {d}", .{word});
    std.debug.print("\n", .{});
}

fn showcasePcsConfig(trace_log_size: u32) !PcsConfigV2 {
    // Match the Cairo proof's visible FRI settings: 26 PoW bits, blowup 2,
    // last-layer degree bound 1, 70 queries and fold step 1. Other protocol differences
    // remain, so timings are a directional showcase, not a controlled ratio.
    return PcsConfigV2.fromFriAndTraceSize(try FriConfigV2.init(26, 0, 1, 70, 1), trace_log_size);
}

fn directPcsConfig(circuit_log_size: u32, chip_rounds: ?u32) !PcsConfigV2 {
    const chip_log = if (chip_rounds) |rounds| try cpu.repeated_step_chip.validateRounds(rounds) else @as(u32, 0);
    var config = try showcasePcsConfig(@max(circuit_log_size, chip_log));
    // The preprocessed tree contains only QM31 operation columns. Keep its
    // natural commitment height while the base/interaction trees fit the chip.
    config.preprocessed_lifting_log_size = circuit_log_size + config.fri_config.log_blowup_factor;
    return config;
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

fn topology(allocator: std.mem.Allocator, source: relation.Program) !preprocessed.PreprocessedCircuit {
    var ctx = try s31.relation_compiler.compile(circuit.builder.NoValue, allocator, source, null);
    defer ctx.deinit();
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &ctx);
    try preprocessed.CircuitView.fromBuilder(&ctx.circuit).validate();
    return preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &ctx.circuit);
}

fn padForProfile(comptime V: type, ctx: *circuit.builder.Context(V)) !void {
    if (!sparse_mode and !direct_mode) return circuit.common.finalize.padContext(V, ctx);
    const raw = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&ctx.circuit));
    if ((!wide_mode and raw.eq != 0) or raw.triple_xor != 0 or raw.blake_g_gate != 0 or
        (direct_mode and raw.m31_to_u32 != 0))
        return error.UnsupportedSparseCircuit;
    return circuit.common.finalize.padToTargets(V, ctx, .{
        .eq = if (wide_mode) circuit.common.finalize.paddedSize(raw.eq) else 0,
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = if (direct_mode) 0 else circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    });
}

fn inspect(allocator: std.mem.Allocator, source: relation.Program) !void {
    var ir = try s31.canonical.build(allocator, source);
    defer ir.deinit();
    var maps = s31.relation_compiler.Maps{};
    defer maps.deinit(allocator);
    var ctx = if (direct_mode)
        try s31.relation_compiler.compileDirectWithSpans(circuit.builder.NoValue, allocator, source, null, &maps, chip_mode)
    else if (chip_mode)
        try s31.relation_compiler.compileChipWithSpans(circuit.builder.NoValue, allocator, source, null, &maps)
    else
        try s31.relation_compiler.compileWithSpans(circuit.builder.NoValue, allocator, source, null, &maps);
    defer ctx.deinit();
    const raw = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&ctx.circuit));
    try padForProfile(circuit.builder.NoValue, &ctx);
    const padded = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&ctx.circuit));
    var preprocessed_cells: usize = 0;
    var max_preprocessed_log: u32 = 0;
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(embedded_source, &source_digest, .{});
    var root: [32]u8 = undefined;
    var circuit_hash: [32]u8 = undefined;
    var trace_log: u32 = undefined;
    var preprocessed_columns: usize = undefined;
    if (direct_mode) {
        var pp = try circuit.common.direct_arithmetic.Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        const layout = pp.layout();
        for (layout.entries) |entry| {
            preprocessed_cells += @as(usize, 1) << @intCast(entry.log_size);
            max_preprocessed_log = @max(max_preprocessed_log, entry.log_size);
        }
        root = try pp.preprocessedRoot(allocator, 1);
        const chip_request: ?cpu.prove.ChipRequest = if (chip_mode) blk: {
            const spec = source.repeatedStepChip().?;
            break :blk .{
                .source_digest = source_digest,
                .rounds = spec.rounds,
                .constant = M31.fromCanonical(spec.constant),
                .initial = @splat(M31.zero()),
                .final = @splat(M31.zero()),
            };
        } else null;
        circuit_hash = cpu.direct_arithmetic.identityHash(
            source_digest,
            root,
            layout.traceLogSize(),
            1,
            chip_request,
        );
        trace_log = @max(pp.traceLogSize(), if (chip_mode)
            try cpu.repeated_step_chip.validateRounds(source.repeatedStepChip().?.rounds)
        else
            @as(u32, 0));
        preprocessed_columns = circuit.common.direct_arithmetic.N_COLUMNS;
    } else if (wide_mode) {
        var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        const layout = pp.layout();
        for (layout.entries) |entry| {
            preprocessed_cells += @as(usize, 1) << @intCast(entry.log_size);
            max_preprocessed_log = @max(max_preprocessed_log, entry.log_size);
        }
        root = try pp.preprocessedRoot(allocator, 1);
        circuit_hash = cpu.sparse_wide.identityHash(source_digest, root, .{
            layout.logSize("eq_in0_address").?,
            layout.logSize("qm31_ops_in0_address").?,
            layout.logSize("m31_to_u32_input_addr").?,
            16,
        }, 1);
        trace_log = pp.traceLogSize();
        preprocessed_columns = circuit.common.sparse_wide.N_COLUMNS;
    } else if (sparse_mode) {
        var pp = try circuit.common.sparse_arithmetic.Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        const layout = pp.layout();
        for (layout.entries) |entry| {
            preprocessed_cells += @as(usize, 1) << @intCast(entry.log_size);
            max_preprocessed_log = @max(max_preprocessed_log, entry.log_size);
        }
        root = try pp.preprocessedRoot(allocator, 1);
        const chip_request: ?cpu.prove.ChipRequest = if (chip_mode) blk: {
            const spec = source.repeatedStepChip().?;
            break :blk .{
                .source_digest = source_digest,
                .rounds = spec.rounds,
                .constant = M31.fromCanonical(spec.constant),
                .initial = @splat(M31.zero()),
                .final = @splat(M31.zero()),
            };
        } else null;
        circuit_hash = cpu.sparse_arithmetic.identityHash(
            source_digest,
            root,
            .{ layout.logSize("qm31_ops_in0_address").?, layout.logSize("m31_to_u32_input_addr").?, 16 },
            1,
            chip_request,
        );
        trace_log = pp.traceLogSize();
        preprocessed_columns = circuit.common.sparse_arithmetic.N_COLUMNS;
    } else {
        var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        const layout = pp.layout();
        for (layout.entries) |entry| {
            preprocessed_cells += @as(usize, 1) << @intCast(entry.log_size);
            max_preprocessed_log = @max(max_preprocessed_log, entry.log_size);
        }
        const component_logs = try circuit.common.component_list.circuitComponentLogSizes(&layout);
        root = try pp.preprocessedRoot(allocator, 1);
        circuit_hash = try circuit.common.circuit_hash.hostCircuitHash(component_logs, 1, root);
        trace_log = pp.traceLogSize();
        preprocessed_columns = preprocessed.N_PREPROCESSED_COLUMNS;
    }
    const source_hex = std.fmt.bytesToHex(source_digest, .lower);
    const ir_hex = std.fmt.bytesToHex(ir.sha256, .lower);
    const root_hex = std.fmt.bytesToHex(root, .lower);
    const hash_hex = std.fmt.bytesToHex(circuit_hash, .lower);
    const source_map = try allocator.alloc(SourceSpan, ir.source_map.len);
    defer allocator.free(source_map);
    for (ir.source_map, source_map) |item, *mapped| {
        const span = maps.nodes.items[item.id];
        mapped.* = .{
            .name = item.name,
            .canonical_id = item.id,
            .qm31_start = span.qm31_start,
            .qm31_end = span.qm31_end,
            .eq_start = span.eq_start,
            .eq_end = span.eq_end,
            .triple_xor_start = span.triple_xor_start,
            .triple_xor_end = span.triple_xor_end,
            .m31_to_u32_start = span.m31_to_u32_start,
            .m31_to_u32_end = span.m31_to_u32_end,
            .blake_g_start = span.blake_g_start,
            .blake_g_end = span.blake_g_end,
        };
    }
    const packing = try allocator.alloc(InputPacking, source.inputs.len);
    defer allocator.free(packing);
    for (source.inputs, packing) |input, *item| item.* = .{ .name = input.name, .lanes = input.length, .qm31_wires = (input.length + 3) / 4 };
    const report: Report = .{
        .name = source.name,
        .profile = if (direct_mode) "direct-m31-v4" else if (wide_mode) "sparse-wide-v5" else if (sparse_mode) "sparse-v3" else if (chip_mode) "hybrid-step-v2" else "circuit-v1",
        .chip = if (chip_mode) blk: {
            const spec = source.repeatedStepChip().?;
            break :blk .{ .rounds = spec.rounds, .constant = spec.constant, .relation_id = cpu.repeated_step_chip.relation_id };
        } else null,
        .program_sha256 = &source_hex,
        .canonical_ir_sha256 = &ir_hex,
        .preprocessed_root = &root_hex,
        .circuit_hash = &hash_hex,
        .raw = .{ .eq = raw.eq, .qm31_ops = raw.qm31_ops, .triple_xor = raw.triple_xor, .m31_to_u32 = raw.m31_to_u32, .blake_g = raw.blake_g_gate },
        .padded = .{ .eq = padded.eq, .qm31_ops = padded.qm31_ops, .triple_xor = padded.triple_xor, .m31_to_u32 = padded.m31_to_u32, .blake_g = padded.blake_g_gate },
        .preprocessed_columns = preprocessed_columns,
        .preprocessed_cells = preprocessed_cells,
        .fixed_table_max_log_size = max_preprocessed_log,
        .trace_log_size = trace_log,
        .input_packing = packing,
        .source_map = source_map,
        .assertion_map = maps.assertions.items,
        .public_binding = maps.bindings.items,
        .finalization = maps.finalization.?,
        .fri = .{ .pow_bits = 26, .log_blowup_factor = 1, .last_layer_degree_bound = 1, .queries = 70, .fold_step = 1 },
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(encoded);
    std.debug.print("{s}\n", .{encoded});
}

fn prove(allocator: std.mem.Allocator, source: relation.Program, assignment_path: []const u8, path: []const u8, mutation: ?cpu.sparse_arithmetic.Mutation, recurse_check: bool, outer_path: ?[]const u8, child_key_path: ?[]const u8) !void {
    var total_timer = try std.time.Timer.start();
    var assignment = try readAssignment(allocator, assignment_path);
    defer assignment.deinit();
    const public_words = try relation.evaluate(allocator, source, assignment.value);
    var value_ctx = if (direct_mode)
        try s31.relation_compiler.compileDirect(QM31, allocator, source, assignment.value, chip_mode)
    else if (chip_mode)
        try s31.relation_compiler.compileChip(QM31, allocator, source, assignment.value)
    else
        try s31.relation_compiler.compile(QM31, allocator, source, assignment.value);
    defer value_ctx.deinit();
    const witness_ns = total_timer.read();
    var topology_ctx = if (direct_mode)
        try s31.relation_compiler.compileDirect(circuit.builder.NoValue, allocator, source, null, chip_mode)
    else if (chip_mode)
        try s31.relation_compiler.compileChip(circuit.builder.NoValue, allocator, source, null)
    else
        try s31.relation_compiler.compile(circuit.builder.NoValue, allocator, source, null);
    defer topology_ctx.deinit();
    if (!sameTopology(&value_ctx.circuit, &topology_ctx.circuit)) return error.ValueDependentTopology;
    const raw = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit));
    try padForProfile(QM31, &value_ctx);
    try padForProfile(circuit.builder.NoValue, &topology_ctx);
    if (!sameTopology(&value_ctx.circuit, &topology_ctx.circuit)) return error.ValueDependentTopology;
    if (!try value_ctx.isCircuitValid()) return error.UnsatisfiedCircuit;
    var air_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(air_program_bytes, &air_digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(air_digest, .lower), cpu.air.bundle_sha256)) return error.AirBundleMismatch;
    var bundle = try cpu.air.parse(allocator, air_program_bytes);
    defer bundle.deinit();

    const chip_request: ?cpu.prove.ChipRequest = if (chip_mode) blk: {
        const spec = source.repeatedStepChip() orelse return error.UnsupportedChipRelation;
        var source_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(embedded_source, &source_digest, .{});
        var initial: [4]M31 = undefined;
        var final: [4]M31 = undefined;
        for (0..4) |lane| {
            initial[lane] = M31.fromCanonical(public_words[lane]);
            final[lane] = M31.fromCanonical(public_words[4 + lane]);
        }
        break :blk .{
            .source_digest = source_digest,
            .rounds = spec.rounds,
            .constant = M31.fromCanonical(spec.constant),
            .initial = initial,
            .final = final,
        };
    } else null;
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(embedded_source, &source_digest, .{});
    var encoded: []u8 = undefined;
    var setup_ns: u64 = undefined;
    var prove_ns: u64 = undefined;
    var sparse_pow_ns: u64 = 0;
    var sparse_fri_pow_ns: u64 = 0;
    if (direct_mode) {
        var pp = try circuit.common.direct_arithmetic.Circuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
        defer pp.deinit(allocator);
        const pcs = try directPcsConfig(pp.traceLogSize(), if (chip_request) |item| item.rounds else null);
        var committed = try cpu.direct_arithmetic.PreprocessedCommitment.build(allocator, &pp, pcs);
        defer committed.deinit(allocator);
        setup_ns = total_timer.read() - witness_ns;
        var timer = try std.time.Timer.start();
        var proof = try cpu.direct_arithmetic.prove(
            allocator,
            value_ctx.values(),
            &pp,
            &bundle,
            pcs,
            .{ .source_digest = source_digest, .chip_request = chip_request, .preprocessed_commitment = &committed, .test_mutation = mutation, .interaction_pow_time_ns = &sparse_pow_ns, .fri_pow_time_ns = &sparse_fri_pow_ns },
        );
        defer proof.deinit();
        prove_ns = timer.read();
        encoded = try native.serializeDirect(allocator, &proof, chip_mode);
        const layout = pp.layout();
        const root = committed.root();
        const hash = cpu.direct_arithmetic.identityHash(
            source_digest,
            root,
            layout.traceLogSize(),
            pcs.fri_config.log_blowup_factor,
            chip_request,
        );
        try native.verifyDirect(
            allocator,
            &layout,
            &bundle,
            pcs,
            root,
            hash,
            public_words,
            encoded,
            source_digest,
            if (chip_request) |item| native.HybridSpec{
                .source_digest = source_digest,
                .rounds = item.rounds,
                .constant = item.constant,
            } else null,
        );
    } else if (wide_mode) {
        var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
        defer pp.deinit(allocator);
        const pcs = try showcasePcsConfig(pp.traceLogSize());
        var committed = try cpu.sparse_wide.PreprocessedCommitment.build(allocator, &pp, pcs);
        defer committed.deinit(allocator);
        setup_ns = total_timer.read() - witness_ns;
        var timer = try std.time.Timer.start();
        var proof = try cpu.sparse_wide.prove(allocator, value_ctx.values(), &pp, &bundle, pcs, .{
            .source_digest = source_digest,
            .preprocessed_commitment = &committed,
            .pow_time_ns = &sparse_pow_ns,
            .fri_pow_time_ns = &sparse_fri_pow_ns,
        });
        defer proof.deinit();
        prove_ns = timer.read();
        encoded = try native.serializeSparseWide(allocator, &proof);
        const layout = pp.layout();
        const root = committed.root();
        const hash = cpu.sparse_wide.identityHash(source_digest, root, .{
            layout.logSize("eq_in0_address").?,
            layout.logSize("qm31_ops_in0_address").?,
            layout.logSize("m31_to_u32_input_addr").?,
            16,
        }, pcs.fri_config.log_blowup_factor);
        try native.verifySparseWide(allocator, &layout, &bundle, pcs, root, hash, public_words, encoded, source_digest);
    } else if (sparse_mode) {
        var pp = try circuit.common.sparse_arithmetic.Circuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
        defer pp.deinit(allocator);
        const pcs = try showcasePcsConfig(pp.traceLogSize());
        var committed = try cpu.sparse_arithmetic.PreprocessedCommitment.build(allocator, &pp, pcs);
        defer committed.deinit(allocator);
        setup_ns = total_timer.read() - witness_ns;
        var timer = try std.time.Timer.start();
        var proof = try cpu.sparse_arithmetic.prove(
            allocator,
            value_ctx.values(),
            &pp,
            &bundle,
            pcs,
            .{ .source_digest = source_digest, .chip_request = chip_request, .preprocessed_commitment = &committed, .test_mutation = mutation, .pow_time_ns = &sparse_pow_ns, .fri_pow_time_ns = &sparse_fri_pow_ns },
        );
        defer proof.deinit();
        prove_ns = timer.read();
        encoded = try native.serializeSparse(allocator, &proof, chip_mode);
        const layout = pp.layout();
        const root = committed.root();
        const hash = cpu.sparse_arithmetic.identityHash(
            source_digest,
            root,
            .{ layout.logSize("qm31_ops_in0_address").?, layout.logSize("m31_to_u32_input_addr").?, 16 },
            pcs.fri_config.log_blowup_factor,
            chip_request,
        );
        try native.verifySparse(
            allocator,
            &layout,
            &bundle,
            pcs,
            root,
            hash,
            public_words,
            encoded,
            source_digest,
            if (chip_request) |item| native.HybridSpec{
                .source_digest = source_digest,
                .rounds = item.rounds,
                .constant = item.constant,
            } else null,
        );
    } else {
        var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
        defer pp.deinit(allocator);
        const pcs = try showcasePcsConfig(pp.traceLogSize());
        var committed = try cpu.prove.PreprocessedCommitment.build(allocator, &pp, pcs, .{});
        defer committed.deinit(allocator);
        setup_ns = total_timer.read() - witness_ns;
        var timer = try std.time.Timer.start();
        var proof = try cpu.Internal.prove(allocator, value_ctx.values(), &pp, &bundle, pcs, .{
            .preprocessed_commitment = &committed,
            .chip = chip_request,
        }, {});
        defer proof.deinit();
        prove_ns = timer.read();
        encoded = if (chip_mode)
            try native.serializeHybrid(allocator, &proof)
        else
            try native.serialize(allocator, &proof);
        try verifyBytes(allocator, source, &pp, assignment.value, encoded);
        if (recurse_check) {
            const layout = pp.layout();
            const root = committed.root();
            const expected: recursion_gate.Expected = .{
                .preprocessed_root = root,
                .circuit_hash = try circuit.common.circuit_hash.hostCircuitHash(
                    try circuit.common.component_list.circuitComponentLogSizes(&layout),
                    pcs.fri_config.log_blowup_factor,
                    root,
                ),
                .public_words = public_words,
            };
            var recursive = try recursion_gate.verifyChild(allocator, projection_bytes, layout, &proof, expected);
            defer recursive.deinit();
            if (outer_path == null) {
                var wrong_statement = expected;
                wrong_statement.public_words[0] = (wrong_statement.public_words[0] + 1) % core.fields.m31.Modulus;
                if (recursion_gate.verifyChild(allocator, projection_bytes, layout, &proof, wrong_statement)) |accepted| {
                    var invalid = accepted;
                    invalid.deinit();
                    return error.RecursiveVerifierAcceptedWrongStatement;
                } else |err| switch (err) {
                    error.VerificationFailed, error.EqFailedOnEval => {},
                    else => return err,
                }
                inline for (.{ .trace_root, .claimed_sum, .fri_last_layer }) |corruption| {
                    if (recursion_gate.verifyChildWithMutation(allocator, projection_bytes, layout, &proof, expected, corruption)) |accepted| {
                        var invalid = accepted;
                        invalid.deinit();
                        return error.RecursiveVerifierAcceptedCorruptProof;
                    } else |err| switch (err) {
                        error.VerificationFailed, error.EqFailedOnEval => {},
                        else => return err,
                    }
                }
            }
            std.debug.print("S31 recursive child circuit: vars={d} qm31_ops={d} valid=true\n", .{
                recursive.circuit.n_vars,
                recursive.circuit.mul.items.len + recursive.circuit.add.items.len + recursive.circuit.sub.items.len,
            });
            if (outer_path) |destination| try proveOuter(allocator, source, &recursive, layout, pcs, &bundle, expected, destination, child_key_path.?);
        }
    }
    defer allocator.free(encoded);

    const parent = std.fs.path.dirname(path) orelse ".";
    try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = encoded });
    const total_ns = total_timer.read();
    const padded = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit));
    var input_lanes: usize = 0;
    for (source.inputs) |input| input_lanes += input.length;
    printWords(public_words);
    std.debug.print("S31 {s}: lanes={d}, field-ops={d}->{d}, Blake-G={d}->{d}, proof={d} bytes, witness={d:.6}s, setup={d:.6}s, prove={d:.6}s, total through verification={d:.6}s\n", .{
        source.name,
        input_lanes,
        raw.qm31_ops,
        padded.qm31_ops,
        raw.blake_g_gate,
        padded.blake_g_gate,
        encoded.len,
        @as(f64, @floatFromInt(witness_ns)) / std.time.ns_per_s,
        @as(f64, @floatFromInt(setup_ns)) / std.time.ns_per_s,
        @as(f64, @floatFromInt(prove_ns)) / std.time.ns_per_s,
        @as(f64, @floatFromInt(total_ns)) / std.time.ns_per_s,
    });
    if (sparse_mode or direct_mode) std.debug.print("S31 {s} proof: interaction_pow={d:.6}s fri_pow={d:.6}s\n", .{
        if (direct_mode) "direct" else "sparse",
        @as(f64, @floatFromInt(sparse_pow_ns)) / std.time.ns_per_s,
        @as(f64, @floatFromInt(sparse_fri_pow_ns)) / std.time.ns_per_s,
    });
    std.debug.print("proof: {s}\n", .{path});
}

fn proveOuter(
    allocator: std.mem.Allocator,
    source: relation.Program,
    values: *circuit.builder.Context(QM31),
    child_layout: preprocessed.ColumnLayout,
    child_pcs: PcsConfigV2,
    bundle: *const cpu.air.Bundle,
    expected_child: recursion_gate.Expected,
    path: []const u8,
    child_key_path: []const u8,
) !void {
    const key_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(key_bytes);
    var parsed_key = try std.json.parseFromSlice(Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_key.deinit();
    try validateKey(allocator, source, parsed_key.value);
    if (!std.mem.eql(u8, parsed_key.value.preprocessed_root, &std.fmt.bytesToHex(expected_child.preprocessed_root, .lower)) or
        !std.mem.eql(u8, parsed_key.value.circuit_hash, &std.fmt.bytesToHex(expected_child.circuit_hash, .lower)))
        return error.RecursiveChildKeyMismatch;
    var pp = blk: {
        var topology_ctx = try recursion_gate.topology(allocator, projection_bytes, child_layout, child_pcs);
        defer topology_ctx.deinit();
        if (!sameTopology(&values.circuit, &topology_ctx.circuit)) return error.RecursiveValueDependentTopology;
        try circuit.common.finalize.padContext(QM31, values);
        try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
        if (!sameTopology(&values.circuit, &topology_ctx.circuit) or !try values.isCircuitValid())
            return error.InvalidRecursiveCircuit;
        break :blk try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    };
    defer pp.deinit(allocator);
    // The AIR columns own their values. The checked value graph is no longer
    // needed by the prover, which consumes only the variable-value table.
    values.circuit.deinit(allocator);
    values.circuit = .{};
    const pcs = try showcasePcsConfig(pp.traceLogSize());
    var committed = try cpu.prove.PreprocessedCommitment.build(allocator, &pp, pcs, .{});
    defer committed.deinit(allocator);
    var timer = try std.time.Timer.start();
    var outer = try cpu.Internal.prove(allocator, values.values(), &pp, bundle, pcs, .{
        .preprocessed_commitment = &committed,
    }, {});
    defer outer.deinit();
    const prove_ns = timer.read();
    if (outer.output_values.len != 8) return error.InvalidRecursivePublicOutput;
    var public_words: [8]u32 = undefined;
    for (outer.output_values, &public_words) |value, *word| {
        const limbs = value.toM31Array();
        if (limbs[0].v > 65535 or limbs[1].v > 65535 or limbs[2].v != 0 or limbs[3].v != 0)
            return error.InvalidRecursivePublicOutput;
        word.* = limbs[0].v | (limbs[1].v << 16);
    }
    if (!std.meta.eql(public_words, recursion_gate.statementDigest(expected_child.preprocessed_root, expected_child.public_words)))
        return error.RecursiveStatementDigestMismatch;
    const encoded = try native.serialize(allocator, &outer);
    defer allocator.free(encoded);
    const layout = pp.layout();
    const root = committed.root();
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    try native.verify(allocator, &layout, bundle, pcs, root, hash, public_words, encoded);
    try std.fs.cwd().makePath(std.fs.path.dirname(path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = encoded });
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_bytes, &key_digest, .{});
    const key_hex = std.fmt.bytesToHex(key_digest, .lower);
    const root_hex = std.fmt.bytesToHex(root, .lower);
    const hash_hex = std.fmt.bytesToHex(hash, .lower);
    const statement: RecursiveStatement = .{
        .schema = "s31-recursive-gate-statement-v1",
        .child_key_sha256 = &key_hex,
        .child_public_words = expected_child.public_words,
        .outer_public_words = public_words,
        .outer_preprocessed_root = &root_hex,
        .outer_circuit_hash = &hash_hex,
    };
    const encoded_statement = try std.json.Stringify.valueAlloc(allocator, statement, .{});
    defer allocator.free(encoded_statement);
    const statement_path = try std.fmt.allocPrint(allocator, "{s}.statement.json", .{path});
    defer allocator.free(statement_path);
    try std.fs.cwd().writeFile(.{ .sub_path = statement_path, .data = encoded_statement });
    std.debug.print("S31 recursive outer proof: bytes={d} prove={d:.3}s root={s} hash={s} public={any}\n", .{
        encoded.len,
        @as(f64, @floatFromInt(prove_ns)) / std.time.ns_per_s,
        &std.fmt.bytesToHex(root, .lower),
        &std.fmt.bytesToHex(hash, .lower),
        public_words,
    });
}

fn wrapExisting(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_proof_path: []const u8,
    child_statement_path: []const u8,
    outer_path: []const u8,
    child_key_path: []const u8,
) !void {
    const key_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(key_bytes);
    var parsed_key = try std.json.parseFromSlice(Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_key.deinit();
    const key = parsed_key.value;
    try validateKey(allocator, source, key);
    var parsed_statement = try readAssignment(allocator, child_statement_path);
    defer parsed_statement.deinit();
    if (parsed_statement.value.private_inputs != null) return error.InvalidPublicStatement;
    const public_words = try relation.claimedWords(allocator, source, parsed_statement.value);
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = key.padded.eq,
        .qm31_ops = key.padded.qm31_ops,
        .triple_xor = key.padded.triple_xor,
        .m31_to_u32 = key.padded.m31_to_u32,
        .blake_g_gate = key.padded.blake_g,
    });
    if (layout.traceLogSize() != key.trace_log_size) return error.InvalidVerificationKey;
    const pcs = try showcasePcsConfig(key.trace_log_size);
    var root: [32]u8 = undefined;
    var hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&root, key.preprocessed_root);
    _ = try std.fmt.hexToBytes(&hash, key.circuit_hash);
    const expected: recursion_gate.Expected = .{
        .preprocessed_root = root,
        .circuit_hash = hash,
        .public_words = public_words,
    };
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_proof_path, 16 << 20);
    defer allocator.free(child_bytes);
    var converted = try native.verifyAndCapture(allocator, &layout, &bundle, pcs, root, hash, public_words, child_bytes);
    defer converted.deinit();
    var recursive = try recursion_gate.verifyPrepared(allocator, projection_bytes, layout, pcs, &converted, expected);
    defer recursive.deinit();
    std.debug.print("S31 recursive saved child: vars={d} qm31_ops={d} valid=true\n", .{
        recursive.circuit.n_vars,
        recursive.circuit.mul.items.len + recursive.circuit.add.items.len + recursive.circuit.sub.items.len,
    });
    try proveOuter(allocator, source, &recursive, layout, pcs, &bundle, expected, outer_path, child_key_path);
}

fn verifyOuter(
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    statement_path: []const u8,
    embedded_key: []const u8,
) !void {
    if (chip_mode or sparse_mode or direct_mode) return error.UnsupportedRecursiveProfile;
    var parsed_source = try parsedProgram(allocator);
    defer parsed_source.deinit();
    var parsed_key = try std.json.parseFromSlice(Key, allocator, embedded_key, .{ .ignore_unknown_fields = false });
    defer parsed_key.deinit();
    try validateKey(allocator, parsed_source.value, parsed_key.value);
    const statement_bytes = try std.fs.cwd().readFileAlloc(allocator, statement_path, 4096);
    defer allocator.free(statement_bytes);
    var parsed_statement = try std.json.parseFromSlice(RecursiveStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_statement.deinit();
    const statement = parsed_statement.value;
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(embedded_key, &key_digest, .{});
    if (!std.mem.eql(u8, statement.schema, "s31-recursive-gate-statement-v1") or
        !std.mem.eql(u8, statement.child_key_sha256, &std.fmt.bytesToHex(key_digest, .lower)))
        return error.InvalidRecursiveStatement;
    for (statement.child_public_words) |word| if (word >= core.fields.m31.Modulus) return error.NoncanonicalPublicWord;
    var child_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&child_root, parsed_key.value.preprocessed_root);
    if (!std.meta.eql(statement.outer_public_words, recursion_gate.statementDigest(child_root, statement.child_public_words)))
        return error.InvalidRecursiveStatement;
    const child_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = parsed_key.value.padded.eq,
        .qm31_ops = parsed_key.value.padded.qm31_ops,
        .triple_xor = parsed_key.value.padded.triple_xor,
        .m31_to_u32 = parsed_key.value.padded.m31_to_u32,
        .blake_g_gate = parsed_key.value.padded.blake_g,
    });
    if (child_layout.traceLogSize() != parsed_key.value.trace_log_size)
        return error.InvalidVerificationKey;
    var pp = blk: {
        var topology_ctx = try recursion_gate.topology(
            allocator,
            projection_bytes,
            child_layout,
            try showcasePcsConfig(parsed_key.value.trace_log_size),
        );
        defer topology_ctx.deinit();
        try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
        break :blk try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    };
    defer pp.deinit(allocator);
    const pcs = try showcasePcsConfig(pp.traceLogSize());
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const layout = pp.layout();
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    if (!std.mem.eql(u8, statement.outer_preprocessed_root, &std.fmt.bytesToHex(root, .lower)) or
        !std.mem.eql(u8, statement.outer_circuit_hash, &std.fmt.bytesToHex(hash, .lower)))
        return error.InvalidRecursiveStatement;
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    try native.verify(allocator, &layout, &bundle, pcs, root, hash, statement.outer_public_words, proof_bytes);
    std.debug.print("S31 recursive outer verification accepted: {s}\n", .{proof_path});
}

fn verify(allocator: std.mem.Allocator, path: []const u8, statement_path: []const u8, key_path: []const u8, embedded_key: []const u8) !void {
    var parsed = try parsedProgram(allocator);
    defer parsed.deinit();
    var statement = try readAssignment(allocator, statement_path);
    defer statement.deinit();
    if (statement.value.private_inputs != null) return error.InvalidPublicStatement;
    const external_key = try std.fs.cwd().readFileAlloc(allocator, key_path, 4096);
    defer allocator.free(external_key);
    if (!std.mem.eql(u8, external_key, embedded_key)) return error.InvalidVerificationKey;
    var key_parsed = try std.json.parseFromSlice(Key, allocator, embedded_key, .{ .ignore_unknown_fields = false });
    defer key_parsed.deinit();
    const key = key_parsed.value;
    try validateKey(allocator, parsed.value, key);
    var root: [32]u8 = undefined;
    var hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&root, key.preprocessed_root);
    _ = try std.fmt.hexToBytes(&hash, key.circuit_hash);
    const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 16 << 20);
    defer allocator.free(encoded);
    const public_words = try relation.claimedWords(allocator, parsed.value, statement.value);
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    if (direct_mode) {
        if (key.padded.eq != 0 or key.padded.triple_xor != 0 or
            key.padded.blake_g != 0 or key.padded.m31_to_u32 != 0)
            return error.InvalidVerificationKey;
        const layout = try circuit.common.direct_arithmetic.Layout.fromSize(key.padded.qm31_ops);
        const expected_trace_log = @max(layout.traceLogSize(), if (chip_mode)
            try cpu.repeated_step_chip.validateRounds(parsed.value.repeatedStepChip().?.rounds)
        else
            @as(u32, 0));
        if (expected_trace_log != key.trace_log_size) return error.InvalidVerificationKey;
        var source_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(embedded_source, &source_digest, .{});
        const spec: ?native.HybridSpec = if (chip_mode) blk: {
            const shape = parsed.value.repeatedStepChip() orelse return error.UnsupportedChipRelation;
            break :blk .{ .source_digest = source_digest, .rounds = shape.rounds, .constant = M31.fromCanonical(shape.constant) };
        } else null;
        try native.verifyDirect(
            allocator,
            &layout,
            &bundle,
            try directPcsConfig(layout.traceLogSize(), if (chip_mode) parsed.value.repeatedStepChip().?.rounds else null),
            root,
            hash,
            public_words,
            encoded,
            source_digest,
            spec,
        );
    } else if (wide_mode) {
        if (key.padded.eq < 16 or key.padded.triple_xor != 0 or key.padded.blake_g != 0)
            return error.InvalidVerificationKey;
        const layout = try circuit.common.sparse_wide.Layout.fromSizes(key.padded.eq, key.padded.qm31_ops, key.padded.m31_to_u32);
        if (layout.traceLogSize() != key.trace_log_size) return error.InvalidVerificationKey;
        var source_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(embedded_source, &source_digest, .{});
        try native.verifySparseWide(allocator, &layout, &bundle, try showcasePcsConfig(key.trace_log_size), root, hash, public_words, encoded, source_digest);
    } else if (sparse_mode) {
        if (key.padded.eq != 0 or key.padded.triple_xor != 0 or key.padded.blake_g != 0)
            return error.InvalidVerificationKey;
        const layout = try circuit.common.sparse_arithmetic.Layout.fromSizes(
            key.padded.qm31_ops,
            key.padded.m31_to_u32,
        );
        if (layout.traceLogSize() != key.trace_log_size) return error.InvalidVerificationKey;
        var source_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(embedded_source, &source_digest, .{});
        const spec: ?native.HybridSpec = if (chip_mode) blk: {
            const shape = parsed.value.repeatedStepChip() orelse return error.UnsupportedChipRelation;
            break :blk .{ .source_digest = source_digest, .rounds = shape.rounds, .constant = M31.fromCanonical(shape.constant) };
        } else null;
        try native.verifySparse(
            allocator,
            &layout,
            &bundle,
            try showcasePcsConfig(key.trace_log_size),
            root,
            hash,
            public_words,
            encoded,
            source_digest,
            spec,
        );
    } else if (chip_mode) {
        const layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
            .eq = key.padded.eq,
            .qm31_ops = key.padded.qm31_ops,
            .triple_xor = key.padded.triple_xor,
            .m31_to_u32 = key.padded.m31_to_u32,
            .blake_g_gate = key.padded.blake_g,
        });
        if (layout.traceLogSize() != key.trace_log_size) return error.InvalidVerificationKey;
        var source_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(embedded_source, &source_digest, .{});
        const spec = parsed.value.repeatedStepChip() orelse return error.UnsupportedChipRelation;
        try native.verifyHybrid(
            allocator,
            &layout,
            &bundle,
            try showcasePcsConfig(key.trace_log_size),
            root,
            hash,
            public_words,
            encoded,
            .{ .source_digest = source_digest, .rounds = spec.rounds, .constant = M31.fromCanonical(spec.constant) },
        );
    } else {
        const layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
            .eq = key.padded.eq,
            .qm31_ops = key.padded.qm31_ops,
            .triple_xor = key.padded.triple_xor,
            .m31_to_u32 = key.padded.m31_to_u32,
            .blake_g_gate = key.padded.blake_g,
        });
        if (layout.traceLogSize() != key.trace_log_size) return error.InvalidVerificationKey;
        try native.verify(allocator, &layout, &bundle, try showcasePcsConfig(key.trace_log_size), root, hash, public_words, encoded);
    }
    std.debug.print("S31 {s}: native verification accepted {s}\n", .{ parsed.value.name, path });
}

fn validateKey(allocator: std.mem.Allocator, source: relation.Program, key: Key) !void {
    const expected_stdlib = @import("s31_options").stdlib_lock_sha256;
    if (expected_stdlib.len == 0) {
        if (key.stdlib_lock_sha256 != null) return error.InvalidVerificationKey;
    } else {
        const pinned_stdlib = key.stdlib_lock_sha256 orelse return error.InvalidVerificationKey;
        if (!std.mem.eql(u8, pinned_stdlib, expected_stdlib)) return error.InvalidVerificationKey;
    }
    if (!std.mem.eql(u8, key.schema, if (direct_mode) "s31-verification-key-v4" else if (wide_mode) "s31-verification-key-v5" else if (sparse_mode) "s31-verification-key-v3" else if (chip_mode) "s31-verification-key-v2" else "s31-verification-key-v1") or
        !std.mem.eql(u8, key.profile, if (direct_mode) "direct-m31-v4" else if (wide_mode) "sparse-wide-v5" else if (sparse_mode) "sparse-v3" else if (chip_mode) "hybrid-step-v2" else "circuit-v1") or
        !std.mem.eql(u8, key.name, source.name))
        return error.InvalidVerificationKey;
    if (chip_mode) {
        const expected = source.repeatedStepChip() orelse return error.UnsupportedChipRelation;
        const actual = key.chip orelse return error.InvalidVerificationKey;
        if (actual.rounds != expected.rounds or actual.constant != expected.constant or
            actual.relation_id != cpu.repeated_step_chip.relation_id)
            return error.InvalidVerificationKey;
    } else if (key.chip != null) return error.InvalidVerificationKey;
    var program_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(embedded_source, &program_digest, .{});
    if (!std.mem.eql(u8, key.program_sha256, &std.fmt.bytesToHex(program_digest, .lower))) return error.InvalidVerificationKey;
    var ir = try s31.canonical.build(allocator, source);
    defer ir.deinit();
    if (!std.mem.eql(u8, key.canonical_ir_sha256, &std.fmt.bytesToHex(ir.sha256, .lower))) return error.InvalidVerificationKey;
    if (key.preprocessed_root.len != 64 or key.circuit_hash.len != 64 or
        !std.mem.eql(u8, key.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, key.air_bundle_sha256, cpu.air.bundle_sha256) or
        key.fri.pow_bits != 26 or key.fri.log_blowup_factor != 1 or
        key.fri.last_layer_degree_bound != 1 or key.fri.queries != 70 or
        key.fri.fold_step != 1) return error.InvalidVerificationKey;
    try validateCompiledKey(allocator, source, key, program_digest);
}

/// The embedded source must determine the fixed circuit in the embedded key.
/// A source digest alone cannot establish this: a key could carry a different
/// circuit's commitment while retaining the expected source and IR digests.
fn validateCompiledKey(allocator: std.mem.Allocator, source: relation.Program, key: Key, source_digest: [32]u8) !void {
    var ctx = if (direct_mode)
        try s31.relation_compiler.compileDirect(circuit.builder.NoValue, allocator, source, null, chip_mode)
    else if (chip_mode)
        try s31.relation_compiler.compileChip(circuit.builder.NoValue, allocator, source, null)
    else
        try s31.relation_compiler.compile(circuit.builder.NoValue, allocator, source, null);
    defer ctx.deinit();
    try padForProfile(circuit.builder.NoValue, &ctx);
    const sizes = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&ctx.circuit));
    const padded: Rows = .{
        .eq = sizes.eq,
        .qm31_ops = sizes.qm31_ops,
        .triple_xor = sizes.triple_xor,
        .m31_to_u32 = sizes.m31_to_u32,
        .blake_g = sizes.blake_g_gate,
    };
    if (!std.meta.eql(padded, key.padded)) return error.InvalidVerificationKey;

    var expected_root: [32]u8 = undefined;
    var expected_hash: [32]u8 = undefined;
    var expected_trace_log: u32 = undefined;
    if (direct_mode) {
        var pp = try circuit.common.direct_arithmetic.Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        expected_root = try pp.preprocessedRoot(allocator, 1);
        const chip_request: ?cpu.prove.ChipRequest = if (chip_mode) blk: {
            const spec = source.repeatedStepChip() orelse return error.UnsupportedChipRelation;
            break :blk .{
                .source_digest = source_digest,
                .rounds = spec.rounds,
                .constant = M31.fromCanonical(spec.constant),
                .initial = @splat(M31.zero()),
                .final = @splat(M31.zero()),
            };
        } else null;
        expected_hash = cpu.direct_arithmetic.identityHash(
            source_digest,
            expected_root,
            pp.traceLogSize(),
            1,
            chip_request,
        );
        expected_trace_log = @max(pp.traceLogSize(), if (chip_mode)
            try cpu.repeated_step_chip.validateRounds(source.repeatedStepChip().?.rounds)
        else
            @as(u32, 0));
    } else if (wide_mode) {
        var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        const layout = pp.layout();
        expected_root = try pp.preprocessedRoot(allocator, 1);
        expected_hash = cpu.sparse_wide.identityHash(source_digest, expected_root, .{
            layout.logSize("eq_in0_address").?,
            layout.logSize("qm31_ops_in0_address").?,
            layout.logSize("m31_to_u32_input_addr").?,
            16,
        }, 1);
        expected_trace_log = pp.traceLogSize();
    } else if (sparse_mode) {
        var pp = try circuit.common.sparse_arithmetic.Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        const layout = pp.layout();
        expected_root = try pp.preprocessedRoot(allocator, 1);
        const chip_request: ?cpu.prove.ChipRequest = if (chip_mode) blk: {
            const spec = source.repeatedStepChip() orelse return error.UnsupportedChipRelation;
            break :blk .{
                .source_digest = source_digest,
                .rounds = spec.rounds,
                .constant = M31.fromCanonical(spec.constant),
                .initial = @splat(M31.zero()),
                .final = @splat(M31.zero()),
            };
        } else null;
        expected_hash = cpu.sparse_arithmetic.identityHash(
            source_digest,
            expected_root,
            .{ layout.logSize("qm31_ops_in0_address").?, layout.logSize("m31_to_u32_input_addr").?, 16 },
            1,
            chip_request,
        );
        expected_trace_log = pp.traceLogSize();
    } else {
        var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        const layout = pp.layout();
        const component_logs = try circuit.common.component_list.circuitComponentLogSizes(&layout);
        expected_root = try pp.preprocessedRoot(allocator, 1);
        expected_hash = try circuit.common.circuit_hash.hostCircuitHash(component_logs, 1, expected_root);
        expected_trace_log = pp.traceLogSize();
    }
    if (key.trace_log_size != expected_trace_log or
        !std.mem.eql(u8, key.preprocessed_root, &std.fmt.bytesToHex(expected_root, .lower)) or
        !std.mem.eql(u8, key.circuit_hash, &std.fmt.bytesToHex(expected_hash, .lower)))
        return error.InvalidVerificationKey;
}

fn verifyBytes(allocator: std.mem.Allocator, source: relation.Program, pp: *const preprocessed.PreprocessedCircuit, assignment: relation.Assignment, encoded: []const u8) !void {
    const public_words = try relation.claimedWords(allocator, source, assignment);
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const pcs = try showcasePcsConfig(pp.traceLogSize());
    const layout = pp.layout();
    const logs = try circuit.common.component_list.circuitComponentLogSizes(&layout);
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(logs, pcs.fri_config.log_blowup_factor, root);
    if (chip_mode) {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(embedded_source, &digest, .{});
        const spec = source.repeatedStepChip() orelse return error.UnsupportedChipRelation;
        try native.verifyHybrid(allocator, &layout, &bundle, pcs, root, hash, public_words, encoded, .{
            .source_digest = digest,
            .rounds = spec.rounds,
            .constant = M31.fromCanonical(spec.constant),
        });
    } else try native.verify(allocator, &layout, &bundle, pcs, root, hash, public_words, encoded);
}

fn parseAirBundle(allocator: std.mem.Allocator) !cpu.air.Bundle {
    var air_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(air_program_bytes, &air_digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(air_digest, .lower), cpu.air.bundle_sha256)) return error.AirBundleMismatch;
    var projection_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(projection_bytes, &projection_digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(projection_digest, .lower), projection_sha256)) return error.VerifierProjectionMismatch;
    return cpu.air.parse(allocator, air_program_bytes);
}
