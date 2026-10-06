//! One compiled S31 relation and its separately built native host verifier.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const s31 = @import("stwo_s31_prototype");
const native = @import("native_verifier.zig");
const recursion_gate = @import("recursion_gate.zig");
const fixed_fold = @import("fixed_fold.zig");
const state_fold = @import("state_fold.zig");
const relation = s31.relation;

const QM31 = core.fields.qm31.QM31;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const preprocessed = circuit.common.preprocessed;
const embedded_source = @embedFile("s31_program_source");
const projection_bytes = @embedFile("s31_air_projection");
const air_program_bytes = @embedFile("s31_air_programs");
const sealed_prover_key = @embedFile("s31_verification_key");
const sealed_prover_recursive_key = @embedFile("s31_recursive_key");
const sealed_prover_recursive_next_key = @embedFile("s31_recursive_next_key");
const sealed_prover_fold_key = @embedFile("s31_fold_key");
const sealed_prover_state_fold_key = @embedFile("s31_state_fold_key");
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

const RecursiveChainStatement = struct {
    schema: []const u8,
    leaf: RecursiveStatement,
    head: RecursiveStatement,
};

const RecursiveKey = struct {
    schema: []const u8,
    child_key_sha256: []const u8,
    projection_sha256: []const u8,
    air_bundle_sha256: []const u8,
    outer_preprocessed_root: []const u8,
    outer_circuit_hash: []const u8,
    outer_padded: Rows,
    outer_trace_log_size: u32,
};

const FoldKey = struct {
    schema: []const u8,
    base_recursive_key_sha256: []const u8,
    projection_sha256: []const u8,
    air_bundle_sha256: []const u8,
    fold_preprocessed_root: []const u8,
    fold_circuit_hash: []const u8,
    padded: Rows,
    trace_log_size: u32,
};

const StateFoldKey = struct {
    schema: []const u8,
    base_recursive_key_sha256: []const u8,
    projection_sha256: []const u8,
    air_bundle_sha256: []const u8,
    source_rounds: u32,
    step_body: []const relation.Step,
    fold_preprocessed_root: []const u8,
    fold_circuit_hash: []const u8,
    padded: Rows,
    trace_log_size: u32,
};

const StateFoldStatement = struct {
    schema: []const u8,
    state_fold_key_sha256: []const u8,
    step: u16,
    leaf_public_words: [8]u32,
    base_public_words: [8]u32,
    initial_state: [4]u32,
    current_state: [4]u32,
    fold_public_words: [8]u32,
    fold_preprocessed_root: []const u8,
    fold_circuit_hash: []const u8,
};

const FoldStatement = struct {
    schema: []const u8,
    fold_key_sha256: []const u8,
    step: u16,
    leaf_public_words: [8]u32,
    base_public_words: [8]u32,
    fold_public_words: [8]u32,
    fold_preprocessed_root: []const u8,
    fold_circuit_hash: []const u8,
};

const RecursiveGeometry = struct {
    root: [32]u8,
    hash: [32]u8,
    padded: Rows,
    trace_log_size: u32,
};

const VerifiedRecursiveStatement = struct {
    layout: preprocessed.ColumnLayout,
    pcs: PcsConfigV2,
    root: [32]u8,
    hash: [32]u8,
};

const VerifiedFoldKey = struct {
    layout: preprocessed.ColumnLayout,
    pcs: PcsConfigV2,
    base_root: [32]u8,
    root: [32]u8,
    hash: [32]u8,
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
    repeated_step: ?relation.ChipSpec,
    state_fold_step: ?relation.StateFoldSpec,
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
        try prove(allocator, parsed.value, args[2], args[3], null, false, null, null, false);
    } else if (std.mem.eql(u8, command, "recurse-check") and args.len == 5 and !chip_mode and !sparse_mode and !direct_mode) {
        try prove(allocator, parsed.value, args[2], args[3], null, true, null, args[4], false);
    } else if (std.mem.eql(u8, command, "recurse-prove") and (args.len == 6 or (args.len == 7 and std.mem.eql(u8, args[6], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try prove(allocator, parsed.value, args[2], args[3], null, true, args[4], args[5], args.len == 7);
    } else if (std.mem.eql(u8, command, "recurse-wrap") and (args.len == 6 or (args.len == 7 and std.mem.eql(u8, args[6], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapExisting(allocator, parsed.value, args[2], args[3], args[4], args[5], false, args.len == 7);
    } else if (std.mem.eql(u8, command, "recurse-wrap-next") and (args.len == 8 or (args.len == 9 and std.mem.eql(u8, args[8], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapNextOuter(allocator, parsed.value, args[2], args[3], args[4], args[5], args[6], args[7], false, args.len == 9);
    } else if (std.mem.eql(u8, command, "recurse-audit-next") and args.len == 6 and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapNextOuter(allocator, parsed.value, args[2], args[3], null, args[4], args[5], null, true, false);
    } else if (std.mem.eql(u8, command, "recurse-audit") and args.len == 5 and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapExisting(allocator, parsed.value, args[2], args[3], null, args[4], true, false);
    } else if (std.mem.eql(u8, command, "recurse-keygen") and args.len == 4 and !chip_mode and !sparse_mode and !direct_mode) {
        try generateRecursiveKey(allocator, parsed.value, args[2], args[3]);
    } else if (std.mem.eql(u8, command, "recurse-keygen-next") and args.len == 5 and !chip_mode and !sparse_mode and !direct_mode) {
        try generateNextRecursiveKey(allocator, parsed.value, args[2], args[3], args[4]);
    } else if (std.mem.eql(u8, command, "fold-keygen") and args.len == 5 and !chip_mode and !sparse_mode and !direct_mode) {
        try generateFoldKey(allocator, parsed.value, args[2], args[3], args[4]);
    } else if (std.mem.eql(u8, command, "state-fold-keygen") and args.len == 5 and !chip_mode and !sparse_mode and !direct_mode) {
        try generateStateFoldKey(allocator, parsed.value, args[2], args[3], args[4]);
    } else if (std.mem.eql(u8, command, "state-fold-wrap-base") and (args.len == 8 or (args.len == 9 and std.mem.eql(u8, args[8], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapStateFold(allocator, parsed.value, args[2], args[3], args[4], args[5], args[6], args[7], true, args.len == 9, false);
    } else if (std.mem.eql(u8, command, "state-fold-wrap-next") and (args.len == 8 or (args.len == 9 and std.mem.eql(u8, args[8], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapStateFold(allocator, parsed.value, args[2], args[3], args[4], args[5], args[6], args[7], false, args.len == 9, false);
    } else if (std.mem.eql(u8, command, "state-fold-wrap-batch") and (args.len == 12 or (args.len == 13 and std.mem.eql(u8, args[12], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapStateFoldBatch(allocator, parsed.value, args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args.len == 13);
    } else if (std.mem.eql(u8, command, "state-fold-audit-base") and args.len == 7 and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapStateFold(allocator, parsed.value, args[2], args[3], "", args[4], args[5], args[6], true, false, true);
    } else if (std.mem.eql(u8, command, "state-fold-audit-next") and args.len == 7 and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapStateFold(allocator, parsed.value, args[2], args[3], "", args[4], args[5], args[6], false, false, true);
    } else if (std.mem.eql(u8, command, "fold-inspect") and args.len == 5 and !chip_mode and !sparse_mode and !direct_mode) {
        try inspectFold(allocator, parsed.value, args[2], args[3], args[4]);
    } else if (std.mem.eql(u8, command, "state-fold-inspect") and args.len == 5 and !chip_mode and !sparse_mode and !direct_mode) {
        try inspectStateFold(allocator, parsed.value, args[2], args[3], args[4]);
    } else if (std.mem.eql(u8, command, "fold-audit") and args.len == 7 and !chip_mode and !sparse_mode and !direct_mode) {
        try auditFoldBase(allocator, parsed.value, args[2], args[3], args[4], args[5], args[6]);
    } else if (std.mem.eql(u8, command, "fold-wrap-base") and (args.len == 8 or (args.len == 9 and std.mem.eql(u8, args[8], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapFold(allocator, parsed.value, args[2], args[3], args[4], args[5], args[6], args[7], true, args.len == 9, false);
    } else if (std.mem.eql(u8, command, "fold-wrap-next") and (args.len == 8 or (args.len == 9 and std.mem.eql(u8, args[8], "--low-memory"))) and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapFold(allocator, parsed.value, args[2], args[3], args[4], args[5], args[6], args[7], false, args.len == 9, false);
    } else if (std.mem.eql(u8, command, "fold-audit-next") and args.len == 7 and !chip_mode and !sparse_mode and !direct_mode) {
        try wrapFold(allocator, parsed.value, args[2], args[3], "", args[4], args[5], args[6], false, false, true);
    } else if (std.mem.eql(u8, command, "prove-adversarial") and args.len == 5 and (sparse_mode or direct_mode) and chip_mode) {
        const mutation = std.meta.stringToEnum(cpu.sparse_arithmetic.Mutation, args[4]) orelse
            return error.InvalidMutation;
        try prove(allocator, parsed.value, args[2], args[3], mutation, false, null, null, false);
    } else return usage();
}

/// Entry point of the separately installed verifier binary. Its accepted
/// program is fixed by `embedded_source` at compile time.
pub fn verifierMain(embedded_key: []const u8, embedded_recursive_key: []const u8, embedded_recursive_next_key: []const u8, embedded_fold_key: []const u8, embedded_state_fold_key: []const u8) !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "recurse-verify"))
        return verifyOuter(allocator, args[2], args[3], embedded_key, embedded_recursive_key);
    if (args.len == 4 and std.mem.eql(u8, args[1], "recurse-verify-next"))
        return verifyNextOuter(allocator, args[2], args[3], embedded_key, embedded_recursive_key, embedded_recursive_next_key);
    if (args.len == 4 and std.mem.eql(u8, args[1], "fold-verify"))
        return verifyFold(allocator, args[2], args[3], embedded_key, embedded_recursive_key, embedded_fold_key);
    if (args.len == 4 and std.mem.eql(u8, args[1], "state-fold-verify"))
        return verifyStateFold(allocator, args[2], args[3], embedded_key, embedded_recursive_key, embedded_state_fold_key);
    if (args.len != 4) {
        std.debug.print("usage: s31-PROGRAM-native-verifier PROOF PUBLIC-STATEMENT.json VERIFICATION-KEY.json\n       recurse-verify PROOF STATEMENT.json | recurse-verify-next PROOF CHAIN.json | fold-verify PROOF FOLD-STATEMENT.json\n", .{});
        return error.InvalidArguments;
    }
    try verify(allocator, args[1], args[2], args[3], embedded_key);
}

fn usage() error{InvalidArguments} {
    std.debug.print("usage: s31-program check | inspect | run ASSIGNMENT.json | prove ASSIGNMENT.json PROOF\n", .{});
    std.debug.print("       recurse-check ASSIGNMENT.json CHILD-PROOF CHILD-KEY.json | recurse-prove ASSIGNMENT.json CHILD-PROOF OUTER-PROOF CHILD-KEY.json [--low-memory]\n", .{});
    std.debug.print("       recurse-wrap CHILD-PROOF CHILD-STATEMENT.json OUTER-PROOF CHILD-KEY.json [--low-memory]\n", .{});
    std.debug.print("       recurse-wrap-next OUTER-PROOF OUTER-STATEMENT.json NEXT-PROOF CHILD-KEY.json RECURSIVE-KEY.json NEXT-KEY.json [--low-memory]\n", .{});
    std.debug.print("       recurse-audit CHILD-PROOF CHILD-STATEMENT.json CHILD-KEY.json | recurse-audit-next OUTER-PROOF OUTER-STATEMENT.json CHILD-KEY.json RECURSIVE-KEY.json\n", .{});
    std.debug.print("       recurse-keygen CHILD-KEY.json RECURSIVE-KEY.json | recurse-keygen-next CHILD-KEY.json RECURSIVE-KEY.json NEXT-KEY.json\n", .{});
    std.debug.print("       fold-keygen CHILD-KEY.json RECURSIVE-KEY.json FOLD-KEY.json | fold-inspect CHILD-KEY RECURSIVE-KEY FOLD-KEY\n", .{});
    std.debug.print("       fold-audit FIRST-PROOF FIRST-STATEMENT CHILD-KEY RECURSIVE-KEY FOLD-KEY\n", .{});
    std.debug.print("       fold-wrap-base|fold-wrap-next CHILD-PROOF CHILD-STATEMENT OUT-PROOF CHILD-KEY RECURSIVE-KEY FOLD-KEY [--low-memory]\n", .{});
    std.debug.print("       fold-audit-next FOLD-PROOF FOLD-STATEMENT CHILD-KEY RECURSIVE-KEY FOLD-KEY\n", .{});
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

fn checkedChildKeyDigest(allocator: std.mem.Allocator, source: relation.Program, path: []const u8) ![32]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 4096);
    defer allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var parsed = try std.json.parseFromSlice(Key, allocator, bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    try validateKey(allocator, source, parsed.value);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
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
    try circuit.common.finalize.padToTargets(V, ctx, .{
        .eq = if (wide_mode) circuit.common.finalize.paddedSize(raw.eq) else 0,
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = if (direct_mode) 0 else circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    });
    if (direct_mode and try ctx.circuit.firstYieldViolation(ctx.gpa) != null)
        return error.InvalidDirectYieldTopology;
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
        .repeated_step = source.repeatedStepChip(),
        .state_fold_step = source.stateFoldStep(),
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

fn prove(allocator: std.mem.Allocator, source: relation.Program, assignment_path: []const u8, path: []const u8, mutation: ?cpu.sparse_arithmetic.Mutation, recurse_check: bool, outer_path: ?[]const u8, child_key_path: ?[]const u8, low_memory: bool) !void {
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
        var captured_child: ?cpu.verifier_proof.VerifierProof = null;
        defer if (captured_child) |*captured| captured.deinit();
        if (recurse_check and outer_path != null) {
            // The production one-shot wrapper consumes openings captured by
            // the native verifier from the serialized child proof, exactly
            // like recurse-wrap. This is one verification, not a separate
            // metadata conversion after an independent verification pass.
            const child_layout = pp.layout();
            const child_pcs = try showcasePcsConfig(pp.traceLogSize());
            const child_root = committed.root();
            const canonical_root = try pp.preprocessedRoot(allocator, child_pcs.fri_config.log_blowup_factor);
            if (!std.mem.eql(u8, &child_root, &canonical_root)) return error.RecursiveChildRootMismatch;
            const child_hash = try circuit.common.circuit_hash.hostCircuitHash(
                try circuit.common.component_list.circuitComponentLogSizes(&child_layout),
                child_pcs.fri_config.log_blowup_factor,
                child_root,
            );
            captured_child = try native.verifyAndCapture(
                allocator,
                &child_layout,
                &bundle,
                child_pcs,
                child_root,
                child_hash,
                public_words,
                encoded,
            );
        } else try verifyBytes(allocator, source, &pp, assignment.value, encoded);
        if (recurse_check) {
            const layout = pp.layout();
            const root = committed.root();
            const child_key_digest = try checkedChildKeyDigest(allocator, source, child_key_path.?);
            const expected: recursion_gate.Expected = .{
                .preprocessed_root = root,
                .circuit_hash = try circuit.common.circuit_hash.hostCircuitHash(
                    try circuit.common.component_list.circuitComponentLogSizes(&layout),
                    pcs.fri_config.log_blowup_factor,
                    root,
                ),
                .child_key_digest = child_key_digest,
                .public_words = public_words,
            };
            var recursive = if (captured_child) |*captured|
                try recursion_gate.verifyPrepared(allocator, projection_bytes, layout, pcs, captured, expected)
            else
                try recursion_gate.verifyChild(allocator, projection_bytes, layout, &proof, expected);
            defer recursive.deinit();
            if (outer_path == null) {
                var prover_material = try cpu.verifier_proof.prepare(allocator, &proof);
                defer prover_material.deinit();
                var verified_material = try native.verifyAndCapture(
                    allocator,
                    &layout,
                    &bundle,
                    pcs,
                    root,
                    expected.circuit_hash,
                    public_words,
                    encoded,
                );
                defer verified_material.deinit();
                const prover_wire = try prover_material.serialize(allocator);
                defer allocator.free(prover_wire);
                const verified_wire = try verified_material.serialize(allocator);
                defer allocator.free(verified_wire);
                if (!std.mem.eql(u8, prover_wire, verified_wire)) return error.RecursiveProofConversionMismatch;
                std.debug.print("S31 recursive conversion parity: {d} bytes identical\n", .{prover_wire.len});
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
                inline for (.{ .preprocessed_root, .trace_root, .claimed_sum, .channel_salt, .fri_witness, .fri_last_layer }) |corruption| {
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
            if (outer_path) |destination| try proveOuter(allocator, source, &recursive, layout, pcs, &bundle, expected, destination, child_key_path.?, low_memory);
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
    low_memory: bool,
) !void {
    const key_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(key_bytes);
    if (!std.mem.eql(u8, key_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var parsed_key = try std.json.parseFromSlice(Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_key.deinit();
    try validateKey(allocator, source, parsed_key.value);
    if (!std.mem.eql(u8, parsed_key.value.preprocessed_root, &std.fmt.bytesToHex(expected_child.preprocessed_root, .lower)) or
        !std.mem.eql(u8, parsed_key.value.circuit_hash, &std.fmt.bytesToHex(expected_child.circuit_hash, .lower)))
        return error.RecursiveChildKeyMismatch;
    var child_key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_bytes, &child_key_digest, .{});
    if (!std.mem.eql(u8, &child_key_digest, &expected_child.child_key_digest)) return error.RecursiveChildKeyMismatch;
    const recursive_key_path = try std.fs.path.join(allocator, &.{
        std.fs.path.dirname(child_key_path) orelse ".",
        "recursive-verification-key.json",
    });
    defer allocator.free(recursive_key_path);
    const recursive_bytes = try std.fs.cwd().readFileAlloc(allocator, recursive_key_path, 4096);
    defer allocator.free(recursive_bytes);
    if (!std.mem.eql(u8, recursive_bytes, sealed_prover_recursive_key)) return error.UnsealedRecursiveKey;
    try proveOuterCircuit(allocator, values, child_layout, child_pcs, bundle, expected_child, path, recursive_bytes, low_memory);
}

fn proveOuterCircuit(
    allocator: std.mem.Allocator,
    values: *circuit.builder.Context(QM31),
    child_layout: preprocessed.ColumnLayout,
    child_pcs: PcsConfigV2,
    bundle: *const cpu.air.Bundle,
    expected_child: recursion_gate.Expected,
    path: []const u8,
    recursive_bytes: []const u8,
    low_memory: bool,
) !void {
    var pp = blk: {
        var topology_ctx = try recursion_gate.topology(allocator, projection_bytes, child_layout, child_pcs, expected_child.child_key_digest, expected_child.preprocessed_root);
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
    const layout = pp.layout();
    const root = committed.root();
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    var parsed_recursive = try std.json.parseFromSlice(RecursiveKey, allocator, recursive_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_recursive.deinit();
    const recursive_key = parsed_recursive.value;
    const sealed_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = recursive_key.outer_padded.eq,
        .qm31_ops = recursive_key.outer_padded.qm31_ops,
        .triple_xor = recursive_key.outer_padded.triple_xor,
        .m31_to_u32 = recursive_key.outer_padded.m31_to_u32,
        .blake_g_gate = recursive_key.outer_padded.blake_g,
    });
    if (!std.mem.eql(u8, recursive_key.schema, "s31-recursive-verification-key-v2") or
        !std.mem.eql(u8, recursive_key.child_key_sha256, &std.fmt.bytesToHex(expected_child.child_key_digest, .lower)) or
        !std.mem.eql(u8, recursive_key.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, recursive_key.air_bundle_sha256, cpu.air.bundle_sha256) or
        !layout.eql(&sealed_layout) or
        recursive_key.outer_trace_log_size != layout.traceLogSize() or
        !std.mem.eql(u8, recursive_key.outer_preprocessed_root, &std.fmt.bytesToHex(root, .lower)) or
        !std.mem.eql(u8, recursive_key.outer_circuit_hash, &std.fmt.bytesToHex(hash, .lower)))
        return error.RecursiveOuterKeyMismatch;
    var timer = try std.time.Timer.start();
    var outer = try cpu.Internal.prove(allocator, values.values(), &pp, bundle, pcs, .{
        .preprocessed_commitment = &committed,
        .evaluations_only = low_memory,
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
    if (!std.meta.eql(public_words, recursion_gate.statementDigest(expected_child.child_key_digest, expected_child.public_words)))
        return error.RecursiveStatementDigestMismatch;
    const encoded = try native.serialize(allocator, &outer);
    defer allocator.free(encoded);
    try native.verify(allocator, &layout, bundle, pcs, root, hash, public_words, encoded);
    try std.fs.cwd().makePath(std.fs.path.dirname(path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = encoded });
    const key_hex = std.fmt.bytesToHex(expected_child.child_key_digest, .lower);
    const root_hex = std.fmt.bytesToHex(root, .lower);
    const hash_hex = std.fmt.bytesToHex(hash, .lower);
    const statement: RecursiveStatement = .{
        .schema = "s31-recursive-gate-statement-v2",
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
    outer_path: ?[]const u8,
    child_key_path: []const u8,
    audit_only: bool,
    low_memory: bool,
) !void {
    const key_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(key_bytes);
    if (!std.mem.eql(u8, key_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
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
    var child_key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_bytes, &child_key_digest, .{});
    _ = try std.fmt.hexToBytes(&root, key.preprocessed_root);
    _ = try std.fmt.hexToBytes(&hash, key.circuit_hash);
    const expected: recursion_gate.Expected = .{
        .preprocessed_root = root,
        .circuit_hash = hash,
        .child_key_digest = child_key_digest,
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
    if (!try recursive.isCircuitValid()) return error.InvalidRecursiveCircuit;
    if (audit_only) {
        var wrong_statement = expected;
        wrong_statement.public_words[0] = (wrong_statement.public_words[0] + 1) % core.fields.m31.Modulus;
        if (recursion_gate.verifyPrepared(allocator, projection_bytes, layout, pcs, &converted, wrong_statement)) |accepted| {
            var invalid = accepted;
            invalid.deinit();
            return error.RecursiveVerifierAcceptedWrongStatement;
        } else |err| switch (err) {
            error.VerificationFailed, error.EqFailedOnEval => {},
            else => return err,
        }
        inline for (.{ .preprocessed_root, .trace_root, .claimed_sum, .channel_salt, .fri_witness, .fri_last_layer }) |corruption| {
            if (recursion_gate.verifyPreparedWithMutation(allocator, projection_bytes, layout, pcs, &converted, expected, corruption)) |accepted| {
                var invalid = accepted;
                invalid.deinit();
                return error.RecursiveVerifierAcceptedCorruptProof;
            } else |err| switch (err) {
                error.VerificationFailed, error.EqFailedOnEval => {},
                else => return err,
            }
        }
        std.debug.print("S31 recursive saved child audit: valid=true rejected=7\n", .{});
        return;
    }
    std.debug.print("S31 recursive saved child: vars={d} qm31_ops={d} valid=true\n", .{
        recursive.circuit.n_vars,
        recursive.circuit.mul.items.len + recursive.circuit.add.items.len + recursive.circuit.sub.items.len,
    });
    try proveOuter(allocator, source, &recursive, layout, pcs, &bundle, expected, outer_path.?, child_key_path, low_memory);
}

fn wrapNextOuter(
    allocator: std.mem.Allocator,
    source: relation.Program,
    first_proof_path: []const u8,
    first_statement_path: []const u8,
    next_proof_path: ?[]const u8,
    child_key_path: []const u8,
    first_key_path: []const u8,
    next_key_path: ?[]const u8,
    audit_only: bool,
    low_memory: bool,
) !void {
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    if (!std.mem.eql(u8, child_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var parsed_child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_child.deinit();
    try validateKey(allocator, source, parsed_child.value);
    const first_key_bytes = try std.fs.cwd().readFileAlloc(allocator, first_key_path, 4096);
    defer allocator.free(first_key_bytes);
    if (!std.mem.eql(u8, first_key_bytes, sealed_prover_recursive_key)) return error.UnsealedRecursiveKey;
    var parsed_first_key = try std.json.parseFromSlice(RecursiveKey, allocator, first_key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_first_key.deinit();
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    const first_statement_bytes = try std.fs.cwd().readFileAlloc(allocator, first_statement_path, 4096);
    defer allocator.free(first_statement_bytes);
    var parsed_first_statement = try std.json.parseFromSlice(RecursiveStatement, allocator, first_statement_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_first_statement.deinit();
    const first_statement = parsed_first_statement.value;
    const verified_first = try validateRecursiveStatement(first_statement, child_digest, parsed_first_key.value, true);
    const first_proof_bytes = try std.fs.cwd().readFileAlloc(allocator, first_proof_path, 16 << 20);
    defer allocator.free(first_proof_bytes);
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    var captured = try native.verifyAndCapture(allocator, &verified_first.layout, &bundle, verified_first.pcs, verified_first.root, verified_first.hash, first_statement.outer_public_words, first_proof_bytes);
    defer captured.deinit();
    var first_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(first_key_bytes, &first_digest, .{});
    const expected: recursion_gate.Expected = .{
        .preprocessed_root = verified_first.root,
        .circuit_hash = verified_first.hash,
        .child_key_digest = first_digest,
        .public_words = first_statement.outer_public_words,
    };
    var recursive = try recursion_gate.verifyPrepared(allocator, projection_bytes, verified_first.layout, verified_first.pcs, &captured, expected);
    defer recursive.deinit();
    if (!try recursive.isCircuitValid()) return error.InvalidRecursiveCircuit;
    if (audit_only) {
        var wrong_statement = expected;
        wrong_statement.public_words[0] ^= 1;
        if (recursion_gate.verifyPrepared(allocator, projection_bytes, verified_first.layout, verified_first.pcs, &captured, wrong_statement)) |accepted| {
            var invalid = accepted;
            invalid.deinit();
            return error.RecursiveVerifierAcceptedWrongStatement;
        } else |err| switch (err) {
            error.VerificationFailed, error.EqFailedOnEval => {},
            else => return err,
        }
        inline for (.{ .preprocessed_root, .trace_root, .claimed_sum, .channel_salt, .fri_witness, .fri_last_layer }) |corruption| {
            if (recursion_gate.verifyPreparedWithMutation(allocator, projection_bytes, verified_first.layout, verified_first.pcs, &captured, expected, corruption)) |accepted| {
                var invalid = accepted;
                invalid.deinit();
                return error.RecursiveVerifierAcceptedCorruptProof;
            } else |err| switch (err) {
                error.VerificationFailed, error.EqFailedOnEval => {},
                else => return err,
            }
        }
        std.debug.print("S31 recursive level-2 circuit audit: valid=true rejected=7\n", .{});
        return;
    }
    const next_key_bytes = try std.fs.cwd().readFileAlloc(allocator, next_key_path.?, 4096);
    defer allocator.free(next_key_bytes);
    if (!std.mem.eql(u8, next_key_bytes, sealed_prover_recursive_next_key)) return error.UnsealedRecursiveKey;
    try proveOuterCircuit(allocator, &recursive, verified_first.layout, verified_first.pcs, &bundle, expected, next_proof_path.?, next_key_bytes, low_memory);
    const next_statement_path = try std.fmt.allocPrint(allocator, "{s}.statement.json", .{next_proof_path.?});
    defer allocator.free(next_statement_path);
    const next_statement_bytes = try std.fs.cwd().readFileAlloc(allocator, next_statement_path, 4096);
    defer allocator.free(next_statement_bytes);
    var parsed_next_statement = try std.json.parseFromSlice(RecursiveStatement, allocator, next_statement_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_next_statement.deinit();
    const chain: RecursiveChainStatement = .{
        .schema = "s31-recursive-chain-statement-v1",
        .leaf = first_statement,
        .head = parsed_next_statement.value,
    };
    const chain_bytes = try std.json.Stringify.valueAlloc(allocator, chain, .{});
    defer allocator.free(chain_bytes);
    try std.fs.cwd().writeFile(.{ .sub_path = next_statement_path, .data = chain_bytes });
    try verifyNextOuter(allocator, next_proof_path.?, next_statement_path, child_bytes, first_key_bytes, next_key_bytes);
}

fn generateRecursiveKey(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_key_path: []const u8,
    output_path: []const u8,
) !void {
    const key_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(key_bytes);
    var parsed_key = try std.json.parseFromSlice(Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_key.deinit();
    try validateKey(allocator, source, parsed_key.value);
    const child_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = parsed_key.value.padded.eq,
        .qm31_ops = parsed_key.value.padded.qm31_ops,
        .triple_xor = parsed_key.value.padded.triple_xor,
        .m31_to_u32 = parsed_key.value.padded.m31_to_u32,
        .blake_g_gate = parsed_key.value.padded.blake_g,
    });
    if (child_layout.traceLogSize() != parsed_key.value.trace_log_size)
        return error.InvalidVerificationKey;
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_bytes, &child_digest, .{});
    var child_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&child_root, parsed_key.value.preprocessed_root);
    const geometry = try buildRecursiveGeometry(allocator, child_layout, try showcasePcsConfig(parsed_key.value.trace_log_size), child_digest, child_root);
    try writeRecursiveKey(allocator, output_path, child_digest, geometry);
}

fn buildRecursiveGeometry(
    allocator: std.mem.Allocator,
    child_layout: preprocessed.ColumnLayout,
    child_pcs: PcsConfigV2,
    child_digest: [32]u8,
    child_root: [32]u8,
) !RecursiveGeometry {
    var topology_ctx = try recursion_gate.topology(allocator, projection_bytes, child_layout, child_pcs, child_digest, child_root);
    defer topology_ctx.deinit();
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
    const padded = circuit.common.finalize.rawComponentSizes(
        preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit),
    );
    var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    defer pp.deinit(allocator);
    const pcs = try showcasePcsConfig(pp.traceLogSize());
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const layout = pp.layout();
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    return .{
        .root = root,
        .hash = hash,
        .padded = .{
            .eq = padded.eq,
            .qm31_ops = padded.qm31_ops,
            .triple_xor = padded.triple_xor,
            .m31_to_u32 = padded.m31_to_u32,
            .blake_g = padded.blake_g_gate,
        },
        .trace_log_size = pp.traceLogSize(),
    };
}

fn writeRecursiveKey(allocator: std.mem.Allocator, output_path: []const u8, child_digest: [32]u8, geometry: RecursiveGeometry) !void {
    const child_hex = std.fmt.bytesToHex(child_digest, .lower);
    const root_hex = std.fmt.bytesToHex(geometry.root, .lower);
    const hash_hex = std.fmt.bytesToHex(geometry.hash, .lower);
    const recursive_key: RecursiveKey = .{
        .schema = "s31-recursive-verification-key-v2",
        .child_key_sha256 = &child_hex,
        .projection_sha256 = projection_sha256,
        .air_bundle_sha256 = cpu.air.bundle_sha256,
        .outer_preprocessed_root = &root_hex,
        .outer_circuit_hash = &hash_hex,
        .outer_padded = geometry.padded,
        .outer_trace_log_size = geometry.trace_log_size,
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, recursive_key, .{});
    defer allocator.free(encoded);
    try std.fs.cwd().makePath(std.fs.path.dirname(output_path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = output_path, .data = encoded });
}

fn generateNextRecursiveKey(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_key_path: []const u8,
    recursive_key_path: []const u8,
    output_path: []const u8,
) !void {
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    var parsed_child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_child.deinit();
    try validateKey(allocator, source, parsed_child.value);
    const parent_bytes = try std.fs.cwd().readFileAlloc(allocator, recursive_key_path, 4096);
    defer allocator.free(parent_bytes);
    var parsed_parent = try std.json.parseFromSlice(RecursiveKey, allocator, parent_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_parent.deinit();
    const parent = parsed_parent.value;
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    if (!std.mem.eql(u8, parent.schema, "s31-recursive-verification-key-v2") or
        !std.mem.eql(u8, parent.child_key_sha256, &std.fmt.bytesToHex(child_digest, .lower)) or
        !std.mem.eql(u8, parent.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, parent.air_bundle_sha256, cpu.air.bundle_sha256))
        return error.InvalidRecursiveVerificationKey;
    const child_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = parsed_child.value.padded.eq,
        .qm31_ops = parsed_child.value.padded.qm31_ops,
        .triple_xor = parsed_child.value.padded.triple_xor,
        .m31_to_u32 = parsed_child.value.padded.m31_to_u32,
        .blake_g_gate = parsed_child.value.padded.blake_g,
    });
    if (child_layout.traceLogSize() != parsed_child.value.trace_log_size) return error.InvalidVerificationKey;
    var child_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&child_root, parsed_child.value.preprocessed_root);
    const expected_parent = try buildRecursiveGeometry(allocator, child_layout, try showcasePcsConfig(child_layout.traceLogSize()), child_digest, child_root);
    if (!std.mem.eql(u8, parent.outer_preprocessed_root, &std.fmt.bytesToHex(expected_parent.root, .lower)) or
        !std.mem.eql(u8, parent.outer_circuit_hash, &std.fmt.bytesToHex(expected_parent.hash, .lower)) or
        !std.meta.eql(parent.outer_padded, expected_parent.padded) or
        parent.outer_trace_log_size != expected_parent.trace_log_size)
        return error.InvalidRecursiveVerificationKey;
    const parent_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = parent.outer_padded.eq,
        .qm31_ops = parent.outer_padded.qm31_ops,
        .triple_xor = parent.outer_padded.triple_xor,
        .m31_to_u32 = parent.outer_padded.m31_to_u32,
        .blake_g_gate = parent.outer_padded.blake_g,
    });
    if (parent_layout.traceLogSize() != parent.outer_trace_log_size) return error.InvalidRecursiveVerificationKey;
    var parent_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(parent_bytes, &parent_digest, .{});
    const next = try buildRecursiveGeometry(allocator, parent_layout, try showcasePcsConfig(parent_layout.traceLogSize()), parent_digest, expected_parent.root);
    try writeRecursiveKey(allocator, output_path, parent_digest, next);
}

fn generateFoldKey(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_key_path: []const u8,
    recursive_key_path: []const u8,
    output_path: []const u8,
) !void {
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    var parsed_child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_child.deinit();
    try validateKey(allocator, source, parsed_child.value);
    const first_bytes = try std.fs.cwd().readFileAlloc(allocator, recursive_key_path, 4096);
    defer allocator.free(first_bytes);
    var parsed_first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_first.deinit();
    const first = parsed_first.value;
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    if (!std.mem.eql(u8, first.schema, "s31-recursive-verification-key-v2") or
        !std.mem.eql(u8, first.child_key_sha256, &std.fmt.bytesToHex(child_digest, .lower)) or
        !std.mem.eql(u8, first.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, first.air_bundle_sha256, cpu.air.bundle_sha256))
        return error.InvalidRecursiveVerificationKey;
    const child_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = parsed_child.value.padded.eq,
        .qm31_ops = parsed_child.value.padded.qm31_ops,
        .triple_xor = parsed_child.value.padded.triple_xor,
        .m31_to_u32 = parsed_child.value.padded.m31_to_u32,
        .blake_g_gate = parsed_child.value.padded.blake_g,
    });
    if (child_layout.traceLogSize() != parsed_child.value.trace_log_size) return error.InvalidVerificationKey;
    var child_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&child_root, parsed_child.value.preprocessed_root);
    const expected_first = try buildRecursiveGeometry(allocator, child_layout, try showcasePcsConfig(child_layout.traceLogSize()), child_digest, child_root);
    if (!std.mem.eql(u8, first.outer_preprocessed_root, &std.fmt.bytesToHex(expected_first.root, .lower)) or
        !std.mem.eql(u8, first.outer_circuit_hash, &std.fmt.bytesToHex(expected_first.hash, .lower)) or
        !std.meta.eql(first.outer_padded, expected_first.padded) or
        first.outer_trace_log_size != expected_first.trace_log_size)
        return error.InvalidRecursiveVerificationKey;
    const first_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = first.outer_padded.eq,
        .qm31_ops = first.outer_padded.qm31_ops,
        .triple_xor = first.outer_padded.triple_xor,
        .m31_to_u32 = first.outer_padded.m31_to_u32,
        .blake_g_gate = first.outer_padded.blake_g,
    });
    if (first_layout.traceLogSize() != first.outer_trace_log_size) return error.InvalidRecursiveVerificationKey;
    var topology_ctx = try fixed_fold.topology(allocator, projection_bytes, first_layout, try showcasePcsConfig(first_layout.traceLogSize()), expected_first.root);
    defer topology_ctx.deinit();
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
    const padded = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit));
    var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    defer pp.deinit(allocator);
    const layout = pp.layout();
    if (!layout.eql(&first_layout)) return error.UnsupportedFixedFoldGeometry;
    const pcs = try showcasePcsConfig(layout.traceLogSize());
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    var first_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(first_bytes, &first_digest, .{});
    const first_hex = std.fmt.bytesToHex(first_digest, .lower);
    const root_hex = std.fmt.bytesToHex(root, .lower);
    const hash_hex = std.fmt.bytesToHex(hash, .lower);
    const fold_key: FoldKey = .{
        .schema = "s31-fixed-fold-verification-key-v2",
        .base_recursive_key_sha256 = &first_hex,
        .projection_sha256 = projection_sha256,
        .air_bundle_sha256 = cpu.air.bundle_sha256,
        .fold_preprocessed_root = &root_hex,
        .fold_circuit_hash = &hash_hex,
        .padded = .{
            .eq = padded.eq,
            .qm31_ops = padded.qm31_ops,
            .triple_xor = padded.triple_xor,
            .m31_to_u32 = padded.m31_to_u32,
            .blake_g = padded.blake_g_gate,
        },
        .trace_log_size = layout.traceLogSize(),
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, fold_key, .{});
    defer allocator.free(encoded);
    try std.fs.cwd().makePath(std.fs.path.dirname(output_path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = output_path, .data = encoded });
}

fn generateStateFoldKey(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_key_path: []const u8,
    recursive_key_path: []const u8,
    output_path: []const u8,
) !void {
    const spec = source.stateFoldStep() orelse return error.UnsupportedStateFoldSource;
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    var parsed_child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_child.deinit();
    try validateKey(allocator, source, parsed_child.value);
    const first_bytes = try std.fs.cwd().readFileAlloc(allocator, recursive_key_path, 4096);
    defer allocator.free(first_bytes);
    var parsed_first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_first.deinit();
    const first = parsed_first.value;
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    if (!std.mem.eql(u8, first.schema, "s31-recursive-verification-key-v2") or
        !std.mem.eql(u8, first.child_key_sha256, &std.fmt.bytesToHex(child_digest, .lower)) or
        !std.mem.eql(u8, first.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, first.air_bundle_sha256, cpu.air.bundle_sha256))
        return error.InvalidRecursiveVerificationKey;
    const child_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = parsed_child.value.padded.eq,
        .qm31_ops = parsed_child.value.padded.qm31_ops,
        .triple_xor = parsed_child.value.padded.triple_xor,
        .m31_to_u32 = parsed_child.value.padded.m31_to_u32,
        .blake_g_gate = parsed_child.value.padded.blake_g,
    });
    if (child_layout.traceLogSize() != parsed_child.value.trace_log_size) return error.InvalidVerificationKey;
    var child_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&child_root, parsed_child.value.preprocessed_root);
    const expected_first = try buildRecursiveGeometry(allocator, child_layout, try showcasePcsConfig(child_layout.traceLogSize()), child_digest, child_root);
    if (!std.mem.eql(u8, first.outer_preprocessed_root, &std.fmt.bytesToHex(expected_first.root, .lower)) or
        !std.mem.eql(u8, first.outer_circuit_hash, &std.fmt.bytesToHex(expected_first.hash, .lower)) or
        !std.meta.eql(first.outer_padded, expected_first.padded) or
        first.outer_trace_log_size != expected_first.trace_log_size)
        return error.InvalidRecursiveVerificationKey;
    const first_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = first.outer_padded.eq,
        .qm31_ops = first.outer_padded.qm31_ops,
        .triple_xor = first.outer_padded.triple_xor,
        .m31_to_u32 = first.outer_padded.m31_to_u32,
        .blake_g_gate = first.outer_padded.blake_g,
    });
    if (first_layout.traceLogSize() != first.outer_trace_log_size) return error.InvalidRecursiveVerificationKey;
    var topology_ctx = try state_fold.topology(allocator, projection_bytes, first_layout, try showcasePcsConfig(first_layout.traceLogSize()), expected_first.root, spec.body);
    defer topology_ctx.deinit();
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
    const padded = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit));
    var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    defer pp.deinit(allocator);
    const layout = pp.layout();
    if (!layout.eql(&first_layout)) return error.UnsupportedStateFoldGeometry;
    const pcs = try showcasePcsConfig(layout.traceLogSize());
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    var first_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(first_bytes, &first_digest, .{});
    const first_hex = std.fmt.bytesToHex(first_digest, .lower);
    const root_hex = std.fmt.bytesToHex(root, .lower);
    const hash_hex = std.fmt.bytesToHex(hash, .lower);
    const state_key: StateFoldKey = .{
        .schema = "s31-state-fold-verification-key-v2",
        .base_recursive_key_sha256 = &first_hex,
        .projection_sha256 = projection_sha256,
        .air_bundle_sha256 = cpu.air.bundle_sha256,
        .source_rounds = spec.rounds,
        .step_body = spec.body,
        .fold_preprocessed_root = &root_hex,
        .fold_circuit_hash = &hash_hex,
        .padded = .{
            .eq = padded.eq,
            .qm31_ops = padded.qm31_ops,
            .triple_xor = padded.triple_xor,
            .m31_to_u32 = padded.m31_to_u32,
            .blake_g = padded.blake_g_gate,
        },
        .trace_log_size = layout.traceLogSize(),
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, state_key, .{});
    defer allocator.free(encoded);
    try std.fs.cwd().makePath(std.fs.path.dirname(output_path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = output_path, .data = encoded });
}

fn auditFoldBase(
    allocator: std.mem.Allocator,
    source: relation.Program,
    first_proof_path: []const u8,
    first_statement_path: []const u8,
    child_key_path: []const u8,
    first_key_path: []const u8,
    fold_key_path: []const u8,
) !void {
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    if (!std.mem.eql(u8, child_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer child.deinit();
    try validateKey(allocator, source, child.value);
    const first_bytes = try std.fs.cwd().readFileAlloc(allocator, first_key_path, 4096);
    defer allocator.free(first_bytes);
    if (!std.mem.eql(u8, first_bytes, sealed_prover_recursive_key)) return error.UnsealedRecursiveKey;
    var first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer first.deinit();
    const statement_bytes = try std.fs.cwd().readFileAlloc(allocator, first_statement_path, 4096);
    defer allocator.free(statement_bytes);
    var statement = try std.json.parseFromSlice(RecursiveStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
    defer statement.deinit();
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    const verified = try validateRecursiveStatement(statement.value, child_digest, first.value, true);
    const fold_bytes = try std.fs.cwd().readFileAlloc(allocator, fold_key_path, 4096);
    defer allocator.free(fold_bytes);
    var fold = try std.json.parseFromSlice(FoldKey, allocator, fold_bytes, .{ .ignore_unknown_fields = false });
    defer fold.deinit();
    var first_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(first_bytes, &first_digest, .{});
    if (!std.mem.eql(u8, fold.value.schema, "s31-fixed-fold-verification-key-v2") or
        !std.mem.eql(u8, fold.value.base_recursive_key_sha256, &std.fmt.bytesToHex(first_digest, .lower)) or
        !std.mem.eql(u8, fold.value.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, fold.value.air_bundle_sha256, cpu.air.bundle_sha256))
        return error.InvalidFoldVerificationKey;
    const fold_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = fold.value.padded.eq,
        .qm31_ops = fold.value.padded.qm31_ops,
        .triple_xor = fold.value.padded.triple_xor,
        .m31_to_u32 = fold.value.padded.m31_to_u32,
        .blake_g_gate = fold.value.padded.blake_g,
    });
    if (!fold_layout.eql(&verified.layout) or fold_layout.traceLogSize() != fold.value.trace_log_size)
        return error.InvalidFoldVerificationKey;
    var fold_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fold_root, fold.value.fold_preprocessed_root);
    const fold_pcs = try showcasePcsConfig(fold_layout.traceLogSize());
    const fold_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&fold_layout),
        fold_pcs.fri_config.log_blowup_factor,
        fold_root,
    );
    if (!std.mem.eql(u8, fold.value.fold_circuit_hash, &std.fmt.bytesToHex(fold_hash, .lower)))
        return error.InvalidFoldVerificationKey;
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, first_proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    var captured = try native.verifyAndCapture(allocator, &verified.layout, &bundle, verified.pcs, verified.root, verified.hash, statement.value.outer_public_words, proof_bytes);
    defer captured.deinit();
    var values = try fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.root, fold_root, statement.value.outer_public_words, 0);
    defer values.deinit();
    var wrong_words = statement.value.outer_public_words;
    wrong_words[0] ^= 1;
    if (fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.root, fold_root, wrong_words, 0)) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.FoldVerifierAcceptedWrongLeaf;
    } else |err| switch (err) {
        error.VerificationFailed, error.EqFailedOnEval => {},
        else => return err,
    }
    var wrong_base_root = verified.root;
    wrong_base_root[0] ^= 1;
    if (fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, wrong_base_root, fold_root, statement.value.outer_public_words, 0)) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.FoldVerifierAcceptedWrongBaseRoot;
    } else |err| switch (err) {
        error.VerificationFailed, error.EqFailedOnEval => {},
        else => return err,
    }
    if (fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.root, fold_root, statement.value.outer_public_words, 1)) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.FoldVerifierAcceptedWrongStep;
    } else |err| switch (err) {
        error.VerificationFailed, error.EqFailedOnEval => {},
        else => return err,
    }
    inline for (.{ .base_selector, .zero_test_inverse, .previous_counter }) |mutation| {
        if (fixed_fold.verifyPreparedWithMutation(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.root, fold_root, statement.value.outer_public_words, 0, mutation)) |accepted| {
            var invalid = accepted;
            invalid.deinit();
            return error.FoldVerifierAcceptedForgedCounter;
        } else |err| switch (err) {
            error.VerificationFailed, error.EqFailedOnEval => {},
            else => return err,
        }
    }
    var topology_ctx = try fixed_fold.topology(allocator, projection_bytes, verified.layout, verified.pcs, verified.root);
    defer topology_ctx.deinit();
    if (!sameTopology(&values.circuit, &topology_ctx.circuit)) return error.FoldValueDependentTopology;
    try circuit.common.finalize.padContext(QM31, &values);
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
    if (!sameTopology(&values.circuit, &topology_ctx.circuit) or !try values.isCircuitValid())
        return error.InvalidFoldCircuit;
    var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    defer pp.deinit(allocator);
    const actual_root = try pp.preprocessedRoot(allocator, fold_pcs.fri_config.log_blowup_factor);
    if (!std.mem.eql(u8, &actual_root, &fold_root)) return error.FoldKeyTopologyMismatch;
    std.debug.print("S31 fixed-fold base audit: vars={d} qm31_ops={d} valid=true rejected=6\n", .{
        values.circuit.n_vars,
        values.circuit.mul.items.len + values.circuit.add.items.len + values.circuit.sub.items.len,
    });
}

fn validateFoldKey(child_bytes: []const u8, first_bytes: []const u8, first: RecursiveKey, fold: FoldKey) !VerifiedFoldKey {
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    if (!std.mem.eql(u8, first.schema, "s31-recursive-verification-key-v2") or
        !std.mem.eql(u8, first.child_key_sha256, &std.fmt.bytesToHex(child_digest, .lower)) or
        !std.mem.eql(u8, first.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, first.air_bundle_sha256, cpu.air.bundle_sha256))
        return error.InvalidRecursiveVerificationKey;
    var first_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(first_bytes, &first_digest, .{});
    if (!std.mem.eql(u8, fold.schema, "s31-fixed-fold-verification-key-v2") or
        !std.mem.eql(u8, fold.base_recursive_key_sha256, &std.fmt.bytesToHex(first_digest, .lower)) or
        !std.mem.eql(u8, fold.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, fold.air_bundle_sha256, cpu.air.bundle_sha256))
        return error.InvalidFoldVerificationKey;
    const first_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = first.outer_padded.eq,
        .qm31_ops = first.outer_padded.qm31_ops,
        .triple_xor = first.outer_padded.triple_xor,
        .m31_to_u32 = first.outer_padded.m31_to_u32,
        .blake_g_gate = first.outer_padded.blake_g,
    });
    const fold_layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = fold.padded.eq,
        .qm31_ops = fold.padded.qm31_ops,
        .triple_xor = fold.padded.triple_xor,
        .m31_to_u32 = fold.padded.m31_to_u32,
        .blake_g_gate = fold.padded.blake_g,
    });
    if (first_layout.traceLogSize() != first.outer_trace_log_size or
        fold_layout.traceLogSize() != fold.trace_log_size or
        !first_layout.eql(&fold_layout)) return error.InvalidFoldVerificationKey;
    const pcs = try showcasePcsConfig(fold_layout.traceLogSize());
    var base_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&base_root, first.outer_preprocessed_root);
    const base_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&first_layout),
        pcs.fri_config.log_blowup_factor,
        base_root,
    );
    if (!std.mem.eql(u8, first.outer_circuit_hash, &std.fmt.bytesToHex(base_hash, .lower)))
        return error.InvalidRecursiveVerificationKey;
    var root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&root, fold.fold_preprocessed_root);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&fold_layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    if (!std.mem.eql(u8, fold.fold_circuit_hash, &std.fmt.bytesToHex(hash, .lower)))
        return error.InvalidFoldVerificationKey;
    return .{ .layout = fold_layout, .pcs = pcs, .base_root = base_root, .root = root, .hash = hash };
}

fn validateStateFoldKey(
    child_bytes: []const u8,
    first_bytes: []const u8,
    first: RecursiveKey,
    key: StateFoldKey,
    spec: relation.StateFoldSpec,
) !VerifiedFoldKey {
    if (!std.mem.eql(u8, key.schema, "s31-state-fold-verification-key-v2") or
        key.source_rounds != spec.rounds or key.step_body.len != spec.body.len)
        return error.InvalidStateFoldVerificationKey;
    for (key.step_body, spec.body) |sealed, source_step| {
        if (sealed.op != source_step.op or sealed.constant != source_step.constant)
            return error.InvalidStateFoldVerificationKey;
    }
    // Both fold keys have the same layout and identity fields; the key's
    // domain, ordered transition body, and source rounds are checked above.
    const common: FoldKey = .{
        .schema = "s31-fixed-fold-verification-key-v2",
        .base_recursive_key_sha256 = key.base_recursive_key_sha256,
        .projection_sha256 = key.projection_sha256,
        .air_bundle_sha256 = key.air_bundle_sha256,
        .fold_preprocessed_root = key.fold_preprocessed_root,
        .fold_circuit_hash = key.fold_circuit_hash,
        .padded = key.padded,
        .trace_log_size = key.trace_log_size,
    };
    return validateFoldKey(child_bytes, first_bytes, first, common);
}

fn validateStateFoldStatement(
    statement: StateFoldStatement,
    child_bytes: []const u8,
    state_key_bytes: []const u8,
    verified: VerifiedFoldKey,
) !void {
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(state_key_bytes, &key_digest, .{});
    if (!std.mem.eql(u8, statement.schema, "s31-state-fold-statement-v1") or
        !std.mem.eql(u8, statement.state_fold_key_sha256, &std.fmt.bytesToHex(key_digest, .lower)) or
        !std.mem.eql(u8, statement.fold_preprocessed_root, &std.fmt.bytesToHex(verified.root, .lower)) or
        !std.mem.eql(u8, statement.fold_circuit_hash, &std.fmt.bytesToHex(verified.hash, .lower)))
        return error.InvalidStateFoldStatement;
    for (statement.leaf_public_words) |word| if (word >= core.fields.m31.Modulus) {
        return error.NoncanonicalPublicWord;
    };
    for (statement.initial_state, 0..) |word, i| {
        if (word >= core.fields.m31.Modulus or word != statement.leaf_public_words[4 + i])
            return error.InvalidStateFoldInitialState;
    }
    for (statement.current_state) |word| if (word >= core.fields.m31.Modulus) {
        return error.NoncanonicalState;
    };
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    const base = recursion_gate.statementDigest(child_digest, statement.leaf_public_words);
    if (!std.meta.eql(statement.base_public_words, base) or
        !std.meta.eql(statement.fold_public_words, state_fold.statementDigest(
            verified.root,
            statement.step,
            base,
            statement.initial_state,
            statement.current_state,
        ))) return error.InvalidStateFoldStatement;
}

fn inspectFold(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_key_path: []const u8,
    first_key_path: []const u8,
    fold_key_path: []const u8,
) !void {
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    if (!std.mem.eql(u8, child_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer child.deinit();
    try validateKey(allocator, source, child.value);
    const first_bytes = try std.fs.cwd().readFileAlloc(allocator, first_key_path, 4096);
    defer allocator.free(first_bytes);
    if (!std.mem.eql(u8, first_bytes, sealed_prover_recursive_key)) return error.UnsealedRecursiveKey;
    var first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer first.deinit();
    const fold_bytes = try std.fs.cwd().readFileAlloc(allocator, fold_key_path, 4096);
    defer allocator.free(fold_bytes);
    if (!std.mem.eql(u8, fold_bytes, sealed_prover_fold_key)) return error.UnsealedFoldKey;
    var fold = try std.json.parseFromSlice(FoldKey, allocator, fold_bytes, .{ .ignore_unknown_fields = false });
    defer fold.deinit();
    const verified = try validateFoldKey(child_bytes, first_bytes, first.value, fold.value);
    var topology_ctx = try fixed_fold.topology(allocator, projection_bytes, verified.layout, verified.pcs, verified.base_root);
    defer topology_ctx.deinit();
    try emitFoldGeometry(allocator, &topology_ctx, verified, fold.value.padded, "s31-fixed-fold-geometry-v1", null);
}

fn inspectStateFold(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_key_path: []const u8,
    first_key_path: []const u8,
    state_key_path: []const u8,
) !void {
    const spec = source.stateFoldStep() orelse return error.UnsupportedStateFoldSource;
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    if (!std.mem.eql(u8, child_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer child.deinit();
    try validateKey(allocator, source, child.value);
    const first_bytes = try std.fs.cwd().readFileAlloc(allocator, first_key_path, 4096);
    defer allocator.free(first_bytes);
    if (!std.mem.eql(u8, first_bytes, sealed_prover_recursive_key)) return error.UnsealedRecursiveKey;
    var first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer first.deinit();
    const state_bytes = try std.fs.cwd().readFileAlloc(allocator, state_key_path, 4096);
    defer allocator.free(state_bytes);
    if (!std.mem.eql(u8, state_bytes, sealed_prover_state_fold_key)) return error.UnsealedStateFoldKey;
    var state_key = try std.json.parseFromSlice(StateFoldKey, allocator, state_bytes, .{ .ignore_unknown_fields = false });
    defer state_key.deinit();
    const verified = try validateStateFoldKey(child_bytes, first_bytes, first.value, state_key.value, spec);
    var stages: state_fold.StageCapture = .{};
    var topology_ctx = try state_fold.topologyWithStages(allocator, projection_bytes, verified.layout, verified.pcs, verified.base_root, spec.body, &stages);
    defer topology_ctx.deinit();
    try emitFoldGeometry(allocator, &topology_ctx, verified, state_key.value.padded, "s31-state-fold-geometry-v2", stages.slice());
}

fn emitFoldGeometry(
    allocator: std.mem.Allocator,
    topology_ctx: *circuit.builder.Context(circuit.builder.NoValue),
    verified: VerifiedFoldKey,
    padded: Rows,
    schema: []const u8,
    stages: ?[]const state_fold.StageStats,
) !void {
    const raw = circuit.common.finalize.rawComponentSizes(preprocessed.CircuitView.fromBuilder(&topology_ctx.circuit));
    const raw_vars = topology_ctx.circuit.n_vars;
    try circuit.common.finalize.padContext(circuit.builder.NoValue, topology_ctx);
    var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    defer pp.deinit(allocator);
    const actual_root = try pp.preprocessedRoot(allocator, verified.pcs.fri_config.log_blowup_factor);
    if (!std.mem.eql(u8, &actual_root, &verified.root) or !pp.layout().eql(&verified.layout))
        return error.FoldKeyTopologyMismatch;
    const raw_rows: Rows = .{
        .eq = raw.eq,
        .qm31_ops = raw.qm31_ops,
        .triple_xor = raw.triple_xor,
        .m31_to_u32 = raw.m31_to_u32,
        .blake_g = raw.blake_g_gate,
    };
    if (raw_rows.eq > padded.eq or raw_rows.qm31_ops > padded.qm31_ops or
        raw_rows.triple_xor > padded.triple_xor or raw_rows.m31_to_u32 > padded.m31_to_u32 or
        raw_rows.blake_g > padded.blake_g)
        return error.FoldKeyTopologyMismatch;
    const headroom: Rows = .{
        .eq = padded.eq - raw_rows.eq,
        .qm31_ops = padded.qm31_ops - raw_rows.qm31_ops,
        .triple_xor = padded.triple_xor - raw_rows.triple_xor,
        .m31_to_u32 = padded.m31_to_u32 - raw_rows.m31_to_u32,
        .blake_g = padded.blake_g - raw_rows.blake_g,
    };
    const root_hex = std.fmt.bytesToHex(verified.root, .lower);
    const hash_hex = std.fmt.bytesToHex(verified.hash, .lower);
    const report = .{
        .schema = schema,
        .fold_preprocessed_root = &root_hex,
        .fold_circuit_hash = &hash_hex,
        .trace_log_size = verified.layout.traceLogSize(),
        .raw_vars = raw_vars,
        .padded_vars = topology_ctx.circuit.n_vars,
        .raw_rows = raw_rows,
        .padded_rows = padded,
        .headroom_rows = headroom,
        .verifier_stages = stages,
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(encoded);
    std.debug.print("{s}\n", .{encoded});
}

fn validateFoldStatement(statement: FoldStatement, child_bytes: []const u8, fold_bytes: []const u8, verified: VerifiedFoldKey) !void {
    var fold_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(fold_bytes, &fold_digest, .{});
    if (!std.mem.eql(u8, statement.schema, "s31-fixed-fold-statement-v2") or
        !std.mem.eql(u8, statement.fold_key_sha256, &std.fmt.bytesToHex(fold_digest, .lower)) or
        !std.mem.eql(u8, statement.fold_preprocessed_root, &std.fmt.bytesToHex(verified.root, .lower)) or
        !std.mem.eql(u8, statement.fold_circuit_hash, &std.fmt.bytesToHex(verified.hash, .lower)))
        return error.InvalidFoldStatement;
    for (statement.leaf_public_words) |word| if (word >= core.fields.m31.Modulus) {
        return error.NoncanonicalPublicWord;
    };
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
    const base = recursion_gate.statementDigest(child_digest, statement.leaf_public_words);
    if (!std.meta.eql(statement.base_public_words, base) or
        !std.meta.eql(statement.fold_public_words, fixed_fold.statementDigest(verified.root, statement.step, base)))
        return error.InvalidFoldStatement;
}

fn wrapFold(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_proof_path: []const u8,
    child_statement_path: []const u8,
    output_path: []const u8,
    child_key_path: []const u8,
    first_key_path: []const u8,
    fold_key_path: []const u8,
    base_case: bool,
    low_memory: bool,
    audit_only: bool,
) !void {
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    if (!std.mem.eql(u8, child_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer child.deinit();
    try validateKey(allocator, source, child.value);
    const first_bytes = try std.fs.cwd().readFileAlloc(allocator, first_key_path, 4096);
    defer allocator.free(first_bytes);
    if (!std.mem.eql(u8, first_bytes, sealed_prover_recursive_key)) return error.UnsealedRecursiveKey;
    var first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer first.deinit();
    const fold_bytes = try std.fs.cwd().readFileAlloc(allocator, fold_key_path, 4096);
    defer allocator.free(fold_bytes);
    if (!std.mem.eql(u8, fold_bytes, sealed_prover_fold_key)) return error.UnsealedFoldKey;
    var fold = try std.json.parseFromSlice(FoldKey, allocator, fold_bytes, .{ .ignore_unknown_fields = false });
    defer fold.deinit();
    const verified = try validateFoldKey(child_bytes, first_bytes, first.value, fold.value);
    const statement_bytes = try std.fs.cwd().readFileAlloc(allocator, child_statement_path, 8192);
    defer allocator.free(statement_bytes);
    var leaf_public_words: [8]u32 = undefined;
    var base_public_words: [8]u32 = undefined;
    var step: u16 = undefined;
    var child_root: [32]u8 = undefined;
    var child_hash: [32]u8 = undefined;
    var child_public_words: [8]u32 = undefined;
    if (base_case) {
        var first_statement = try std.json.parseFromSlice(RecursiveStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
        defer first_statement.deinit();
        var child_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
        const parent = try validateRecursiveStatement(first_statement.value, child_digest, first.value, true);
        if (!parent.layout.eql(&verified.layout) or !std.mem.eql(u8, &parent.root, &verified.base_root))
            return error.InvalidFoldBaseKey;
        leaf_public_words = first_statement.value.child_public_words;
        base_public_words = first_statement.value.outer_public_words;
        child_public_words = base_public_words;
        child_root = parent.root;
        child_hash = parent.hash;
        step = 0;
    } else {
        var previous = try std.json.parseFromSlice(FoldStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
        defer previous.deinit();
        try validateFoldStatement(previous.value, child_bytes, fold_bytes, verified);
        if (previous.value.step == std.math.maxInt(u16)) return error.FoldStepOverflow;
        leaf_public_words = previous.value.leaf_public_words;
        base_public_words = previous.value.base_public_words;
        child_public_words = previous.value.fold_public_words;
        child_root = verified.root;
        child_hash = verified.hash;
        step = previous.value.step + 1;
    }
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, child_proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    var captured = try native.verifyAndCapture(allocator, &verified.layout, &bundle, verified.pcs, child_root, child_hash, child_public_words, proof_bytes);
    defer captured.deinit();
    var values = try fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.base_root, verified.root, base_public_words, step);
    defer values.deinit();
    if (audit_only) {
        var wrong_leaf = base_public_words;
        wrong_leaf[0] ^= 1;
        if (fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.base_root, verified.root, wrong_leaf, step)) |accepted| {
            var invalid = accepted;
            invalid.deinit();
            return error.FoldVerifierAcceptedWrongLeaf;
        } else |err| switch (err) {
            error.VerificationFailed, error.EqFailedOnEval => {},
            else => return err,
        }
        if (fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.base_root, verified.root, base_public_words, step - 1)) |accepted| {
            var invalid = accepted;
            invalid.deinit();
            return error.FoldVerifierAcceptedWrongStep;
        } else |err| switch (err) {
            error.VerificationFailed, error.EqFailedOnEval => {},
            else => return err,
        }
        var wrong_root = verified.root;
        wrong_root[0] ^= 1;
        if (fixed_fold.verifyPrepared(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.base_root, wrong_root, base_public_words, step)) |accepted| {
            var invalid = accepted;
            invalid.deinit();
            return error.FoldVerifierAcceptedWrongRoot;
        } else |err| switch (err) {
            error.VerificationFailed, error.EqFailedOnEval => {},
            else => return err,
        }
        inline for (.{ .base_selector, .zero_test_inverse, .previous_counter }) |mutation| {
            if (fixed_fold.verifyPreparedWithMutation(allocator, projection_bytes, verified.layout, verified.pcs, &captured, verified.base_root, verified.root, base_public_words, step, mutation)) |accepted| {
                var invalid = accepted;
                invalid.deinit();
                return error.FoldVerifierAcceptedForgedCounter;
            } else |err| switch (err) {
                error.VerificationFailed, error.EqFailedOnEval => {},
                else => return err,
            }
        }
        std.debug.print("S31 fixed-fold recursive circuit audit: valid=true rejected=6\n", .{});
        return;
    }
    var pp = blk: {
        var topology_ctx = try fixed_fold.topology(allocator, projection_bytes, verified.layout, verified.pcs, verified.base_root);
        defer topology_ctx.deinit();
        if (!sameTopology(&values.circuit, &topology_ctx.circuit)) return error.FoldValueDependentTopology;
        try circuit.common.finalize.padContext(QM31, &values);
        try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
        if (!sameTopology(&values.circuit, &topology_ctx.circuit) or !try values.isCircuitValid())
            return error.InvalidFoldCircuit;
        break :blk try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
    };
    defer pp.deinit(allocator);
    values.circuit.deinit(allocator);
    values.circuit = .{};
    var committed = try cpu.prove.PreprocessedCommitment.build(allocator, &pp, verified.pcs, .{});
    defer committed.deinit(allocator);
    const actual_root = committed.root();
    if (!std.mem.eql(u8, &actual_root, &verified.root) or !pp.layout().eql(&verified.layout))
        return error.FoldKeyTopologyMismatch;
    var timer = try std.time.Timer.start();
    var proof = try cpu.Internal.prove(allocator, values.values(), &pp, &bundle, verified.pcs, .{
        .preprocessed_commitment = &committed,
        .evaluations_only = low_memory,
    }, {});
    defer proof.deinit();
    const elapsed = timer.read();
    if (proof.output_values.len != 8) return error.InvalidFoldPublicOutput;
    var public_words: [8]u32 = undefined;
    for (proof.output_values, &public_words) |value, *word| {
        const limbs = value.toM31Array();
        if (limbs[0].v > 65535 or limbs[1].v > 65535 or limbs[2].v != 0 or limbs[3].v != 0)
            return error.InvalidFoldPublicOutput;
        word.* = limbs[0].v | (limbs[1].v << 16);
    }
    if (!std.meta.eql(public_words, fixed_fold.statementDigest(verified.root, step, base_public_words)))
        return error.InvalidFoldPublicOutput;
    const encoded = try native.serialize(allocator, &proof);
    defer allocator.free(encoded);
    try native.verify(allocator, &verified.layout, &bundle, verified.pcs, verified.root, verified.hash, public_words, encoded);
    var fold_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(fold_bytes, &fold_digest, .{});
    const key_hex = std.fmt.bytesToHex(fold_digest, .lower);
    const root_hex = std.fmt.bytesToHex(verified.root, .lower);
    const hash_hex = std.fmt.bytesToHex(verified.hash, .lower);
    const statement: FoldStatement = .{
        .schema = "s31-fixed-fold-statement-v2",
        .fold_key_sha256 = &key_hex,
        .step = step,
        .leaf_public_words = leaf_public_words,
        .base_public_words = base_public_words,
        .fold_public_words = public_words,
        .fold_preprocessed_root = &root_hex,
        .fold_circuit_hash = &hash_hex,
    };
    try validateFoldStatement(statement, child_bytes, fold_bytes, verified);
    const encoded_statement = try std.json.Stringify.valueAlloc(allocator, statement, .{});
    defer allocator.free(encoded_statement);
    try std.fs.cwd().makePath(std.fs.path.dirname(output_path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = output_path, .data = encoded });
    const statement_path = try std.fmt.allocPrint(allocator, "{s}.statement.json", .{output_path});
    defer allocator.free(statement_path);
    try std.fs.cwd().writeFile(.{ .sub_path = statement_path, .data = encoded_statement });
    std.debug.print("S31 fixed-fold proof: step={d} bytes={d} prove={d:.3}s root={s}\n", .{
        step, encoded.len, @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s, &root_hex,
    });
}

fn verifyFold(
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    statement_path: []const u8,
    child_bytes: []const u8,
    first_bytes: []const u8,
    fold_bytes: []const u8,
) !void {
    if (chip_mode or sparse_mode or direct_mode) return error.UnsupportedRecursiveProfile;
    var source = try parsedProgram(allocator);
    defer source.deinit();
    var child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer child.deinit();
    try validateKey(allocator, source.value, child.value);
    var first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer first.deinit();
    var fold = try std.json.parseFromSlice(FoldKey, allocator, fold_bytes, .{ .ignore_unknown_fields = false });
    defer fold.deinit();
    const verified = try validateFoldKey(child_bytes, first_bytes, first.value, fold.value);
    const statement_bytes = try std.fs.cwd().readFileAlloc(allocator, statement_path, 4096);
    defer allocator.free(statement_bytes);
    var statement = try std.json.parseFromSlice(FoldStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
    defer statement.deinit();
    try validateFoldStatement(statement.value, child_bytes, fold_bytes, verified);
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    try native.verify(allocator, &verified.layout, &bundle, verified.pcs, verified.root, verified.hash, statement.value.fold_public_words, proof_bytes);
    std.debug.print("S31 fixed-fold verification accepted: step={d} proof={s}\n", .{ statement.value.step, proof_path });
}

fn expectStateFoldCircuitRejection(
    allocator: std.mem.Allocator,
    verified: VerifiedFoldKey,
    captured: *const cpu.verifier_proof.VerifierProof,
    base_root: [32]u8,
    self_root: [32]u8,
    base_public_words: [8]u32,
    initial_state: [4]u32,
    current_state: [4]u32,
    previous_state: [4]u32,
    step: u16,
    body: []const relation.Step,
    mutation: ?state_fold.Mutation,
) !void {
    if (state_fold.verifyPreparedWithMutation(
        allocator,
        projection_bytes,
        verified.layout,
        verified.pcs,
        captured,
        base_root,
        self_root,
        base_public_words,
        initial_state,
        current_state,
        previous_state,
        step,
        body,
        mutation,
    )) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.StateFoldAuditAcceptedMutation;
    } else |err| switch (err) {
        error.VerificationFailed, error.EqFailedOnEval => {},
        else => return err,
    }
}

fn wrapStateFold(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_proof_path: []const u8,
    child_statement_path: []const u8,
    output_path: []const u8,
    child_key_path: []const u8,
    first_key_path: []const u8,
    state_key_path: []const u8,
    base_case: bool,
    low_memory: bool,
    audit_only: bool,
) !void {
    var cache: ?StateFoldCache = null;
    defer if (cache) |*prepared| prepared.deinit(allocator);
    return wrapStateFoldWithCache(allocator, source, child_proof_path, child_statement_path,
        output_path, child_key_path, first_key_path, state_key_path, base_case,
        low_memory, audit_only, &cache);
}

const StateFoldCache = struct {
    pp: preprocessed.PreprocessedCircuit,
    commitment: cpu.prove.PreprocessedCommitment,

    fn deinit(self: *StateFoldCache, allocator: std.mem.Allocator) void {
        self.commitment.deinit(allocator);
        self.pp.deinit(allocator);
    }
};

fn rejectExistingFoldOutput(path: []const u8) !void {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.OutputAlreadyExists;
}

/// Reuse the sealed preprocessed circuit and commitment while every step
/// independently checks its child proof and value/topology gate equality.
fn wrapStateFoldBatch(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_proof_path: []const u8,
    child_statement_path: []const u8,
    output_path: []const u8,
    child_key_path: []const u8,
    first_key_path: []const u8,
    state_key_path: []const u8,
    steps_text: []const u8,
    checkpoint_dir: []const u8,
    first_step_text: []const u8,
    case_text: []const u8,
    low_memory: bool,
) !void {
    const steps = try std.fmt.parseInt(u32, steps_text, 10);
    const first_step = try std.fmt.parseInt(u32, first_step_text, 10);
    const base_case = std.mem.eql(u8, case_text, "base");
    if (!base_case and !std.mem.eql(u8, case_text, "next")) return error.InvalidFoldBranch;
    if (steps == 0 or steps > 65536 or first_step > 65535 or
        first_step + steps - 1 > 65535 or (base_case and first_step != 0) or
        (!base_case and first_step == 0)) return error.InvalidFoldStepRange;
    if (std.mem.eql(u8, child_proof_path, output_path)) return error.OutputAlreadyExists;
    const initial_bytes = try std.fs.cwd().readFileAlloc(allocator, child_statement_path, 8192);
    defer allocator.free(initial_bytes);
    if (base_case) {
        var initial = try std.json.parseFromSlice(RecursiveStatement, allocator, initial_bytes, .{ .ignore_unknown_fields = false });
        defer initial.deinit();
        if (!std.mem.eql(u8, initial.value.schema, "s31-recursive-gate-statement-v2")) return error.InvalidFoldBranch;
    } else {
        var initial = try std.json.parseFromSlice(StateFoldStatement, allocator, initial_bytes, .{ .ignore_unknown_fields = false });
        defer initial.deinit();
        if (!std.mem.eql(u8, initial.value.schema, "s31-state-fold-statement-v1") or
            @as(u32, initial.value.step) + 1 != first_step) return error.InvalidFoldStepRange;
    }
    try std.fs.cwd().makePath(checkpoint_dir);
    var paths = std.heap.ArenaAllocator.init(allocator);
    defer paths.deinit();
    const scratch = paths.allocator();
    for (0..steps) |index| {
        const target = if (index + 1 == steps) output_path else
            try std.fmt.allocPrint(scratch, "{s}/state-{d:0>5}.proof", .{ checkpoint_dir, first_step + @as(u32, @intCast(index)) });
        try rejectExistingFoldOutput(target);
        const statement_path = try std.fmt.allocPrint(scratch, "{s}.statement.json", .{target});
        try rejectExistingFoldOutput(statement_path);
    }
    var cache: ?StateFoldCache = null;
    defer if (cache) |*prepared| prepared.deinit(allocator);
    var current_proof = child_proof_path;
    var current_statement = child_statement_path;
    for (0..steps) |index| {
        const target = if (index + 1 == steps) output_path else
            try std.fmt.allocPrint(scratch, "{s}/state-{d:0>5}.proof", .{ checkpoint_dir, first_step + @as(u32, @intCast(index)) });
        try wrapStateFoldWithCache(allocator, source, current_proof, current_statement,
            target, child_key_path, first_key_path, state_key_path,
            base_case and index == 0, low_memory, false, &cache);
        current_proof = target;
        current_statement = try std.fmt.allocPrint(scratch, "{s}.statement.json", .{target});
    }
}

fn wrapStateFoldWithCache(
    allocator: std.mem.Allocator,
    source: relation.Program,
    child_proof_path: []const u8,
    child_statement_path: []const u8,
    output_path: []const u8,
    child_key_path: []const u8,
    first_key_path: []const u8,
    state_key_path: []const u8,
    base_case: bool,
    low_memory: bool,
    audit_only: bool,
    cache: *?StateFoldCache,
) !void {
    const spec = source.stateFoldStep() orelse return error.UnsupportedStateFoldSource;
    const child_bytes = try std.fs.cwd().readFileAlloc(allocator, child_key_path, 4096);
    defer allocator.free(child_bytes);
    if (!std.mem.eql(u8, child_bytes, sealed_prover_key)) return error.UnsealedRecursiveKey;
    var child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer child.deinit();
    try validateKey(allocator, source, child.value);
    const first_bytes = try std.fs.cwd().readFileAlloc(allocator, first_key_path, 4096);
    defer allocator.free(first_bytes);
    if (!std.mem.eql(u8, first_bytes, sealed_prover_recursive_key)) return error.UnsealedRecursiveKey;
    var first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer first.deinit();
    const state_bytes = try std.fs.cwd().readFileAlloc(allocator, state_key_path, 4096);
    defer allocator.free(state_bytes);
    if (!std.mem.eql(u8, state_bytes, sealed_prover_state_fold_key)) return error.UnsealedStateFoldKey;
    var state_key = try std.json.parseFromSlice(StateFoldKey, allocator, state_bytes, .{ .ignore_unknown_fields = false });
    defer state_key.deinit();
    const verified = try validateStateFoldKey(child_bytes, first_bytes, first.value, state_key.value, spec);
    const statement_bytes = try std.fs.cwd().readFileAlloc(allocator, child_statement_path, 8192);
    defer allocator.free(statement_bytes);
    var leaf_public_words: [8]u32 = undefined;
    var base_public_words: [8]u32 = undefined;
    var initial_state: [4]u32 = undefined;
    var current_state: [4]u32 = undefined;
    var previous_state: [4]u32 = .{ 0, 0, 0, 0 };
    var step: u16 = undefined;
    var child_root: [32]u8 = undefined;
    var child_hash: [32]u8 = undefined;
    var child_public_words: [8]u32 = undefined;
    if (base_case) {
        var first_statement = try std.json.parseFromSlice(RecursiveStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
        defer first_statement.deinit();
        var child_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(child_bytes, &child_digest, .{});
        const parent = try validateRecursiveStatement(first_statement.value, child_digest, first.value, true);
        if (!parent.layout.eql(&verified.layout) or !std.mem.eql(u8, &parent.root, &verified.base_root))
            return error.InvalidStateFoldBaseKey;
        leaf_public_words = first_statement.value.child_public_words;
        base_public_words = first_statement.value.outer_public_words;
        for (&initial_state, 0..) |*word, i| word.* = leaf_public_words[4 + i];
        current_state = initial_state;
        child_public_words = base_public_words;
        child_root = parent.root;
        child_hash = parent.hash;
        step = 0;
    } else {
        var previous = try std.json.parseFromSlice(StateFoldStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
        defer previous.deinit();
        try validateStateFoldStatement(previous.value, child_bytes, state_bytes, verified);
        if (previous.value.step == std.math.maxInt(u16)) return error.FoldStepOverflow;
        leaf_public_words = previous.value.leaf_public_words;
        base_public_words = previous.value.base_public_words;
        initial_state = previous.value.initial_state;
        previous_state = previous.value.current_state;
        current_state = try state_fold.nextState(previous_state, spec.body);
        child_public_words = previous.value.fold_public_words;
        child_root = verified.root;
        child_hash = verified.hash;
        step = previous.value.step + 1;
    }
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, child_proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    var captured = try native.verifyAndCapture(allocator, &verified.layout, &bundle, verified.pcs, child_root, child_hash, child_public_words, proof_bytes);
    defer captured.deinit();
    var values = try state_fold.verifyPrepared(
        allocator,
        projection_bytes,
        verified.layout,
        verified.pcs,
        &captured,
        verified.base_root,
        verified.root,
        base_public_words,
        initial_state,
        current_state,
        previous_state,
        step,
        spec.body,
    );
    defer values.deinit();
    if (audit_only) {
        var wrong_leaf = base_public_words;
        wrong_leaf[0] ^= 1;
        try expectStateFoldCircuitRejection(allocator, verified, &captured, verified.base_root, verified.root, wrong_leaf, initial_state, current_state, previous_state, step, spec.body, null);
        var wrong_current = current_state;
        wrong_current[0] = if (wrong_current[0] == 0) 1 else 0;
        try expectStateFoldCircuitRejection(allocator, verified, &captured, verified.base_root, verified.root, base_public_words, initial_state, wrong_current, previous_state, step, spec.body, null);
        try expectStateFoldCircuitRejection(allocator, verified, &captured, verified.base_root, verified.root, base_public_words, initial_state, current_state, previous_state, if (step == 0) 1 else step - 1, spec.body, null);
        var wrong_initial = initial_state;
        wrong_initial[0] = if (wrong_initial[0] == 0) 1 else 0;
        try expectStateFoldCircuitRejection(allocator, verified, &captured, verified.base_root, verified.root, base_public_words, wrong_initial, current_state, previous_state, step, spec.body, null);
        if (base_case) {
            var wrong_root = verified.base_root;
            wrong_root[0] ^= 1;
            try expectStateFoldCircuitRejection(allocator, verified, &captured, wrong_root, verified.root, base_public_words, initial_state, current_state, previous_state, step, spec.body, null);
        } else {
            var wrong_root = verified.root;
            wrong_root[0] ^= 1;
            try expectStateFoldCircuitRejection(allocator, verified, &captured, verified.base_root, wrong_root, base_public_words, initial_state, current_state, previous_state, step, spec.body, null);
            var wrong_previous = previous_state;
            wrong_previous[0] = if (wrong_previous[0] == 0) 1 else 0;
            try expectStateFoldCircuitRejection(allocator, verified, &captured, verified.base_root, verified.root, base_public_words, initial_state, current_state, wrong_previous, step, spec.body, null);
        }
        inline for (.{ .base_selector, .zero_test_inverse, .previous_counter, .current_state }) |mutation| {
            try expectStateFoldCircuitRejection(allocator, verified, &captured, verified.base_root, verified.root, base_public_words, initial_state, current_state, previous_state, step, spec.body, mutation);
        }
        std.debug.print("S31 state-fold circuit audit: step={d} valid=true rejected={d}\n", .{ step, if (base_case) @as(u32, 9) else 10 });
        return;
    }
    {
        var topology_ctx = try state_fold.topology(allocator, projection_bytes, verified.layout, verified.pcs, verified.base_root, spec.body);
        defer topology_ctx.deinit();
        if (!sameTopology(&values.circuit, &topology_ctx.circuit)) return error.StateFoldValueDependentTopology;
        try circuit.common.finalize.padContext(QM31, &values);
        try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology_ctx);
        if (!sameTopology(&values.circuit, &topology_ctx.circuit) or !try values.isCircuitValid())
            return error.InvalidStateFoldCircuit;
        if (cache.* == null) {
            var pp = try preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology_ctx.circuit);
            errdefer pp.deinit(allocator);
            var committed = try cpu.prove.PreprocessedCommitment.build(allocator, &pp, verified.pcs, .{});
            errdefer committed.deinit(allocator);
            const actual_root = committed.root();
            if (!std.mem.eql(u8, &actual_root, &verified.root) or !pp.layout().eql(&verified.layout))
                return error.StateFoldKeyTopologyMismatch;
            cache.* = .{ .pp = pp, .commitment = committed };
        }
    }
    const prepared = if (cache.*) |*item| item else unreachable;
    const prepared_root = prepared.commitment.root();
    if (!std.mem.eql(u8, &prepared_root, &verified.root) or
        !prepared.pp.layout().eql(&verified.layout)) return error.StateFoldKeyTopologyMismatch;
    values.circuit.deinit(allocator);
    values.circuit = .{};
    var timer = try std.time.Timer.start();
    var proof = try cpu.Internal.prove(allocator, values.values(), &prepared.pp, &bundle, verified.pcs, .{
        .preprocessed_commitment = &prepared.commitment,
        .evaluations_only = low_memory,
    }, {});
    defer proof.deinit();
    const elapsed = timer.read();
    if (proof.output_values.len != 8) return error.InvalidStateFoldPublicOutput;
    var public_words: [8]u32 = undefined;
    for (proof.output_values, &public_words) |value, *word| {
        const limbs = value.toM31Array();
        if (limbs[0].v > 65535 or limbs[1].v > 65535 or limbs[2].v != 0 or limbs[3].v != 0)
            return error.InvalidStateFoldPublicOutput;
        word.* = limbs[0].v | (limbs[1].v << 16);
    }
    if (!std.meta.eql(public_words, state_fold.statementDigest(verified.root, step, base_public_words, initial_state, current_state)))
        return error.InvalidStateFoldPublicOutput;
    const encoded = try native.serialize(allocator, &proof);
    defer allocator.free(encoded);
    try native.verify(allocator, &verified.layout, &bundle, verified.pcs, verified.root, verified.hash, public_words, encoded);
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(state_bytes, &key_digest, .{});
    const key_hex = std.fmt.bytesToHex(key_digest, .lower);
    const root_hex = std.fmt.bytesToHex(verified.root, .lower);
    const hash_hex = std.fmt.bytesToHex(verified.hash, .lower);
    const statement: StateFoldStatement = .{
        .schema = "s31-state-fold-statement-v1",
        .state_fold_key_sha256 = &key_hex,
        .step = step,
        .leaf_public_words = leaf_public_words,
        .base_public_words = base_public_words,
        .initial_state = initial_state,
        .current_state = current_state,
        .fold_public_words = public_words,
        .fold_preprocessed_root = &root_hex,
        .fold_circuit_hash = &hash_hex,
    };
    try validateStateFoldStatement(statement, child_bytes, state_bytes, verified);
    const encoded_statement = try std.json.Stringify.valueAlloc(allocator, statement, .{});
    defer allocator.free(encoded_statement);
    try std.fs.cwd().makePath(std.fs.path.dirname(output_path) orelse ".");
    try std.fs.cwd().writeFile(.{ .sub_path = output_path, .data = encoded });
    const statement_path = try std.fmt.allocPrint(allocator, "{s}.statement.json", .{output_path});
    defer allocator.free(statement_path);
    try std.fs.cwd().writeFile(.{ .sub_path = statement_path, .data = encoded_statement });
    std.debug.print("S31 state-fold proof: step={d} bytes={d} prove={d:.3}s state={any}\n", .{
        step, encoded.len, @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s, current_state,
    });
}

fn verifyStateFold(
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    statement_path: []const u8,
    child_bytes: []const u8,
    first_bytes: []const u8,
    state_bytes: []const u8,
) !void {
    if (chip_mode or sparse_mode or direct_mode) return error.UnsupportedRecursiveProfile;
    var source = try parsedProgram(allocator);
    defer source.deinit();
    const spec = source.value.stateFoldStep() orelse return error.UnsupportedStateFoldSource;
    var child = try std.json.parseFromSlice(Key, allocator, child_bytes, .{ .ignore_unknown_fields = false });
    defer child.deinit();
    try validateKey(allocator, source.value, child.value);
    var first = try std.json.parseFromSlice(RecursiveKey, allocator, first_bytes, .{ .ignore_unknown_fields = false });
    defer first.deinit();
    var state_key = try std.json.parseFromSlice(StateFoldKey, allocator, state_bytes, .{ .ignore_unknown_fields = false });
    defer state_key.deinit();
    const verified = try validateStateFoldKey(child_bytes, first_bytes, first.value, state_key.value, spec);
    const statement_bytes = try std.fs.cwd().readFileAlloc(allocator, statement_path, 4096);
    defer allocator.free(statement_bytes);
    var statement = try std.json.parseFromSlice(StateFoldStatement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
    defer statement.deinit();
    try validateStateFoldStatement(statement.value, child_bytes, state_bytes, verified);
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    try native.verify(allocator, &verified.layout, &bundle, verified.pcs, verified.root, verified.hash, statement.value.fold_public_words, proof_bytes);
    std.debug.print("S31 state-fold verification accepted: step={d} state={any}\n", .{ statement.value.step, statement.value.current_state });
}

fn verifyOuter(
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    statement_path: []const u8,
    embedded_key: []const u8,
    embedded_recursive_key: []const u8,
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
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(embedded_key, &key_digest, .{});
    var parsed_recursive = try std.json.parseFromSlice(RecursiveKey, allocator, embedded_recursive_key, .{ .ignore_unknown_fields = false });
    defer parsed_recursive.deinit();
    const verified = try validateRecursiveStatement(parsed_statement.value, key_digest, parsed_recursive.value, true);
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    try native.verify(allocator, &verified.layout, &bundle, verified.pcs, verified.root, verified.hash, parsed_statement.value.outer_public_words, proof_bytes);
    std.debug.print("S31 recursive outer verification accepted: {s}\n", .{proof_path});
}

fn validateRecursiveStatement(statement: RecursiveStatement, child_digest: [32]u8, recursive_key: RecursiveKey, canonical_child_words: bool) !VerifiedRecursiveStatement {
    if (!std.mem.eql(u8, statement.schema, "s31-recursive-gate-statement-v2") or
        !std.mem.eql(u8, statement.child_key_sha256, &std.fmt.bytesToHex(child_digest, .lower)) or
        !std.meta.eql(statement.outer_public_words, recursion_gate.statementDigest(child_digest, statement.child_public_words)))
        return error.InvalidRecursiveStatement;
    if (canonical_child_words) for (statement.child_public_words) |word| {
        if (word >= core.fields.m31.Modulus) return error.NoncanonicalPublicWord;
    };
    if (!std.mem.eql(u8, recursive_key.schema, "s31-recursive-verification-key-v2") or
        !std.mem.eql(u8, recursive_key.child_key_sha256, &std.fmt.bytesToHex(child_digest, .lower)) or
        !std.mem.eql(u8, recursive_key.projection_sha256, projection_sha256) or
        !std.mem.eql(u8, recursive_key.air_bundle_sha256, cpu.air.bundle_sha256))
        return error.InvalidRecursiveVerificationKey;
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = recursive_key.outer_padded.eq,
        .qm31_ops = recursive_key.outer_padded.qm31_ops,
        .triple_xor = recursive_key.outer_padded.triple_xor,
        .m31_to_u32 = recursive_key.outer_padded.m31_to_u32,
        .blake_g_gate = recursive_key.outer_padded.blake_g,
    });
    if (layout.traceLogSize() != recursive_key.outer_trace_log_size)
        return error.InvalidRecursiveVerificationKey;
    const pcs = try showcasePcsConfig(layout.traceLogSize());
    var root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&root, recursive_key.outer_preprocessed_root);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    if (!std.mem.eql(u8, recursive_key.outer_circuit_hash, &std.fmt.bytesToHex(hash, .lower)) or
        !std.mem.eql(u8, statement.outer_preprocessed_root, &std.fmt.bytesToHex(root, .lower)) or
        !std.mem.eql(u8, statement.outer_circuit_hash, &std.fmt.bytesToHex(hash, .lower)))
        return error.InvalidRecursiveStatement;
    return .{ .layout = layout, .pcs = pcs, .root = root, .hash = hash };
}

fn verifyNextOuter(
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    chain_path: []const u8,
    embedded_key: []const u8,
    embedded_recursive_key: []const u8,
    embedded_recursive_next_key: []const u8,
) !void {
    if (chip_mode or sparse_mode or direct_mode) return error.UnsupportedRecursiveProfile;
    var parsed_source = try parsedProgram(allocator);
    defer parsed_source.deinit();
    var parsed_key = try std.json.parseFromSlice(Key, allocator, embedded_key, .{ .ignore_unknown_fields = false });
    defer parsed_key.deinit();
    try validateKey(allocator, parsed_source.value, parsed_key.value);
    var parsed_first_key = try std.json.parseFromSlice(RecursiveKey, allocator, embedded_recursive_key, .{ .ignore_unknown_fields = false });
    defer parsed_first_key.deinit();
    var parsed_next_key = try std.json.parseFromSlice(RecursiveKey, allocator, embedded_recursive_next_key, .{ .ignore_unknown_fields = false });
    defer parsed_next_key.deinit();
    const chain_bytes = try std.fs.cwd().readFileAlloc(allocator, chain_path, 8192);
    defer allocator.free(chain_bytes);
    var parsed_chain = try std.json.parseFromSlice(RecursiveChainStatement, allocator, chain_bytes, .{ .ignore_unknown_fields = false });
    defer parsed_chain.deinit();
    const chain = parsed_chain.value;
    if (!std.mem.eql(u8, chain.schema, "s31-recursive-chain-statement-v1")) return error.InvalidRecursiveStatement;
    var child_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(embedded_key, &child_digest, .{});
    _ = try validateRecursiveStatement(chain.leaf, child_digest, parsed_first_key.value, true);
    if (!std.meta.eql(chain.head.child_public_words, chain.leaf.outer_public_words)) return error.InvalidRecursiveStatement;
    var first_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(embedded_recursive_key, &first_digest, .{});
    const verified = try validateRecursiveStatement(chain.head, first_digest, parsed_next_key.value, false);
    var bundle = try parseAirBundle(allocator);
    defer bundle.deinit();
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, proof_path, 16 << 20);
    defer allocator.free(proof_bytes);
    try native.verify(allocator, &verified.layout, &bundle, verified.pcs, verified.root, verified.hash, chain.head.outer_public_words, proof_bytes);
    std.debug.print("S31 recursive level-2 verification accepted: {s}\n", .{proof_path});
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
