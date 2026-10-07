//! Sealed package adapter for the one-header circuit plus SHA AIR proof.
//! The digest hint in the circuit is admissible only through joint.prove and
//! native.verify, which join its private Gate wires to the SHA trace.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const s31 = @import("stwo_s31_prototype");
const joint = s31.sha_joint_prover;
const native = s31.sha_joint_native_verifier;
const profile = s31.sha_joint_profile;

const QM31 = core.fields.qm31.QM31;
const NoValue = circuit.builder.NoValue;
const relation = s31.relation;
const compiler = s31.relation_compiler;
const source_bytes = @embedFile("s31_program_source");
const sealed_key = @embedFile("s31_verification_key");
const air_bytes = @embedFile("s31_air_programs");
const stdlib_lock_sha256 = @import("s31_options").stdlib_lock_sha256;

const Rows = struct { eq: usize, qm31_ops: usize, triple_xor: usize, m31_to_u32: usize, blake_g: usize };
const Fri = struct { pow_bits: u32, log_blowup_factor: u32, last_layer_degree_bound: u32, queries: u32, fold_step: u32 };
const ShaMetadata = struct {
    key_digest: []const u8,
    n_vars: u32,
    gate_addresses: [profile.gate_address_count]u32,
    circuit_logs: [4]u32,
    component_names: [profile.component_count][]const u8,
    claimed_sums: usize,
    sha_calls: u32,
    proof_envelope: []const u8,
};
const Key = struct {
    schema: []const u8,
    name: []const u8,
    profile: []const u8,
    chip: ?u8,
    program_sha256: []const u8,
    canonical_ir_sha256: []const u8,
    preprocessed_root: []const u8,
    circuit_hash: []const u8,
    padded: Rows,
    trace_log_size: u32,
    projection_sha256: []const u8,
    air_bundle_sha256: []const u8,
    stdlib_lock_sha256: ?[]const u8 = null,
    fri: Fri,
    sha_joint: ShaMetadata,
};
const Span = struct {
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
const ShaCost = struct {
    compression_calls: u32,
    sha_component_rows: [profile.sha_component_count]u32,
    caller_rows: u32,
    lookup_table_rows: [profile.table_component_count]usize,
    fixed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,
    note: []const u8,
};
const Report = struct {
    name: []const u8,
    profile: []const u8 = "sha-joint-v1",
    chip: ?u8 = null,
    repeated_step: ?u8 = null,
    state_fold_step: ?u8 = null,
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
    source_map: []const Span,
    assertion_map: []const compiler.AssertionSpan,
    public_binding: []const compiler.BindingSpan,
    finalization: compiler.FinalizationSpan,
    fri: Fri,
    sha_joint: ShaMetadata,
    sha_air_cost: ShaCost,
};

fn validateShape(allocator: std.mem.Allocator, program: relation.Program) !void {
    if (program.inputs.len != 1 or program.inputs[0].kind != .u16 or
        program.inputs[0].visibility != .private or program.inputs[0].length != 40)
        return error.UnsupportedShaJointRelation;
    var calls: usize = 0;
    for (program.nodes) |node| if (node.op == .hash_sha256d_header) {
        calls += 1;
        if (!std.mem.eql(u8, node.lhs orelse "", program.inputs[0].name))
            return error.UnsupportedShaJointRelation;
    };
    if (calls != 1 or program.public_outputs.len != 1) return error.UnsupportedShaJointRelation;
    const shape = (try program.shapeOf(allocator, program.public_outputs[0])) orelse return error.UnsupportedShaJointRelation;
    if (shape.kind != .m31 or shape.length != 8) return error.UnsupportedShaJointRelation;
}

fn digestSource() [32]u8 {
    var bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source_bytes, &bytes, .{});
    return bytes;
}

fn pcsConfig(trace_log: u32) !core.pcs.config_v2.PcsConfigV2 {
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    return core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(trace_log, 18));
}

fn pad(comptime V: type, ctx: *circuit.builder.Context(V)) !void {
    const raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
    if (raw.triple_xor != 0 or raw.blake_g_gate != 0) return error.UnsupportedShaJointCircuit;
    try circuit.common.finalize.padToTargets(V, ctx, .{
        .eq = circuit.common.finalize.paddedSize(raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    });
}

fn rows(ctx: anytype) Rows {
    const value = circuit.common.finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
    return .{ .eq = value.eq, .qm31_ops = value.qm31_ops, .triple_xor = value.triple_xor, .m31_to_u32 = value.m31_to_u32, .blake_g = value.blake_g_gate };
}

const Topology = struct {
    ctx: circuit.builder.Context(NoValue),
    maps: compiler.Maps,
    pp: circuit.common.sparse_wide.Circuit,
    key: native.Key,
    raw: Rows,
    padded: Rows,

    fn deinit(self: *Topology, allocator: std.mem.Allocator) void {
        self.pp.deinit(allocator);
        self.ctx.deinit();
        self.maps.deinit(allocator);
    }
};

fn topology(allocator: std.mem.Allocator, program: relation.Program) !Topology {
    try validateShape(allocator, program);
    var maps = compiler.Maps{};
    errdefer maps.deinit(allocator);
    var ctx = try compiler.compileShaChipWithSpans(NoValue, allocator, program, null, &maps);
    errdefer ctx.deinit();
    if (maps.sha_boundaries.items.len != 1) return error.UnsupportedShaJointRelation;
    const raw = rows(&ctx);
    try pad(NoValue, &ctx);
    const padded = rows(&ctx);
    const addresses = maps.sha_boundaries.items[0].addresses;
    var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(allocator, &ctx.circuit, .{ .addresses = addresses });
    errdefer pp.deinit(allocator);
    const key = try native.deriveKey(allocator, digestSource(), &pp, @intCast(ctx.circuit.n_vars), addresses, try pcsConfig(pp.traceLogSize()));
    return .{ .ctx = ctx, .maps = maps, .pp = pp, .key = key, .raw = raw, .padded = padded };
}

fn inspect(allocator: std.mem.Allocator, program: relation.Program) !void {
    var topo = try topology(allocator, program);
    defer topo.deinit(allocator);
    var ir = try s31.canonical.build(allocator, program);
    defer ir.deinit();
    const source_hex = std.fmt.bytesToHex(digestSource(), .lower);
    const ir_hex = std.fmt.bytesToHex(ir.sha256, .lower);
    const root_hex = std.fmt.bytesToHex(topo.key.preprocessed_root, .lower);
    const identity = try topo.key.profile.circuitIdentity(topo.key.preprocessed_root);
    const identity_hex = std.fmt.bytesToHex(identity, .lower);
    const key_digest = try topo.key.profile.keyDigest(topo.key.preprocessed_root);
    const key_hex = std.fmt.bytesToHex(key_digest, .lower);
    const layout = topo.pp.layout();
    var fixed_cells: usize = 0;
    var max_log: u32 = 0;
    for (layout.entries) |entry| {
        fixed_cells += @as(usize, 1) << @intCast(entry.log_size);
        max_log = @max(max_log, entry.log_size);
    }
    var fixed_columns: usize = circuit.common.sparse_wide.N_COLUMNS;
    var main_columns: usize = 21;
    var interaction_columns: usize = 28;
    var sha_rows: [profile.sha_component_count]u32 = undefined;
    for (topo.key.profile.sha_components, &sha_rows) |component, *row| {
        fixed_columns += component.preprocessed_columns;
        fixed_cells += @as(usize, component.preprocessed_columns) << @intCast(component.log_size);
        max_log = @max(max_log, component.log_size);
        main_columns += component.main_columns;
        interaction_columns += component.interaction_columns;
        row.* = component.live_rows;
    }
    var table_rows: [profile.table_component_count]usize = undefined;
    for (topo.key.profile.table_roster, &table_rows) |table, *row| {
        fixed_columns += 1 + table.arity;
        fixed_cells += @as(usize, 1 + table.arity) << @intCast(table.log_size);
        max_log = @max(max_log, table.log_size);
        main_columns += 1;
        interaction_columns += 4;
        row.* = @as(usize, 1) << @intCast(table.log_size);
    }
    main_columns += topo.key.profile.caller_shape.main_columns;
    interaction_columns += topo.key.profile.caller_shape.interaction_columns;
    const spans = try allocator.alloc(Span, ir.source_map.len);
    defer allocator.free(spans);
    for (ir.source_map, spans) |item, *mapped| {
        const span = topo.maps.nodes.items[item.id];
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
    const packing = [_]InputPacking{.{ .name = program.inputs[0].name, .lanes = 40, .qm31_wires = 10 }};
    const report: Report = .{
        .name = program.name,
        .program_sha256 = &source_hex,
        .canonical_ir_sha256 = &ir_hex,
        .preprocessed_root = &root_hex,
        .circuit_hash = &identity_hex,
        .raw = topo.raw,
        .padded = topo.padded,
        .preprocessed_columns = fixed_columns,
        .preprocessed_cells = fixed_cells,
        .fixed_table_max_log_size = @max(max_log, 18),
        .trace_log_size = @max(topo.pp.traceLogSize(), 18),
        .input_packing = &packing,
        .source_map = spans,
        .assertion_map = topo.maps.assertions.items,
        .public_binding = topo.maps.bindings.items,
        .finalization = topo.maps.finalization.?,
        .fri = .{ .pow_bits = 26, .log_blowup_factor = 1, .last_layer_degree_bound = 1, .queries = 70, .fold_step = 1 },
        .sha_joint = .{ .key_digest = &key_hex, .n_vars = topo.key.profile.n_vars, .gate_addresses = topo.key.profile.gate_addresses, .circuit_logs = topo.key.profile.circuit_logs, .component_names = profile.component_names, .claimed_sums = profile.claimed_sum_count, .sha_calls = profile.call_count, .proof_envelope = "S31NAT6S" },
        .sha_air_cost = .{
            .compression_calls = profile.call_count,
            .sha_component_rows = sha_rows,
            .caller_rows = @as(u32, 1) << @intCast(topo.key.profile.caller_shape.log_size),
            .lookup_table_rows = table_rows,
            .fixed_columns = fixed_columns,
            .main_columns = main_columns,
            .interaction_columns = interaction_columns,
            .note = "Circuit raw/padded fields exclude SHA, caller and lookup-table rows; these are included above.",
        },
    };
    const json = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(json);
    std.debug.print("{s}\n", .{json});
}

fn validateKey(allocator: std.mem.Allocator, program: relation.Program, topo: *const Topology, key_bytes: []const u8) !void {
    var parsed = try std.json.parseFromSlice(Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const key = parsed.value;
    if (stdlib_lock_sha256.len == 0) {
        if (key.stdlib_lock_sha256 != null) return error.InvalidShaJointVerificationKey;
    } else if (!std.mem.eql(u8, key.stdlib_lock_sha256 orelse return error.InvalidShaJointVerificationKey, stdlib_lock_sha256))
        return error.InvalidShaJointVerificationKey;
    var ir = try s31.canonical.build(allocator, program);
    defer ir.deinit();
    const digest = try topo.key.profile.keyDigest(topo.key.preprocessed_root);
    const identity = try topo.key.profile.circuitIdentity(topo.key.preprocessed_root);
    if (!std.mem.eql(u8, key.schema, "s31-verification-key-sha-joint-v1") or
        !std.mem.eql(u8, key.profile, "sha-joint-v1") or key.chip != null or
        !std.mem.eql(u8, key.name, program.name) or
        !std.mem.eql(u8, key.program_sha256, &std.fmt.bytesToHex(digestSource(), .lower)) or
        !std.mem.eql(u8, key.canonical_ir_sha256, &std.fmt.bytesToHex(ir.sha256, .lower)) or
        !std.mem.eql(u8, key.preprocessed_root, &std.fmt.bytesToHex(topo.key.preprocessed_root, .lower)) or
        !std.mem.eql(u8, key.circuit_hash, &std.fmt.bytesToHex(identity, .lower)) or
        !std.meta.eql(key.padded, topo.padded) or
        key.trace_log_size != @max(topo.pp.traceLogSize(), 18) or
        !std.mem.eql(u8, key.projection_sha256, "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09") or
        !std.mem.eql(u8, key.air_bundle_sha256, "7b8022b09d84db371cc433aa0fcf132f7687f2720e05e4dc9a7650c575dc02c2") or
        key.fri.pow_bits != 26 or key.fri.log_blowup_factor != 1 or
        key.fri.last_layer_degree_bound != 1 or key.fri.queries != 70 or key.fri.fold_step != 1 or
        !std.mem.eql(u8, key.sha_joint.key_digest, &std.fmt.bytesToHex(digest, .lower)) or
        key.sha_joint.n_vars != topo.key.profile.n_vars or
        !std.meta.eql(key.sha_joint.gate_addresses, topo.key.profile.gate_addresses) or
        !std.meta.eql(key.sha_joint.circuit_logs, topo.key.profile.circuit_logs) or
        key.sha_joint.sha_calls != 3 or key.sha_joint.claimed_sums != profile.claimed_sum_count or
        !std.mem.eql(u8, key.sha_joint.proof_envelope, "S31NAT6S"))
        return error.InvalidShaJointVerificationKey;
    for (key.sha_joint.component_names, profile.component_names) |actual, expected|
        if (!std.mem.eql(u8, actual, expected)) return error.InvalidShaJointVerificationKey;
}

fn sameTopology(a: *const circuit.builder.Circuit, b: *const circuit.builder.Circuit) bool {
    if (a.n_vars != b.n_vars) return false;
    inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "triple_xor", "m31_to_u32", "blake_g_gate", "output" }) |field| {
        const left = @field(a, field).items;
        const right = @field(b, field).items;
        if (left.len != right.len) return false;
        for (left, right) |l, r| if (!std.meta.eql(l, r)) return false;
    }
    inline for (.{ "ends", "inputs", "outputs" }) |field| {
        const left = @field(a.permutation, field).items;
        const right = @field(b.permutation, field).items;
        if (left.len != right.len) return false;
        for (left, right) |l, r| if (!std.meta.eql(l, r)) return false;
    }
    return true;
}

fn publicOutputs(words: [8]u32) [8]QM31 {
    var outputs: [8]QM31 = undefined;
    for (words, &outputs) |word, *slot| slot.* = QM31.fromM31(
        core.fields.m31.M31.fromCanonical(word & 0xffff),
        core.fields.m31.M31.fromCanonical(word >> 16),
        core.fields.m31.M31.zero(),
        core.fields.m31.M31.zero(),
    );
    return outputs;
}

fn readAssignment(allocator: std.mem.Allocator, path: []const u8) !relation.ParsedAssignment {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 20);
    defer allocator.free(bytes);
    return relation.parseAssignment(allocator, bytes);
}

fn prove(allocator: std.mem.Allocator, program: relation.Program, assignment_path: []const u8, proof_path: []const u8) !void {
    var assignment = try readAssignment(allocator, assignment_path);
    defer assignment.deinit();
    const words = try relation.evaluate(allocator, program, assignment.value);
    var topo = try topology(allocator, program);
    defer topo.deinit(allocator);
    var maps = compiler.Maps{};
    defer maps.deinit(allocator);
    var values = try compiler.compileShaChipWithSpans(QM31, allocator, program, assignment.value, &maps);
    defer values.deinit();
    if (maps.sha_boundaries.items.len != 1 or
        !std.meta.eql(maps.sha_boundaries.items[0].addresses, topo.maps.sha_boundaries.items[0].addresses))
        return error.ValueDependentShaJointTopology;
    try pad(QM31, &values);
    if (!sameTopology(&values.circuit, &topo.ctx.circuit) or !try values.isCircuitValid())
        return error.InvalidShaJointCircuit;
    const input = try relation.inputValues(allocator, assignment.value, program.inputs[0]);
    defer allocator.free(input);
    var header: [80]u8 = undefined;
    for (input, 0..) |limb, i| std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(limb.toU32()), .little);
    var bundle = try cpu.air.parse(allocator, air_bytes);
    defer bundle.deinit();
    var metrics = joint.Metrics{};
    var proof = try joint.prove(allocator, values.values(), &topo.pp, &bundle, topo.key.profile.pcs, .{
        .source_digest = digestSource(),
        .n_vars = topo.key.profile.n_vars,
        .gate_addresses = topo.key.profile.gate_addresses,
        .header = header,
        .metrics = &metrics,
    });
    defer proof.deinit();
    const claimed = publicOutputs(words);
    if (proof.output_values.len != claimed.len) return error.InvalidShaJointPublicOutput;
    for (claimed, proof.output_values) |expected, actual|
        if (!std.meta.eql(expected, actual)) return error.InvalidShaJointPublicOutput;
    const encoded = try joint.serialize(allocator, &proof);
    defer allocator.free(encoded);
    try native.verify(allocator, topo.key.admission(&claimed), encoded);
    const parent = std.fs.path.dirname(proof_path) orelse ".";
    try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = proof_path, .data = encoded });
    std.debug.print("public words:", .{});
    for (words) |word| std.debug.print(" {d}", .{word});
    std.debug.print("\nS31 SHA joint proof: {d} bytes, fixed={d}, main={d}, interaction={d}\nproof: {s}\n", .{
        encoded.len, metrics.fixed_columns, metrics.main_columns, metrics.interaction_columns, proof_path,
    });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) return error.InvalidArguments;
    var parsed = try relation.parseProgram(allocator, source_bytes);
    defer parsed.deinit();
    try validateShape(allocator, parsed.value);
    if (std.mem.eql(u8, args[1], "check") and args.len == 2) {
        var topo = try topology(allocator, parsed.value);
        defer topo.deinit(allocator);
        std.debug.print("S31 {s}: SHA joint relation valid\n", .{parsed.value.name});
    } else if (std.mem.eql(u8, args[1], "inspect") and args.len == 2) {
        try inspect(allocator, parsed.value);
    } else if (std.mem.eql(u8, args[1], "run") and args.len == 3) {
        var assignment = try readAssignment(allocator, args[2]);
        defer assignment.deinit();
        const words = try relation.evaluate(allocator, parsed.value, assignment.value);
        std.debug.print("public words:", .{});
        for (words) |word| std.debug.print(" {d}", .{word});
        std.debug.print("\n", .{});
    } else if (std.mem.eql(u8, args[1], "prove") and args.len == 4) {
        if (sealed_key.len == 0) return error.UnsealedShaJointProver;
        var topo = try topology(allocator, parsed.value);
        defer topo.deinit(allocator);
        try validateKey(allocator, parsed.value, &topo, sealed_key);
        try prove(allocator, parsed.value, args[2], args[3]);
    } else return error.InvalidArguments;
}

pub fn verifierMain() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 4) return error.InvalidArguments;
    var parsed = try relation.parseProgram(allocator, source_bytes);
    defer parsed.deinit();
    var topo = try topology(allocator, parsed.value);
    defer topo.deinit(allocator);
    const external_key = try std.fs.cwd().readFileAlloc(allocator, args[3], 16 << 10);
    defer allocator.free(external_key);
    if (!std.mem.eql(u8, external_key, sealed_key)) return error.InvalidShaJointVerificationKey;
    try validateKey(allocator, parsed.value, &topo, sealed_key);
    var statement = try readAssignment(allocator, args[2]);
    defer statement.deinit();
    if (statement.value.private_inputs != null) return error.InvalidPublicStatement;
    const claimed = publicOutputs(try relation.claimedWords(allocator, parsed.value, statement.value));
    const proof_bytes = try std.fs.cwd().readFileAlloc(allocator, args[1], 64 << 20);
    defer allocator.free(proof_bytes);
    try native.verify(allocator, topo.key.admission(&claimed), proof_bytes);
    std.debug.print("S31 SHA joint native verification accepted: {s}\n", .{args[1]});
}
