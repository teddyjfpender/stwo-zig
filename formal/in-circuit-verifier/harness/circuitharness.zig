//! Scope-B differential vectors: real circuit proofs against the Lean
//! `circuitAccepts` spec.
//!
//! Proves the R7 digest-output circuits (fibonacci, triple_xor,
//! m31_to_u32, blake_g_gate) with the in-repo circuit prover under
//! the pinned profile (Blake2sM31 channel, plain Blake2s Merkle,
//! `defaultPcsConfig`: blowup 1, fold step 1, last layer 0, PoW 10,
//! 3 queries), then runs the shipping acceptance predicate — the
//! in-circuit verifier built with values (`circuit_cpu.verify.
//! verifyProofBytes`) — on the original and on a battery of tampered
//! statements and proofs. Each case records the native-shape proof (the
//! same JSON schema as `harness.zig`), the statement data, and the Zig
//! verdict; the Lean side replays the statement transcript, instantiates
//! `circuitAir` and must agree accept/reject on every case.
//!
//! Tampered values are flipped on the native proof in place (and
//! reverted), then converted to `CircuitSerialize` bytes, so both
//! verifiers judge the same mutated object. Only fields the conversion
//! reads from the proof are tampered; the per-query witness expansions
//! come from the prover aux and are covered wire-level by rung R11.
//!
//! The prover's transcript step digests and lookup elements are recorded
//! for transcript-replay debugging on the Lean side.
//!
//! Build (from the repo root):
//!   zig build-exe \
//!     --dep stwo_core --dep stwo_circuit_frontend --dep stwo_circuit_cpu_integration \
//!     --dep circuit_testing --dep stwo_circuit_recursion_wire \
//!     -Mroot=formal/in-circuit-verifier/harness/circuitharness.zig \
//!     --dep stwo_core --dep stwo_prover_api --dep stwo_prover_engine \
//!     --dep stwo_cpu_backend --dep stwo_circuit_frontend --dep stwo_cairo_frontend \
//!     --dep stwo_circuit_recursion_wire --dep circuit_composition_cpu_aot \
//!     -Mstwo_circuit_cpu_integration=src/integrations/circuit_cpu/mod.zig \
//!     --dep stwo_cairo_frontend \
//!     -Mcircuit_composition_cpu_aot=formal/in-circuit-verifier/harness/aot_stub.zig \
//!     --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_api \
//!     --dep stwo_prover_engine --dep interop_felt_json --dep interop_cairo_prover_parameters \
//!     -Mstwo_cairo_frontend=src/frontends/cairo/mod.zig \
//!     --dep stwo_core --dep interop_felt_json --dep interop_cairo_prover_parameters \
//!     -Mstwo_circuit_recursion_wire=src/interop/circuit_recursion/mod.zig \
//!     --dep stwo_core --dep stwo_circuit_frontend \
//!     -Mcircuit_testing=src/frontends/circuit/testing/mod.zig \
//!     --dep stwo_core --dep stwo_prover_engine \
//!     -Mstwo_circuit_frontend=src/frontends/circuit/mod.zig \
//!     --dep stwo_core -Minterop_felt_json=src/interop/felt_json.zig \
//!     --dep stwo_core -Minterop_cairo_prover_parameters=src/interop/cairo_prover_parameters.zig \
//!     --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_engine \
//!     -Mstwo_cpu_backend=src/backends/cpu_scalar/mod.zig \
//!     --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_api \
//!     -Mstwo_prover_engine=src/prover/mod.zig \
//!     --dep stwo_core -Mstwo_backend_contracts=src/backend/mod.zig \
//!     --dep stwo_core -Mstwo_prover_api=src/prover_api/mod.zig \
//!     -Mstwo_core=src/core/mod.zig -O ReleaseSafe
//!
//! Run (from the repo root):
//!   ./circuitharness formal/in-circuit-verifier/harness
//! (writes circuitvectors_<circuit>.json into the given directory)

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const circuit_testing = @import("circuit_testing");
const wire = @import("stwo_circuit_recursion_wire");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const preprocessed = circuit.common.preprocessed;
const component_list = circuit.common.component_list;
const verify_request = wire.verify_request;

const Prover = circuit_cpu.Internal;
const Hasher = Prover.Hasher;
const Proof = core.pcs.CommitmentSchemeProof(Hasher);
const Step = circuit_cpu.prove.Step;

// ---------------------------------------------------------------------------
// JSON writers (same schema as harness.zig).

fn qm31Json(w: anytype, v: QM31) !void {
    const limbs = v.toM31Array();
    try w.print("[{d},{d},{d},{d}]", .{ limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() });
}

fn hashJson(w: anytype, h: [32]u8) !void {
    try w.print("\"{s}\"", .{std.fmt.bytesToHex(h, .lower)});
}

fn friLayerJson(w: anytype, layer: core.fri.FriLayerProof(Hasher)) !void {
    try w.writeAll("{\"witness\":[");
    for (layer.fri_witness, 0..) |v, i| {
        if (i > 0) try w.writeAll(",");
        try qm31Json(w, v);
    }
    try w.writeAll("],\"hash_witness\":[");
    for (layer.decommitment.hash_witness, 0..) |h, i| {
        if (i > 0) try w.writeAll(",");
        try hashJson(w, h);
    }
    try w.writeAll("],\"commitment\":");
    try hashJson(w, layer.commitment);
    try w.writeAll("}");
}

fn proofJson(allocator: std.mem.Allocator, proof: *const Proof) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"commitments\":[");
    for (proof.commitments.items, 0..) |c, i| {
        if (i > 0) try w.writeAll(",");
        try hashJson(w, c);
    }
    try w.writeAll("],\"sampled_values\":[");
    for (proof.sampled_values.items, 0..) |tree, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("[");
        for (tree, 0..) |col, j| {
            if (j > 0) try w.writeAll(",");
            try w.writeAll("[");
            for (col, 0..) |v, k| {
                if (k > 0) try w.writeAll(",");
                try qm31Json(w, v);
            }
            try w.writeAll("]");
        }
        try w.writeAll("]");
    }
    try w.writeAll("],\"decommitments\":[");
    for (proof.decommitments.items, 0..) |d, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("[");
        for (d.hash_witness, 0..) |h, j| {
            if (j > 0) try w.writeAll(",");
            try hashJson(w, h);
        }
        try w.writeAll("]");
    }
    try w.writeAll("],\"queried_values\":[");
    for (proof.queried_values.items, 0..) |tree, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("[");
        for (tree, 0..) |col, j| {
            if (j > 0) try w.writeAll(",");
            try w.writeAll("[");
            for (col, 0..) |v, k| {
                if (k > 0) try w.writeAll(",");
                try w.print("{d}", .{v.toU32()});
            }
            try w.writeAll("]");
        }
        try w.writeAll("]");
    }
    try w.print("],\"proof_of_work\":{d},\"fri\":{{", .{proof.proof_of_work});
    try w.writeAll("\"first_layer\":");
    try friLayerJson(w, proof.fri_proof.first_layer);
    try w.writeAll(",\"inner_layers\":[");
    for (proof.fri_proof.inner_layers, 0..) |layer, i| {
        if (i > 0) try w.writeAll(",");
        try friLayerJson(w, layer);
    }
    try w.writeAll("],\"last_layer_poly\":[");
    for (proof.fri_proof.last_layer_poly.coefficients(), 0..) |c, i| {
        if (i > 0) try w.writeAll(",");
        try qm31Json(w, c);
    }
    try w.writeAll("]}}");
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Prover observer: transcript step digests and the lookup elements.

const Observer = struct {
    allocator: std.mem.Allocator,
    steps: std.ArrayListUnmanaged(struct { Step, [32]u8 }) = .empty,
    z: QM31 = undefined,
    alpha: QM31 = undefined,

    pub fn onStep(self: *Observer, which: Step, digest: [32]u8) void {
        self.steps.append(self.allocator, .{ which, digest }) catch @panic("out of memory");
    }

    pub fn onLookupElements(self: *Observer, z: QM31, alpha: QM31) void {
        self.z = z;
        self.alpha = alpha;
    }
};

// ---------------------------------------------------------------------------
// Tamper battery. Proof tampers flip native-proof fields the wire
// conversion reads, so both verifiers judge the same mutated object.

const Tamper = enum {
    none,
    request_output_digest,
    request_preprocessed_root,
    request_eq_log_size,
    channel_salt,
    interaction_pow_nonce,
    pow_nonce,
    claimed_sum,
    sampled_preprocessed,
    sampled_trace,
    sampled_interaction_prev,
    sampled_interaction_oods,
    sampled_composition,
    trace_root,
    interaction_root,
    composition_root,
    queried_value,
    last_layer,
};

fn bump(value: *QM31) void {
    value.* = value.add(QM31.one());
}

/// Applies `tamper` to the proof in place; returns an undo closure's data.
/// Request tampers are applied by the caller on its request copy.
fn applyProofTamper(proof: anytype, tamper: Tamper) void {
    const stark = &proof.stark_proof.proof.commitment_scheme_proof;
    switch (tamper) {
        .none, .request_output_digest, .request_preprocessed_root, .request_eq_log_size => {},
        .channel_salt => proof.channel_salt +%= 1,
        .interaction_pow_nonce => proof.interaction_pow_nonce +%= 1,
        .pow_nonce => stark.proof_of_work +%= 1,
        .claimed_sum => bump(&proof.claimed_sums.eq),
        .sampled_preprocessed => bump(&stark.sampled_values.items[0][0][0]),
        .sampled_trace => bump(&stark.sampled_values.items[1][0][0]),
        .sampled_interaction_prev => {
            for (stark.sampled_values.items[2]) |col| if (col.len == 2) {
                bump(&col[0]);
                return;
            };
            unreachable;
        },
        .sampled_interaction_oods => {
            for (stark.sampled_values.items[2]) |col| if (col.len == 2) {
                bump(&col[1]);
                return;
            };
            unreachable;
        },
        .sampled_composition => bump(&stark.sampled_values.items[3][0][0]),
        .trace_root => stark.commitments.items[1][0] ^= 1,
        .interaction_root => stark.commitments.items[2][0] ^= 1,
        .composition_root => stark.commitments.items[3][0] ^= 1,
        .queried_value => {
            const col = stark.queried_values.items[1][0];
            col[0] = col[0].add(M31.one());
        },
        .last_layer => bump(&stark.fri_proof.last_layer_poly.coefficientsMut()[0]),
    }
}

/// A seeded random value flip on a field the wire conversion reads from
/// the proof, with an exact inverse.
const FuzzOp = union(enum) {
    sampled: [3]usize,
    queried: [2]usize,
    tree_root: usize,
    fri_root: usize,
    last_layer: usize,
    claimed: usize,
    salt,
    interaction_nonce,
    pow_nonce,
};

fn pickFuzz(stark: anytype, random: std.Random) FuzzOp {
    switch (random.intRangeAtMost(u8, 0, 8)) {
        0 => {
            const tree = random.uintLessThan(usize, stark.sampled_values.items.len);
            const col = random.uintLessThan(usize, stark.sampled_values.items[tree].len);
            const idx = random.uintLessThan(usize, stark.sampled_values.items[tree][col].len);
            return .{ .sampled = .{ tree, col, idx } };
        },
        1 => {
            const col = random.uintLessThan(usize, stark.queried_values.items[1].len);
            const idx = random.uintLessThan(usize, stark.queried_values.items[1][col].len);
            return .{ .queried = .{ col, idx } };
        },
        2 => return .{ .tree_root = 1 + random.uintLessThan(usize, 3) },
        3 => return .{ .fri_root = random.uintLessThan(usize, stark.fri_proof.inner_layers.len + 1) },
        4 => return .{ .last_layer = random.uintLessThan(usize, stark.fri_proof.last_layer_poly.coefficients().len) },
        5 => return .{ .claimed = random.uintLessThan(usize, component_list.N_COMPONENTS) },
        6 => return .salt,
        7 => return .interaction_nonce,
        else => return .pow_nonce,
    }
}

fn applyFuzz(proof: anytype, op: FuzzOp, invert: bool) void {
    const stark = &proof.stark_proof.proof.commitment_scheme_proof;
    const delta = if (invert) QM31.zero().sub(QM31.one()) else QM31.one();
    switch (op) {
        .sampled => |at| {
            const col = stark.sampled_values.items[at[0]][at[1]];
            col[at[2]] = col[at[2]].add(delta);
        },
        .queried => |at| {
            const col = stark.queried_values.items[1][at[0]];
            col[at[1]] = if (invert) col[at[1]].sub(M31.one()) else col[at[1]].add(M31.one());
        },
        .tree_root => |tree| stark.commitments.items[tree][0] ^= 1,
        .fri_root => |layer| {
            if (layer == 0) {
                stark.fri_proof.first_layer.commitment[0] ^= 1;
            } else {
                stark.fri_proof.inner_layers[layer - 1].commitment[0] ^= 1;
            }
        },
        .last_layer => |idx| {
            const coefficients = stark.fri_proof.last_layer_poly.coefficientsMut();
            coefficients[idx] = coefficients[idx].add(delta);
        },
        .claimed => |comp| {
            var sums = proof.claimed_sums.toArray();
            sums[comp] = sums[comp].add(delta);
            proof.claimed_sums = @TypeOf(proof.claimed_sums).fromArray(sums);
        },
        .salt => proof.channel_salt = if (invert) proof.channel_salt -% 1 else proof.channel_salt +% 1,
        .interaction_nonce => proof.interaction_pow_nonce = if (invert) proof.interaction_pow_nonce -% 1 else proof.interaction_pow_nonce +% 1,
        .pow_nonce => stark.proof_of_work = if (invert) stark.proof_of_work -% 1 else stark.proof_of_work +% 1,
    }
}

// ---------------------------------------------------------------------------

/// Runs one case: converts the (possibly tampered) proof to wire bytes,
/// takes the shipping verdict, and writes the case JSON. Returns whether
/// the verdict accepted.
fn runCase(
    w: anytype,
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    request: *const verify_request.VerifyRequest,
    proof: anytype,
    label: []const u8,
    first: bool,
) !bool {
    if (!first) try w.writeAll(",");
    var converted = try circuit_cpu.verifier_proof.prepare(gpa, proof);
    const bytes = try converted.serialize(arena);
    converted.deinit();
    const verdict = try circuit_cpu.verify.verifyProofBytes(gpa, table, request, bytes);
    const native_json = try proofJson(arena, &proof.stark_proof.proof.commitment_scheme_proof);

    try w.print("{{\"label\":\"{s}\",\"accepted\":{},", .{ label, verdict.isAccepted() });
    switch (verdict) {
        .accepted => try w.writeAll("\"stage\":null,"),
        .rejected => |why| try w.print("\"stage\":\"{s}:{s}\",", .{ @tagName(why.stage), @errorName(why.reason) }),
    }
    try w.writeAll("\"request\":{\"output_digest\":[");
    for (request.output_digest, 0..) |word, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{d}", .{word});
    }
    try w.writeAll("],\"preprocessed_root\":[");
    for (request.preprocessed_root, 0..) |word, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{d}", .{word});
    }
    try w.writeAll("],\"layout_log_sizes\":[");
    for (request.preprocessed_column_log_sizes, 0..) |column, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{d}", .{column.log_size});
    }
    try w.print("]}},\"channel_salt\":{d},\"interaction_pow_nonce\":{d},\"claimed_sums\":[", .{
        proof.channel_salt, proof.interaction_pow_nonce,
    });
    for (proof.claimed_sums.toArray(), 0..) |sum, i| {
        if (i > 0) try w.writeAll(",");
        try qm31Json(w, sum);
    }
    try w.print("],\"proof\":{s}}}", .{native_json});
    return verdict.isAccepted();
}

fn runCircuit(
    gpa: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    bundle: *const circuit_cpu.air.Bundle,
    which: circuit_testing.contexts.TestContext,
    out_path: []const u8,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var ctx = try circuit_testing.contexts.build(QM31, gpa, which);
    defer ctx.deinit();
    try ctx.finalize(false);
    var pp = try preprocessed.PreprocessedCircuit.preprocessContext(QM31, gpa, &ctx);
    defer pp.deinit(gpa);
    if (!try ctx.isCircuitValid()) return error.InvalidTestCircuit;

    var observer = Observer{ .allocator = arena };
    const pcs_config = circuit_cpu.prove.defaultPcsConfig(pp.traceLogSize());
    var proof = try Prover.prove(gpa, ctx.values(), &pp, bundle, pcs_config, .{}, &observer);
    defer proof.deinit();

    var columns: [preprocessed.N_PREPROCESSED_COLUMNS]verify_request.Column = undefined;
    const layout = pp.layout();
    for (layout.entries, &columns) |entry, *column| column.* = .{ .id = entry.id, .log_size = entry.log_size };
    var output_digest: [8]u32 = undefined;
    for (proof.output_values, &output_digest) |value, *word| {
        const limbs = value.toM31Array();
        word.* = limbs[0].toU32() | (limbs[1].toU32() << 16);
    }
    const base_request = verify_request.VerifyRequest{
        .pcs_config = proof.pcs_config,
        .preprocessed_column_log_sizes = &columns,
        .preprocessed_root = core.vcs.blake2_hash.digestToU32s(proof.stark_proof.proof.commitment_scheme_proof.commitments.items[0]),
        .output_digest = output_digest,
    };

    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;

    try w.print(
        "{{\"profile\":{{\"m31_channel\":true,\"pow_bits\":{d},\"log_blowup\":{d}," ++
            "\"log_last_layer\":{d},\"n_queries\":{d},\"fold_step\":{d}," ++
            "\"trace_lifting_log_size\":{d},\"preprocessed_lifting_log_size\":{d}}},",
        .{
            pcs_config.fri_config.pow_bits,
            pcs_config.fri_config.log_blowup_factor,
            pcs_config.fri_config.log_last_layer_degree_bound,
            pcs_config.fri_config.n_queries,
            pcs_config.fri_config.fold_step,
            pcs_config.trace_lifting_log_size,
            pcs_config.preprocessed_lifting_log_size,
        },
    );
    try w.writeAll("\"statement\":{\"layout\":[");
    for (layout.entries, 0..) |entry, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{{\"id\":\"{s}\",\"log_size\":{d}}}", .{ entry.id, entry.log_size });
    }
    try w.writeAll("],\"component_log_sizes\":[");
    for (proof.component_log_sizes.toArray(), 0..) |log_size, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{d}", .{log_size});
    }
    try w.writeAll("],\"circuit_hash\":");
    try hashJson(w, proof.circuit_hash);
    try w.writeAll(",\"z\":");
    try qm31Json(w, observer.z);
    try w.writeAll(",\"alpha\":");
    try qm31Json(w, observer.alpha);
    try w.print(",\"log_trace_size\":{d}}},\"prover_steps\":[", .{pp.traceLogSize()});
    for (observer.steps.items, 0..) |entry, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{{\"step\":\"{s}\",\"digest\":\"{s}\"}}", .{ @tagName(entry[0]), &std.fmt.bytesToHex(entry[1], .lower) });
    }
    try w.writeAll("],\"cases\":[");

    var n_accept: usize = 0;
    var n_reject: usize = 0;
    inline for (std.meta.fields(Tamper), 0..) |tamper_field, case_index| {
        const tamper: Tamper = @enumFromInt(tamper_field.value);

        var case_columns = columns;
        var request = base_request;
        request.preprocessed_column_log_sizes = &case_columns;
        switch (tamper) {
            .request_output_digest => request.output_digest[0] ^= 1,
            .request_preprocessed_root => request.preprocessed_root[0] ^= 1,
            .request_eq_log_size => for (&case_columns) |*column| {
                if (std.mem.startsWith(u8, column.id, "eq_in")) column.log_size += 1;
            },
            else => {},
        }

        applyProofTamper(&proof, tamper);
        const accepted = try runCase(w, gpa, arena, table, &request, &proof, tamper_field.name, case_index == 0);
        if (accepted) n_accept += 1 else n_reject += 1;
        revertProofTamper(&proof, tamper);
    }

    for (0..10) |fuzz_index| {
        var prng = std.Random.DefaultPrng.init(0xc1cc_0000 + @as(u64, fuzz_index));
        const op = pickFuzz(&proof.stark_proof.proof.commitment_scheme_proof, prng.random());
        applyFuzz(&proof, op, false);
        const label = try std.fmt.allocPrint(arena, "fuzz_{d}", .{fuzz_index});
        const accepted = try runCase(w, gpa, arena, table, &base_request, &proof, label, false);
        if (accepted) n_accept += 1 else n_reject += 1;
        applyFuzz(&proof, op, true);
    }

    try w.writeAll("]}\n");
    try std.fs.cwd().writeFile(.{ .sub_path = out_path, .data = out.written() });
    std.debug.print("wrote {s}: {d} cases ({d} accepted, {d} rejected)\n", .{
        out_path, n_accept + n_reject, n_accept, n_reject,
    });
}

/// Inverse of `applyProofTamper`.
fn revertProofTamper(proof: anytype, tamper: Tamper) void {
    const stark = &proof.stark_proof.proof.commitment_scheme_proof;
    switch (tamper) {
        .none, .request_output_digest, .request_preprocessed_root, .request_eq_log_size => {},
        .channel_salt => proof.channel_salt -%= 1,
        .interaction_pow_nonce => proof.interaction_pow_nonce -%= 1,
        .pow_nonce => stark.proof_of_work -%= 1,
        .claimed_sum => proof.claimed_sums.eq = proof.claimed_sums.eq.sub(QM31.one()),
        .sampled_preprocessed => stark.sampled_values.items[0][0][0] = stark.sampled_values.items[0][0][0].sub(QM31.one()),
        .sampled_trace => stark.sampled_values.items[1][0][0] = stark.sampled_values.items[1][0][0].sub(QM31.one()),
        .sampled_interaction_prev => for (stark.sampled_values.items[2]) |col| {
            if (col.len == 2) {
                col[0] = col[0].sub(QM31.one());
                break;
            }
        },
        .sampled_interaction_oods => for (stark.sampled_values.items[2]) |col| {
            if (col.len == 2) {
                col[1] = col[1].sub(QM31.one());
                break;
            }
        },
        .sampled_composition => stark.sampled_values.items[3][0][0] = stark.sampled_values.items[3][0][0].sub(QM31.one()),
        .trace_root => stark.commitments.items[1][0] ^= 1,
        .interaction_root => stark.commitments.items[2][0] ^= 1,
        .composition_root => stark.commitments.items[3][0] ^= 1,
        .queried_value => {
            const col = stark.queried_values.items[1][0];
            col[0] = col[0].sub(M31.one());
        },
        .last_layer => {
            const coefficients = stark.fri_proof.last_layer_poly.coefficientsMut();
            coefficients[0] = coefficients[0].sub(QM31.one());
        },
    }
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_state.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var args = std.process.args();
    _ = args.next();
    const out_dir = args.next() orelse "formal/in-circuit-verifier/harness";

    const projection_bytes = try std.fs.cwd().readFileAlloc(arena, "vectors/circuit/official/compiled_air_constraints_v1.bin", 8 << 20);
    var projection = try circuit.air_eval.projection.parse(gpa, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(gpa, &projection);
    defer table.deinit();

    const bundle_bytes = try std.fs.cwd().readFileAlloc(arena, circuit_cpu.air.bundle_path, 1 << 20);
    var bundle = try circuit_cpu.air.parse(gpa, bundle_bytes);
    defer bundle.deinit();

    const circuits = [_]circuit_testing.contexts.TestContext{ .fibonacci, .triple_xor, .m31_to_u32, .blake_g_gate };
    inline for (circuits) |which| {
        const out_path = try std.fmt.allocPrint(arena, "{s}/circuitvectors_{s}.json", .{ out_dir, @tagName(which) });
        try runCircuit(gpa, &table, &bundle, which, out_path);
    }
}
