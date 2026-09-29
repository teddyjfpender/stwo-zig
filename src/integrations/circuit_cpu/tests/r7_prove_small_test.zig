//! Rung R7: the small circuits of `crates/circuit_prover/src/prover_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) proved by the Zig circuit
//! prover, compared with the oracle's `prove-small` checkpoint
//! (`vectors/circuit/r7/prove_small.json`): the channel digest after every
//! transcript step, the lookup elements, both nonces, the claimed sums,
//! every commitment and FRI layer root, the last layer, and the per-column
//! and per-component digests of all three committed trees.
//!
//! The circuits are built with the Zig builder as the oracle's
//! `contexts.rs` transcribes them; each one's value table is checked against
//! the oracle's `values_sha256` before it is proved.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");

const QM31 = core.fields.qm31.QM31;
const builder = circuit.builder;
const ivalue = builder.ivalue;
const wrappers = builder.wrappers;
const Context = builder.Context(QM31);
const Var = builder.Var;
const component_list = circuit.common.component_list;
const preprocessed = circuit.common.preprocessed;
const checkpoint = cairo.conformance.checkpoint;
const Prover = circuit_cpu.Internal;
const Step = circuit_cpu.prove.Step;

const fixture_path = "vectors/circuit/r7/prove_small.json";
const N_RESERVED = component_list.N_RESERVED;

const preprocessed_domains = checkpoint.Domains{
    .column = "STWO_CIRCUIT_PREPROCESSED_COLUMN_V1\x00",
    .accumulator = "STWO_CIRCUIT_PREPROCESSED_ACCUMULATOR_V1\x00",
};
const base_domains = checkpoint.Domains{
    .column = "STWO_CIRCUIT_BASE_COLUMN_V1\x00",
    .accumulator = "STWO_CIRCUIT_BASE_ACCUMULATOR_V1\x00",
};
const interaction_domains = checkpoint.Domains{
    .column = "STWO_CIRCUIT_INTERACTION_COLUMN_V1\x00",
    .accumulator = "STWO_CIRCUIT_INTERACTION_ACCUMULATOR_V1\x00",
};

// ---------------------------------------------------------------------------
// The contexts of `tools/stwo-circuit-oracle-rs/src/contexts.rs`.

const TestContext = enum { fibonacci, permutation, blake, triple_xor, m31_to_u32, blake_g_gate };

fn nReserved(which: TestContext) usize {
    return switch (which) {
        .permutation, .blake => 0,
        else => N_RESERVED,
    };
}

fn buildContext(allocator: std.mem.Allocator, which: TestContext) !Context {
    var ctx = try Context.init(allocator, nReserved(which));
    errdefer ctx.deinit();
    switch (which) {
        .fibonacci => {
            var a = try ctx.guess(ivalue.qm31FromU32s(0, 0, 0, 0));
            var b = try ctx.guess(ivalue.qm31FromU32s(1, 0, 0, 0));
            for (2..1030) |_| {
                const next = try ctx.add(a, b);
                a = b;
                b = next;
            }
            try std.testing.expect(ctx.get(b).eql(QM31.fromU32Unchecked(809871181, 0, 0, 0)));
            const out = try builder.blake.m31ToU32(QM31, &ctx, b);
            try setDigestOutputs(&ctx, &.{out});
        },
        .permutation => {
            const a = try ctx.guess(ivalue.qm31FromU32s(0, 2, 0, 2));
            const b = try ctx.guess(ivalue.qm31FromU32s(1, 1, 1, 1));
            const first = try ctx.permute(&.{ a, b }, ivalue.sortByUCoordinate(QM31));
            const copy = [_]Var{ first[0], first[1] };
            _ = try ctx.permute(&copy, ivalue.sortByUCoordinate(QM31));
        },
        .blake => {
            ctx.assert_eq_on_eval = true;
            var inputs: [9]Var = undefined;
            for (&inputs, 0..) |*input, i| {
                const base: u32 = @intCast(4 * i + 82);
                input.* = try ctx.guess(ivalue.qm31FromU32s(base, base + 1, base + 2, base + 3));
            }
            for (0..15) |_| {
                const output = try builder.blake.blake2sM31(QM31, &ctx, &inputs, 9 * 16);
                _ = try ctx.add(output.low, output.high);
            }
        },
        .triple_xor => {
            const cases = [_][3]u32{
                .{ 42, 17, 55 },
                .{ 0x10000, 0x20000, 0x30001 },
                .{ 0x30005, 0x10007, 0x4000b },
            };
            const expected = [_]QM31{
                QM31.fromU32Unchecked(12, 0, 0, 0),
                QM31.fromU32Unchecked(1, 0, 0, 0),
                QM31.fromU32Unchecked(9, 6, 0, 0),
            };
            var out: wrappers.U32Wrapper(Var) = undefined;
            for (cases, expected) |case, want| {
                const a = try guessU32(&ctx, case[0]);
                const b = try guessU32(&ctx, case[1]);
                const c = try guessU32(&ctx, case[2]);
                out = try builder.blake.tripleXor(QM31, &ctx, a, b, c);
                try std.testing.expect(ctx.get(out.get()).eql(want));
            }
            try setDigestOutputs(&ctx, &.{out});
        },
        .m31_to_u32 => {
            const cases = [_]u32{ 42, 100_000, 2_000_042 };
            const expected = [_]QM31{
                QM31.fromU32Unchecked(42, 0, 0, 0),
                QM31.fromU32Unchecked(34464, 1, 0, 0),
                QM31.fromU32Unchecked(33962, 30, 0, 0),
            };
            var outs: [3]wrappers.U32Wrapper(Var) = undefined;
            for (cases, expected, &outs) |case, want, *out| {
                const input = try ctx.guess(QM31.fromU32Unchecked(case, 0, 0, 0));
                out.* = try builder.blake.m31ToU32(QM31, &ctx, input);
                try std.testing.expect(ctx.get(out.get()).eql(want));
            }
            try setDigestOutputs(&ctx, &outs);
        },
        .blake_g_gate => {
            const words = [_]u32{ 305419896, 4294967295, 2147483647, 123456789, 987654321, 468798 };
            var in: [6]wrappers.U32Wrapper(Var) = undefined;
            for (&in, words) |*wire, word| wire.* = try guessU32(&ctx, word);
            const outs = try builder.blake.blakeGGate(QM31, &ctx, in[0], in[1], in[2], in[3], in[4], in[5]);
            const expected = [_]QM31{
                QM31.fromU32Unchecked(49809, 43146, 0, 0),
                QM31.fromU32Unchecked(53691, 63264, 0, 0),
                QM31.fromU32Unchecked(464, 51992, 0, 0),
                QM31.fromU32Unchecked(46984, 55514, 0, 0),
            };
            for (outs, expected) |out, want| try std.testing.expect(ctx.get(out.get()).eql(want));
            try setDigestOutputs(&ctx, &outs);
        },
    }
    return ctx;
}

fn guessU32(ctx: *Context, word: u32) !wrappers.U32Wrapper(Var) {
    return wrappers.guessU32(QM31, ctx, wrappers.u32Value(QM31, word));
}

/// `set_digest_outputs`: cycles `words` through the reserved output wires.
fn setDigestOutputs(ctx: *Context, words: []const wrappers.U32Wrapper(Var)) !void {
    var outputs: [N_RESERVED]Var = undefined;
    for (&outputs, 0..) |*out, i| out.* = words[i % words.len].get();
    try ctx.setOutputs(&outputs);
}

/// `values_sha256` of `tools/stwo-circuit-oracle-rs/src/checkpoint.rs`.
fn valuesSha256(values: []const QM31) [64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("STWO_CIRCUIT_VALUES_V1\x00");
    hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, values.len)));
    for (values) |v| for (v.toM31Array()) |limb|
        hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, limb.toU32())));
    return std.fmt.bytesToHex(hasher.finalResult(), .lower);
}

// ---------------------------------------------------------------------------
// The observer: step digests, lookup elements and tree digests.

const Observer = struct {
    allocator: std.mem.Allocator,
    steps: std.ArrayListUnmanaged(struct { Step, [32]u8 }) = .empty,
    z: QM31 = undefined,
    alpha: QM31 = undefined,
    trees: [3]std.ArrayListUnmanaged(checkpoint.Component) = .{ .empty, .empty, .empty },
    accumulators: [3]checkpoint.Digest = undefined,

    fn deinit(self: *Observer) void {
        self.steps.deinit(self.allocator);
        for (&self.trees) |*tree| {
            for (tree.items) |component| self.allocator.free(component.columns);
            tree.deinit(self.allocator);
        }
    }

    pub fn onStep(self: *Observer, which: Step, digest: [32]u8) void {
        self.steps.append(self.allocator, .{ which, digest }) catch @panic("out of memory");
    }

    pub fn onLookupElements(self: *Observer, z: QM31, alpha: QM31) void {
        self.z = z;
        self.alpha = alpha;
    }

    pub fn onTraces(
        self: *Observer,
        pp: []const prover.pcs.ColumnEvaluation,
        base: []const prover.pcs.ColumnEvaluation,
        interaction: []const prover.pcs.ColumnEvaluation,
    ) !void {
        const one = [_]usize{pp.len};
        self.accumulators[0] = try self.digestTree(0, preprocessed_domains, pp, &.{"preprocessed"}, &one);
        var base_widths: [component_list.N_COMPONENTS]usize = undefined;
        var interaction_widths: [component_list.N_COMPONENTS]usize = undefined;
        for (component_list.component_facts.toArray(), &base_widths, &interaction_widths) |facts, *b, *i| {
            b.* = facts.trace_columns;
            i.* = facts.interaction_columns;
        }
        self.accumulators[1] = try self.digestTree(1, base_domains, base, &component_list.COMPONENT_NAMES, &base_widths);
        self.accumulators[2] = try self.digestTree(2, interaction_domains, interaction, &component_list.COMPONENT_NAMES, &interaction_widths);
    }

    fn digestTree(
        self: *Observer,
        tree: usize,
        domains: checkpoint.Domains,
        columns: []const prover.pcs.ColumnEvaluation,
        labels: []const []const u8,
        widths: []const usize,
    ) !checkpoint.Digest {
        var accumulator = checkpoint.initial_accumulator;
        var cursor: usize = 0;
        for (labels, widths, 0..) |label, width, ordinal| {
            const records = try self.allocator.alloc(checkpoint.Column, width);
            for (records, columns[cursor..][0..width], 0..) |*record, column, index| {
                const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values));
                record.* = .{
                    .ordinal = @intCast(index),
                    .row_count = column.values.len,
                    .sha256 = try checkpoint.digestColumnIn(domains, @intCast(ordinal), label, @intCast(index), @alignCast(words)),
                };
            }
            cursor += width;
            accumulator = try checkpoint.extendAccumulatorIn(domains, accumulator, @intCast(ordinal), label, records);
            try self.trees[tree].append(self.allocator, .{
                .ordinal = @intCast(ordinal),
                .label = label,
                .columns = records,
                .accumulator = accumulator,
            });
        }
        try std.testing.expectEqual(columns.len, cursor);
        return accumulator;
    }
};

// ---------------------------------------------------------------------------
// Comparison helpers over the parsed JSON.

const Json = std.json.Value;

fn field(value: Json, name: []const u8) Json {
    return value.object.get(name) orelse std.debug.panic("fixture is missing {s}", .{name});
}

fn expectHex(expected: Json, actual: []const u8) !void {
    try std.testing.expectEqualStrings(expected.string, &std.fmt.bytesToHex(actual[0..32].*, .lower));
}

fn expectQm31(expected: Json, actual: QM31) !void {
    const limbs = actual.toM31Array();
    for (expected.array.items, limbs) |want, got| try std.testing.expectEqual(@as(u32, @intCast(want.integer)), got.toU32());
}

fn expectU64(expected: Json, actual: u64) !void {
    const hi: u64 = @intCast(field(expected, "hi").integer);
    const lo: u64 = @intCast(field(expected, "lo").integer);
    try std.testing.expectEqual((hi << 32) | lo, actual);
}

fn expectTree(expected_components: Json, expected_accumulator: Json, actual: []const checkpoint.Component, accumulator: checkpoint.Digest) !void {
    try std.testing.expectEqual(expected_components.array.items.len, actual.len);
    for (expected_components.array.items, actual) |want, got| {
        try std.testing.expectEqualStrings(field(want, "label").string, got.label);
        const columns = field(want, "columns").array.items;
        try std.testing.expectEqual(columns.len, got.columns.len);
        for (columns, got.columns) |column, record| {
            try std.testing.expectEqual(@as(u64, 1) << @intCast(field(column, "log_size").integer), record.row_count);
            expectHex(field(column, "sha256"), &record.sha256) catch |err| {
                std.debug.print("column {s}[{d}] differs\n", .{ got.label, record.ordinal });
                return err;
            };
        }
        try expectHex(field(want, "accumulator_sha256"), &got.accumulator);
    }
    try expectHex(expected_accumulator, &accumulator);
}

fn loadBundle(allocator: std.mem.Allocator) !circuit_cpu.air.Bundle {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 1 << 20);
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    try std.testing.expectEqualStrings(circuit_cpu.air.bundle_sha256, &std.fmt.bytesToHex(digest, .lower));
    return circuit_cpu.air.parse(allocator, bytes);
}

fn proveAndCompare(which: TestContext) !void {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, fixture_path, 16 << 20);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(Json, allocator, bytes, .{});
    defer parsed.deinit();
    const expected = for (field(field(parsed.value, "body"), "proofs").array.items) |proof| {
        if (std.mem.eql(u8, field(proof, "name").string, @tagName(which))) break proof;
    } else return error.MissingFixture;

    var ctx = try buildContext(allocator, which);
    defer ctx.deinit();
    try ctx.finalize(false);
    var pp = try preprocessed.PreprocessedCircuit.preprocessContext(QM31, allocator, &ctx);
    defer pp.deinit(allocator);
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expectEqualStrings(field(expected, "values_sha256").string, &valuesSha256(ctx.values()));
    try std.testing.expectEqual(@as(u32, @intCast(field(expected, "trace_log_size").integer)), pp.traceLogSize());

    const fri = field(field(expected, "pcs_config"), "fri_config");
    const pcs_config = circuit_cpu.prove.defaultPcsConfig(pp.traceLogSize());
    try std.testing.expectEqual(@as(u32, @intCast(field(fri, "pow_bits").integer)), pcs_config.fri_config.pow_bits);
    try std.testing.expectEqual(@as(u32, @intCast(field(fri, "n_queries").integer)), pcs_config.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, @intCast(field(fri, "fold_step").integer)), pcs_config.fri_config.fold_step);

    var bundle = try loadBundle(allocator);
    defer bundle.deinit();
    var observer = Observer{ .allocator = allocator };
    defer observer.deinit();
    var proof = try Prover.prove(allocator, ctx.values(), &pp, &bundle, pcs_config, &observer);
    defer proof.deinit();

    // Component log sizes.
    for (field(expected, "component_log_sizes").array.items, proof.component_log_sizes.toArray()) |pair, log_size| {
        try std.testing.expectEqual(@as(u32, @intCast(pair.array.items[1].integer)), log_size);
    }
    // Transcript.
    const steps = field(expected, "steps").array.items;
    try std.testing.expectEqual(steps.len, observer.steps.items.len);
    for (steps, observer.steps.items) |want, got| {
        try std.testing.expectEqualStrings(field(want, "step").string, @tagName(got[0]));
        expectHex(field(want, "channel_digest"), &got[1]) catch |err| {
            std.debug.print("{s}: transcript differs at {s}\n", .{ @tagName(which), @tagName(got[0]) });
            return err;
        };
    }
    const stark = &proof.stark_proof.proof.commitment_scheme_proof;
    try expectHex(field(expected, "preprocessed_root"), &stark.commitments.items[0]);
    try expectHex(field(expected, "circuit_hash"), &proof.circuit_hash);
    const outputs = field(expected, "output_values").array.items;
    try std.testing.expectEqual(outputs.len, proof.output_values.len);
    for (outputs, proof.output_values) |want, got| try expectQm31(want, got);
    try expectU64(field(expected, "interaction_pow_nonce"), proof.interaction_pow_nonce);
    try expectQm31(field(expected, "interaction_z"), observer.z);
    try expectQm31(field(expected, "interaction_alpha"), observer.alpha);
    for (field(expected, "claimed_sums").array.items, proof.claimed_sums.toArray()) |pair, got| {
        try expectQm31(pair.array.items[1], got);
    }
    const commitments = field(expected, "commitments").array.items;
    try std.testing.expectEqual(commitments.len, stark.commitments.items.len);
    for (commitments, stark.commitments.items) |want, got| try expectHex(want, &got);
    const fri_record = field(expected, "fri");
    try expectHex(field(fri_record, "first_layer_root"), &stark.fri_proof.first_layer.commitment);
    const inner = field(fri_record, "inner_layer_roots").array.items;
    try std.testing.expectEqual(inner.len, stark.fri_proof.inner_layers.len);
    for (inner, stark.fri_proof.inner_layers) |want, layer| try expectHex(want, &layer.commitment);
    const last_layer = field(fri_record, "last_layer_poly").array.items;
    try std.testing.expectEqual(last_layer.len, stark.fri_proof.last_layer_poly.coeffs.len);
    for (last_layer, stark.fri_proof.last_layer_poly.coeffs) |want, got| try expectQm31(want, got);
    try expectU64(field(expected, "fri_pow_nonce"), stark.proof_of_work);
    // Committed trees.
    try expectTree(field(expected, "preprocessed_columns"), field(expected, "preprocessed_accumulator_sha256"), observer.trees[0].items, observer.accumulators[0]);
    try expectTree(field(expected, "base_columns"), field(expected, "base_accumulator_sha256"), observer.trees[1].items, observer.accumulators[1]);
    try expectTree(field(expected, "interaction_columns"), field(expected, "interaction_accumulator_sha256"), observer.trees[2].items, observer.accumulators[2]);
}

test "R7: fibonacci proof matches prove_circuit_assignment" {
    try proveAndCompare(.fibonacci);
}

test "R7: permutation proof matches prove_circuit_assignment" {
    try proveAndCompare(.permutation);
}

test "R7: blake proof matches prove_circuit_assignment" {
    try proveAndCompare(.blake);
}

test "R7: triple_xor proof matches prove_circuit_assignment" {
    try proveAndCompare(.triple_xor);
}

test "R7: m31_to_u32 proof matches prove_circuit_assignment" {
    try proveAndCompare(.m31_to_u32);
}

test "R7: blake_g_gate proof matches prove_circuit_assignment" {
    try proveAndCompare(.blake_g_gate);
}
