//! The oracle's gate-list and value digest contract (`vectors/circuit/README.md`,
//! `tools/stwo-circuit-oracle-rs/src/checkpoint.rs`):
//!
//! ```text
//! kind_sha256      = SHA-256("STWO_CIRCUIT_GATE_KIND_V1\0" || kind || 0x00 || count:u64 || SHA-256(records))
//! gate_list_sha256 = SHA-256("STWO_CIRCUIT_GATE_LIST_V1\0" || n_vars:u64 || kind_sha256 × 10)
//! values_sha256    = SHA-256("STWO_CIRCUIT_VALUES_V1\0" || count:u64 || each value as 4 × u32)
//! ```
//!
//! Kinds are in `Circuit` field order; a record is the gate's variable
//! indices in struct field order as little-endian `u32`s (a permutation is
//! `len, inputs.., len, outputs..`). `debug_text_sha256` hashes the upstream
//! `Debug` text.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit_frontend = @import("stwo_circuit_frontend");

const builder = circuit_frontend.builder;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const kind_names = [_][]const u8{ "add", "sub", "mul", "pointwise_mul", "eq", "triple_xor", "m31_to_u32", "blake_g_gate", "permutation", "output" };

pub const KindSummary = struct { count: u64, sha256: [32]u8 };

pub const Summary = struct {
    n_vars: u64,
    kinds: [kind_names.len]KindSummary,
    gate_list_sha256: [32]u8,
    debug_text_sha256: [32]u8,
};

const KindHasher = struct {
    kind: []const u8,
    count: u64 = 0,
    records: Sha256 = .init(.{}),

    fn record(self: *KindHasher, fields: []const u32) void {
        self.count += 1;
        for (fields) |field| self.records.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, field)));
    }

    fn recordList(self: *KindHasher, inputs: []const u32, outputs: []const u32) void {
        self.count += 1;
        for ([_][]const u32{ inputs, outputs }) |list| {
            self.records.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, @intCast(list.len)))));
            for (list) |v| self.records.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
        }
    }

    fn finish(self: *KindHasher) KindSummary {
        var outer = Sha256.init(.{});
        outer.update("STWO_CIRCUIT_GATE_KIND_V1\x00");
        outer.update(self.kind);
        outer.update(&.{0});
        outer.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, self.count)));
        outer.update(&self.records.finalResult());
        return .{ .count = self.count, .sha256 = outer.finalResult() };
    }
};

/// One gate's variable indices, as the oracle's `checkpoint::Gate`: struct
/// fields in declaration order, or a permutation's input and output lists.
pub const Gate = union(enum) {
    fields: []const u32,
    lists: struct { inputs: []const u32, outputs: []const u32 },
};

/// The per-kind gate counts of `circuit`, in `kind_names` order (the oracle's `gate_counts`).
pub fn gateCounts(circuit: *const builder.Circuit) [kind_names.len]usize {
    return .{
        circuit.add.items.len,
        circuit.sub.items.len,
        circuit.mul.items.len,
        circuit.pointwise_mul.items.len,
        circuit.eq.items.len,
        circuit.triple_xor.items.len,
        circuit.m31_to_u32.items.len,
        circuit.blake_g_gate.items.len,
        circuit.permutation.len(),
        circuit.output.items.len,
    };
}

/// The oracle's `visit_gates`: every gate of kind `k` from index `start[k]`
/// on, kind by kind in `kind_names` order, as `visitor.gate(k, gate)`.
pub fn visitGates(circuit: *const builder.Circuit, start: [kind_names.len]usize, visitor: anytype) void {
    for ([_][]const builder.circuit.BinaryGate{ circuit.add.items, circuit.sub.items, circuit.mul.items, circuit.pointwise_mul.items }, 0..) |gates, k| {
        for (gates[start[k]..]) |g| visitor.gate(k, .{ .fields = &.{ g.in0, g.in1, g.out } });
    }
    for (circuit.eq.items[start[4]..]) |g| visitor.gate(4, .{ .fields = &.{ g.in0, g.in1 } });
    for (circuit.triple_xor.items[start[5]..]) |g| visitor.gate(5, .{ .fields = &.{ g.input_a, g.input_b, g.input_c, g.out } });
    for (circuit.m31_to_u32.items[start[6]..]) |g| visitor.gate(6, .{ .fields = &.{ g.input, g.out } });
    for (circuit.blake_g_gate.items[start[7]..]) |g| visitor.gate(7, .{ .fields = &(g.inputs() ++ g.outputs()) });
    for (start[8]..circuit.permutation.len()) |p| {
        const gate = circuit.permutation.get(p);
        visitor.gate(8, .{ .lists = .{ .inputs = gate.inputs, .outputs = gate.outputs } });
    }
    for (circuit.output.items[start[9]..]) |in0| visitor.gate(9, .{ .fields = &.{in0} });
}

/// Summarizes `circuit` under the contract above.
pub fn summarize(gpa: std.mem.Allocator, circuit: *const builder.Circuit) !Summary {
    var hashers: [kind_names.len]KindHasher = undefined;
    for (&hashers, kind_names) |*h, name| h.* = .{ .kind = name };
    const Recorder = struct {
        hashers: *[kind_names.len]KindHasher,
        pub fn gate(self: @This(), kind: usize, g: Gate) void {
            switch (g) {
                .fields => |fields| self.hashers[kind].record(fields),
                .lists => |lists| self.hashers[kind].recordList(lists.inputs, lists.outputs),
            }
        }
    };
    visitGates(circuit, @splat(0), Recorder{ .hashers = &hashers });

    var summary: Summary = undefined;
    summary.n_vars = circuit.n_vars;
    var list = Sha256.init(.{});
    list.update("STWO_CIRCUIT_GATE_LIST_V1\x00");
    list.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, summary.n_vars)));
    for (&summary.kinds, &hashers) |*kind, *h| {
        kind.* = h.finish();
        list.update(&kind.sha256);
    }
    summary.gate_list_sha256 = list.finalResult();

    const text = try builder.debug_format.circuitText(gpa, circuit);
    defer gpa.free(text);
    Sha256.hash(text, &summary.debug_text_sha256, .{});
    return summary;
}

/// `values_sha256`.
pub fn valuesSha256(values: []const QM31) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("STWO_CIRCUIT_VALUES_V1\x00");
    hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, values.len)));
    for (values) |v| {
        for (builder.ivalue.limbs(v)) |limb| hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, limb)));
    }
    return hasher.finalResult();
}

test "circuit summary: default context digests match the oracle's pinned values" {
    // `default_context_digests` in `tools/stwo-circuit-oracle-rs/src/checkpoint.rs`.
    const gpa = std.testing.allocator;
    var ctx = try builder.Context(QM31).init(gpa, 0);
    defer ctx.deinit();
    const summary = try summarize(gpa, &ctx.circuit);
    try std.testing.expectEqual(@as(u64, 3), summary.n_vars);
    try std.testing.expectEqualStrings("169eb78a79a183ddc6318834166cff7cb16d01678810674657b47d2bd3c7d843", &std.fmt.bytesToHex(summary.gate_list_sha256, .lower));
    try std.testing.expectEqualStrings("5602189d215b41df4588507ecb0d1da66e765d33fc84b32445b37961049b7eb6", &std.fmt.bytesToHex(valuesSha256(ctx.values()), .lower));
}

fn smallCircuit(comptime V: type, ctx: *builder.Context(V)) !void {
    const a = try ctx.guess(builder.ivalue.fromQm31(V, builder.ivalue.qm31FromU32s(2, 0, 0, 0)));
    const b = try ctx.guess(builder.ivalue.fromQm31(V, builder.ivalue.qm31FromU32s(2, 0, 0, 0)));
    const sum = try ctx.add(a, b);
    const product = try ctx.mul(a, b);
    try ctx.eq(sum, product);
    _ = try ctx.permute(&.{ ctx.u(), a }, struct {
        fn identity(in: []const V, out: []V) void {
            @memcpy(out, in);
        }
    }.identity);
}

test "circuit summary: small circuit digest is value independent" {
    // `small_circuit_digest_is_value_independent` in the oracle's checkpoint.rs.
    const gpa = std.testing.allocator;
    var values = try builder.Context(QM31).init(gpa, 0);
    defer values.deinit();
    try smallCircuit(QM31, &values);
    var topology = try builder.Context(builder.NoValue).init(gpa, 0);
    defer topology.deinit();
    try smallCircuit(builder.NoValue, &topology);
    const summary = try summarize(gpa, &values.circuit);
    try std.testing.expectEqual(summary, try summarize(gpa, &topology.circuit));
    try std.testing.expectEqualStrings("e00e30382723ad2a33676fefbfe3b1d4fa43324a68273029398398b3c50a08be", &std.fmt.bytesToHex(summary.gate_list_sha256, .lower));
    var counts: [kind_names.len]u64 = undefined;
    for (&counts, summary.kinds) |*c, k| c.* = k.count;
    try std.testing.expectEqual([_]u64{ 1, 0, 1, 0, 1, 0, 0, 0, 1, 1 }, counts);
}
