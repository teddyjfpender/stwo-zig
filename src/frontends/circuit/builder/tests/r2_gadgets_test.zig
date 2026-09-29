//! Rungs R1 and R2: every case of `vectors/circuit/r2/gadgets.json` (oracle
//! `gadgets` subcommand over https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! For each case, as the oracle does, the harness builds the circuit in value
//! mode with `assert_eq_on_eval`, records the output values and the `built`
//! summary, runs `finalize(false)` and records the `finalized` summary and
//! value digest; then it rebuilds in topology mode. It asserts:
//!
//! - both summaries (n_vars, per-kind counts and digests, gate-list digest,
//!   `Debug` text digest), the value digest, the output variables and values
//!   equal the oracle's;
//! - the finalized `Debug` text equals the oracle's line by line (first
//!   difference reported);
//! - the `NoValue` build has identical summaries and output variables;
//! - the finalized circuit is satisfied and yields every variable once;
//! - gadget outputs equal an independent host computation where one exists.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit_frontend = @import("stwo_circuit_frontend");
const gadget_cases = @import("gadget_cases.zig");
const circuit_summary = @import("circuit_summary.zig");

const builder = circuit_frontend.builder;
const QM31 = stwo_core.fields.qm31.QM31;
const P = stwo_core.fields.m31.Modulus;
const Json = std.json.Value;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Case = gadget_cases.Case;

const fixture_path = "vectors/circuit/r2/gadgets.json";

test {
    _ = circuit_summary;
}

test "R1/R2: every gadget case matches the oracle checkpoint" {
    const gpa = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(gpa, fixture_path, 16 << 20);
    defer gpa.free(bytes);
    var parsed = try std.json.parseFromSlice(Json, gpa, bytes, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("stwo-circuit-oracle-checkpoint-v1", root.get("schema").?.string);
    try std.testing.expectEqualStrings("gadgets", root.get("subcommand").?.string);
    try std.testing.expectEqualStrings("5a7c5ede4299c91a61df19a07cba4f7502c14230", root.get("authority").?.object.get("revision").?.string);

    const records = root.get("body").?.object.get("cases").?.array.items;
    try std.testing.expectEqual(gadget_cases.cases.len, records.len);
    for (gadget_cases.cases, records) |case, record| {
        runCase(gpa, case, record.object) catch |err| {
            var name_buffer: [64]u8 = undefined;
            std.debug.print("gadget case {s} failed: {s}\n", .{ case.name(&name_buffer), @errorName(err) });
            return err;
        };
    }
}

fn runCase(gpa: std.mem.Allocator, case: Case, record: std.json.ObjectMap) !void {
    var name_buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings(record.get("name").?.string, case.name(&name_buffer));
    try std.testing.expectEqual(@as(i64, @intCast(case.nReserved())), record.get("n_reserved").?.integer);

    var ctx = try builder.Context(QM31).init(gpa, case.nReserved());
    defer ctx.deinit();
    ctx.assert_eq_on_eval = true;
    const outputs = try case.build(QM31, &ctx);
    const output_values = try gpa.alloc(QM31, outputs.len);
    defer gpa.free(output_values);
    for (output_values, outputs) |*v, out| v.* = ctx.get(out);
    const built = try circuit_summary.summarize(gpa, &ctx.circuit);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
    const finalized = try circuit_summary.summarize(gpa, &ctx.circuit);

    try expectSummary(record.get("built").?.object, built);
    try expectSummary(record.get("finalized").?.object, finalized);
    try expectHex(record.get("finalized_values_sha256").?.string, circuit_summary.valuesSha256(ctx.values()));
    try expectOutputs(record, outputs, output_values);
    if (record.get("finalized_debug_text")) |lines| try expectDebugText(gpa, lines.array.items, &ctx.circuit);
    try expectHostOutputs(case, output_values);

    // Topology mode: the same gates and output variables.
    var topology = try builder.Context(builder.NoValue).init(gpa, case.nReserved());
    defer topology.deinit();
    const topology_outputs = try case.build(builder.NoValue, &topology);
    try std.testing.expectEqualSlices(builder.Var, outputs, topology_outputs);
    try std.testing.expectEqual(built, try circuit_summary.summarize(gpa, &topology.circuit));
    try topology.finalize(false);
    try std.testing.expectEqual(finalized, try circuit_summary.summarize(gpa, &topology.circuit));
}

fn expectHex(expected: []const u8, actual: [32]u8) !void {
    try std.testing.expectEqualStrings(expected, &std.fmt.bytesToHex(actual, .lower));
}

fn expectSummary(expected: std.json.ObjectMap, actual: circuit_summary.Summary) !void {
    try std.testing.expectEqual(expected.get("n_vars").?.integer, @as(i64, @intCast(actual.n_vars)));
    const kinds = expected.get("kinds").?.array.items;
    try std.testing.expectEqual(circuit_summary.kind_names.len, kinds.len);
    for (kinds, actual.kinds, circuit_summary.kind_names) |kind, summary, name| {
        try std.testing.expectEqualStrings(name, kind.object.get("kind").?.string);
        try std.testing.expectEqual(kind.object.get("count").?.integer, @as(i64, @intCast(summary.count)));
        try expectHex(kind.object.get("sha256").?.string, summary.sha256);
    }
    try expectHex(expected.get("gate_list_sha256").?.string, actual.gate_list_sha256);
    try expectHex(expected.get("debug_text_sha256").?.string, actual.debug_text_sha256);
}

fn expectOutputs(record: std.json.ObjectMap, outputs: []const builder.Var, values: []const QM31) !void {
    const vars = record.get("output_vars").?.array.items;
    const expected_values = record.get("output_values").?.array.items;
    try std.testing.expectEqual(vars.len, outputs.len);
    try std.testing.expectEqual(expected_values.len, values.len);
    for (vars, outputs) |v, out| try std.testing.expectEqual(v.integer, @as(i64, out.idx));
    for (expected_values, values) |e, v| {
        const limbs = builder.ivalue.limbs(v);
        for (e.array.items, limbs) |limb, actual| try std.testing.expectEqual(limb.integer, @as(i64, actual));
    }
}

fn expectDebugText(gpa: std.mem.Allocator, expected: []const Json, circuit: *const builder.Circuit) !void {
    const text = try builder.debug_format.circuitText(gpa, circuit);
    defer gpa.free(text);
    var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
    for (expected, 0..) |line, i| {
        const actual = lines.next() orelse return error.DebugTextTooShort;
        if (!std.mem.eql(u8, line.string, actual)) {
            std.debug.print("debug text differs at line {d}: expected `{s}`, got `{s}`\n", .{ i, line.string, actual });
            return error.DebugTextMismatch;
        }
    }
    if (lines.next() != null) return error.DebugTextTooLong;
}

/// Independent host computations of the gadget outputs.
fn expectHostOutputs(case: Case, values: []const QM31) !void {
    switch (case) {
        .blake2s_u32s => |n_bytes| {
            var message: [128]u8 = undefined;
            for (message[0..n_bytes], 0..) |*byte, i| byte.* = gadget_cases.messageByte(i);
            try expectDigestWords(message[0..n_bytes], values);
        },
        .blake2s_qm31 => |c| {
            const n_words = std.math.divCeil(usize, c.n_bytes, 4) catch unreachable;
            var message: [80]u8 = @splat(0);
            for (0..n_words) |i| {
                var word = (@as(u32, 0x0101_0101) *% @as(u32, @intCast(i + 3))) & P;
                const tail = c.n_bytes % 4;
                if (i == n_words - 1 and tail != 0) word &= (@as(u32, 1) << @intCast(8 * tail)) - 1;
                std.mem.writeInt(u32, message[4 * i ..][0..4], word, .little);
            }
            if (c.reduce) {
                var digest: [32]u8 = undefined;
                Blake2s256.hash(message[0..c.n_bytes], &digest, .{});
                try expectReduced(digest, values);
            } else {
                try expectDigestWords(message[0..c.n_bytes], values);
            }
        },
        .reduce_hash_value => {
            var digest: [32]u8 = undefined;
            for ([8]u32{ P, P + 1, std.math.maxInt(u32), 0x8000_0000, P - 1, 0, 1, 0xdead_beef }, 0..) |word, i| std.mem.writeInt(u32, digest[4 * i ..][0..4], word, .little);
            try expectReduced(digest, values);
        },
        .circuit_hash => {
            // `circuit_hash_test.rs`: the expected circuit hash words.
            const words = [8]u32{ 0xa881_0641, 0x5239_1285, 0x90b3_7fd2, 0x905b_887a, 0x7db7_dc81, 0xa7c3_a731, 0xd0d4_6b34, 0x8fa6_a471 };
            try std.testing.expectEqual(words.len, values.len);
            for (words, values) |w, v| try std.testing.expect(v.eql(builder.ivalue.packU32(QM31, w)));
        },
        else => {},
    }
}

fn expectDigestWords(message: []const u8, values: []const QM31) !void {
    var digest: [32]u8 = undefined;
    Blake2s256.hash(message, &digest, .{});
    try std.testing.expectEqual(@as(usize, 8), values.len);
    for (values, 0..) |v, i| try std.testing.expect(v.eql(builder.ivalue.packU32(QM31, std.mem.readInt(u32, digest[4 * i ..][0..4], .little))));
}

/// `reduce_to_m31` then `qm31_from_bytes` on each half.
fn expectReduced(digest: [32]u8, values: []const QM31) !void {
    try std.testing.expectEqual(@as(usize, 2), values.len);
    try std.testing.expect(values[0].eql(builder.blake.qm31FromBytes(digest[0..16].*)));
    try std.testing.expect(values[1].eql(builder.blake.qm31FromBytes(digest[16..32].*)));
}
