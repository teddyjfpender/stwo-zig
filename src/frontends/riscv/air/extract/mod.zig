//! Extraction of the per-row uniqueness model from the shipped opcode AIR.
//!
//! The pipeline is: instantiate `air/semantics` over `symbolic.Scalar`, run
//! `semantic_eval` and `opcode_entries` exactly as the prover does, classify
//! the recorded columns from the relation requests, and serialise the result
//! for `scripts/air_uniqueness.py`.
//!
//! The load-bearing test in this directory is the differential one. Extraction
//! that silently dropped constraints would still produce a well-formed model,
//! and the solver would report `unsat` -- uniqueness proved -- for a system
//! that is not the one being proven about. Replaying the recorded DAG against
//! the QM31 run of the same source on random assignments is what makes an
//! `unsat` mean anything.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const trace = @import("../../runner/trace.zig");
const semantic_eval = @import("../semantic_eval.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");

pub const symbolic = @import("symbolic.zig");
pub const model = @import("model.zig");
pub const json = @import("json.zig");
pub const program = @import("program.zig");
pub const program_json = @import("program_json.zig");

/// Fixed so a failure is reproducible; the differential check is a regression
/// guard, not a fuzzer, and a moving seed would make it flap.
pub const DIFFERENTIAL_SEED: u64 = 0x5157_4F5A_4947_3031;
pub const DIFFERENTIAL_ROUNDS: usize = 8;

/// Write one JSON model per family into `dir`.
pub fn emitAll(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!semantic_eval.isTraceCompatible(family)) continue;

        var names = std.heap.ArenaAllocator.init(allocator);
        defer names.deinit();
        var arena = symbolic.Arena.init(allocator);
        defer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();

        var system = try model.build(names.allocator(), &arena, family);
        defer system.deinit(names.allocator());

        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "{s}.json", .{@tagName(family)});
        const file = try dir.createFile(path, .{});
        defer file.close();
        var out_buffer: [1 << 16]u8 = undefined;
        var writer = file.writer(&out_buffer);
        try json.write(&writer.interface, &arena, system);
        try writer.interface.flush();
    }
}

// Emitting is a test rather than a build step because the extraction has no
// runtime consumer: `scripts/air_uniqueness.py` reads the JSON out of band.
// Set the variable to a directory to refresh the models.
test "extraction: emit models when RISCV_AIR_IR_DIR is set" {
    const path = std.posix.getenv("RISCV_AIR_IR_DIR") orelse return error.SkipZigTest;
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    try emitAll(std.testing.allocator, dir);
}

/// Differentially replay every extracted family against the QM31 evaluator.
///
/// This is public so focused evidence gates can execute the source-binding
/// check without relying on nested Zig test discovery.
pub fn checkDifferential(allocator: std.mem.Allocator) !void {
    var prng = std.Random.DefaultPrng.init(DIFFERENTIAL_SEED);
    const random = prng.random();

    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!semantic_eval.isTraceCompatible(family)) continue;

        var names = std.heap.ArenaAllocator.init(allocator);
        defer names.deinit();
        var arena = symbolic.Arena.init(allocator);
        defer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();

        var system = try model.build(names.allocator(), &arena, family);
        defer system.deinit(names.allocator());

        const n_columns = semantic_eval.mainColumnCount(family);
        const values = try allocator.alloc(M31, arena.names.items.len);
        defer allocator.free(values);
        const secure = try allocator.alloc(QM31, n_columns);
        defer allocator.free(secure);
        const replayed = try allocator.alloc(M31, arena.nodes.items.len);
        defer allocator.free(replayed);

        for (0..DIFFERENTIAL_ROUNDS) |_| {
            // Alias columns are defined by their own constraint, so their draw
            // is irrelevant; only the committed prefix feeds the QM31 run.
            for (values) |*value| value.* = M31.fromU64(random.int(u32));
            for (secure, values[0..n_columns]) |*slot, value| slot.* = QM31.fromBase(value);
            symbolic.replay(&arena, values, replayed);

            const expected = try semantic_eval.evaluate(family, secure, QM31.one());
            // `system.constraints` carries the family's own constraints plus the
            // placement equality, then one defining constraint per alias column.
            try std.testing.expect(system.constraints.len >= expected.len);
            for (expected.values[0..expected.len], system.constraints[0..expected.len]) |want, node| {
                try std.testing.expect(want.eql(QM31.fromBase(replayed[node])));
            }

            const list = try opcode_entries.fromMain(family, secure);
            try std.testing.expectEqual(list.len, system.lookups.len);
            for (list.entries[0..list.len], system.lookups) |want, got| {
                try std.testing.expectEqual(want.domain, got.domain);
                try std.testing.expectEqual(@as(usize, want.arity), got.tuple.len);
                try std.testing.expect(want.numerator.eql(QM31.fromBase(replayed[got.numerator])));
                for (want.values[0..want.arity], got.tuple) |value, node| {
                    try std.testing.expect(value.eql(QM31.fromBase(replayed[node])));
                }
            }
        }
    }
}

test "extraction: symbolic and QM31 runs of the same AIR agree pointwise" {
    try checkDifferential(std.testing.allocator);
}

test "extraction: every family declares outputs and names its committed columns" {
    const allocator = std.testing.allocator;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!semantic_eval.isTraceCompatible(family)) continue;

        var names = std.heap.ArenaAllocator.init(allocator);
        defer names.deinit();
        var arena = symbolic.Arena.init(allocator);
        defer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();

        var system = try model.build(names.allocator(), &arena, family);
        defer system.deinit(names.allocator());

        var outputs: usize = 0;
        var inputs: usize = 0;
        for (system.columns) |column| {
            switch (column.role) {
                .output => outputs += 1,
                .input => inputs += 1,
                .witness => {},
            }
            // Names are emitted verbatim as SMT-LIB symbols downstream.
            try std.testing.expect(column.name.len > 0);
            try std.testing.expect(!std.ascii.isDigit(column.name[0]));
            for (column.name) |byte| {
                try std.testing.expect(std.ascii.isAlphanumeric(byte) or byte == '_');
            }
        }
        // An empty output set makes uniqueness vacuous; an empty input set makes
        // it unprovable. Both are extraction bugs, not AIR findings.
        try std.testing.expect(outputs > 0);
        try std.testing.expect(inputs > 0);
        try std.testing.expectEqual(
            semantic_eval.constraintCount(family) + (system.columns.len - semantic_eval.mainColumnCount(family)),
            system.constraints.len,
        );
    }
}

test "extraction: emitted JSON parses as the flat IR the checker consumes" {
    const allocator = std.testing.allocator;
    var names = std.heap.ArenaAllocator.init(allocator);
    defer names.deinit();
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var system = try model.build(names.allocator(), &arena, .lt_reg);
    defer system.deinit(names.allocator());

    var text = std.Io.Writer.Allocating.init(allocator);
    defer text.deinit();
    try json.write(&text.writer, &arena, system);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, text.written(), .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqual(json.MODULUS, @as(u32, @intCast(object.get("modulus").?.integer)));
    try std.testing.expectEqual(system.columns.len, object.get("columns").?.array.items.len);
    try std.testing.expectEqual(arena.nodes.items.len, object.get("nodes").?.array.items.len);
    try std.testing.expectEqual(system.lookups.len, object.get("lookups").?.array.items.len);
}

test {
    _ = @import("program.zig");
    _ = @import("program_json.zig");
}
