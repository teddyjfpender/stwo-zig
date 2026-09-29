//! The per-stage statement trace of one evaluator run, in the format of
//! `vectors/circuit/r3/statement_trace.json` (oracle subcommand
//! `statement-trace`, `tools/stwo-circuit-oracle-rs/src/components/statement_trace.rs`).
//!
//! The harness marks the context after each of its stages (`inputs`,
//! `evaluate`, `finalize_logup_in_pairs`). For every stage after `inputs` and
//! every gate kind the stage appended to, the gates it appended are hashed with
//! each variable written relative to `base` (`n_vars` after the harness
//! inputs) as the little-endian two's complement `i32`:
//!
//! ```text
//! kind digest   := SHA-256(DOMAIN || kind || 0x00 || count u64 || SHA-256(records))
//! window digest := SHA-256(DOMAIN || kind || 0x00 || window u32 || records of gates
//!                          [128 * window, 128 * window + 128))
//! ```
//!
//! Comparing kind digests and then windows names the first differing run of at
//! most 128 gates of one kind in one harness stage, which the whole-circuit
//! gate-list hash of `components.json` cannot.
//!
//! Gates are counted and visited with the whole-circuit summary's
//! `gateCounts` and `visitGates` (the oracle's `gate_counts` and `visit_gates`).

const std = @import("std");
const circuit_frontend = @import("stwo_circuit_frontend");
const fixture = @import("../../testing/fixture_json.zig");
const circuit_summary = @import("../../testing/circuit_summary.zig");

const Circuit = circuit_frontend.builder.Circuit;
const kind_names = circuit_summary.kind_names;
const n_kinds = kind_names.len;

const Sha256 = std.crypto.hash.sha2.Sha256;
const Value = std.json.Value;

const domain = "STWO_CIRCUIT_STATEMENT_TRACE_V1\x00";
pub const window = 128;
pub const stage_names = [_][]const u8{ "inputs", "evaluate", "finalize_logup_in_pairs" };

/// The circuit's per-kind gate counts and `n_vars` after a stage.
pub const Mark = struct { counts: [n_kinds]usize, n_vars: u32 };

pub fn mark(circuit: *const Circuit) Mark {
    return .{ .counts = circuit_summary.gateCounts(circuit), .n_vars = circuit.n_vars };
}

pub const KindTrace = struct {
    kind: []const u8,
    count: u64,
    sha256: [32]u8,
    windows: []const [32]u8,
};

pub const StageTrace = struct {
    stage: []const u8,
    /// `n_vars` after the stage, relative to `base`.
    n_vars: u64,
    kinds: []const KindTrace,
};

pub const Trace = struct {
    base: u64,
    stages: []const StageTrace,
};

fn header(kind: []const u8) Sha256 {
    var hasher = Sha256.init(.{});
    hasher.update(domain);
    hasher.update(kind);
    hasher.update(&.{0});
    return hasher;
}

const KindDigest = struct {
    kind: []const u8,
    count: u64 = 0,
    records: Sha256 = Sha256.init(.{}),
    window: ?Sha256 = null,
    windows: std.ArrayList([32]u8) = .empty,

    fn closeWindow(self: *KindDigest, arena: std.mem.Allocator) !void {
        if (self.window) |*open| {
            try self.windows.append(arena, open.finalResult());
            self.window = null;
        }
    }

    fn gate(self: *KindDigest, arena: std.mem.Allocator, g: circuit_summary.Gate, base: u32) !void {
        if (self.count % window == 0) {
            try self.closeWindow(arena);
            var opened = header(self.kind);
            opened.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(self.count / window))));
            self.window = opened;
        }
        self.count += 1;
        switch (g) {
            .fields => |fields| self.updateRelative(fields, base),
            .lists => |lists| for ([_][]const u32{ lists.inputs, lists.outputs }) |list| {
                self.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, @intCast(list.len)))));
                self.updateRelative(list, base);
            },
        }
    }

    fn update(self: *KindDigest, bytes: []const u8) void {
        self.records.update(bytes);
        self.window.?.update(bytes);
    }

    /// Each variable as `var - base`, a little-endian two's complement `i32`.
    fn updateRelative(self: *KindDigest, vars: []const u32, base: u32) void {
        for (vars) |v| {
            const relative: i32 = @intCast(@as(i64, v) - @as(i64, base));
            self.update(&std.mem.toBytes(std.mem.nativeToLittle(i32, relative)));
        }
    }

    fn finish(self: *KindDigest, arena: std.mem.Allocator) !?KindTrace {
        try self.closeWindow(arena);
        if (self.count == 0) return null;
        var outer = header(self.kind);
        outer.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, self.count)));
        outer.update(&self.records.finalResult());
        return .{ .kind = self.kind, .count = self.count, .sha256 = outer.finalResult(), .windows = self.windows.items };
    }
};

/// The trace of the stages between consecutive `marks` (one per
/// `stage_names` entry) of `circuit`. Allocates from `arena`.
pub fn trace(arena: std.mem.Allocator, circuit: *const Circuit, marks: []const Mark) !Trace {
    std.debug.assert(marks.len == stage_names.len);
    const base = marks[0].n_vars;
    const stages = try arena.alloc(StageTrace, marks.len - 1);
    for (stages, marks[0 .. marks.len - 1], marks[1..], stage_names[1..]) |*stage, start, end, name| {
        var digests: [n_kinds]KindDigest = undefined;
        for (&digests, kind_names) |*digest, kind| digest.* = .{ .kind = kind };
        var visitor: Visitor = .{ .arena = arena, .digests = &digests, .start = start.counts, .end = end.counts, .base = base };
        circuit_summary.visitGates(circuit, start.counts, &visitor);
        if (visitor.failure) |err| return err;
        var kinds: std.ArrayList(KindTrace) = .empty;
        for (&digests) |*digest| if (try digest.finish(arena)) |kind| try kinds.append(arena, kind);
        stage.* = .{ .stage = name, .n_vars = end.n_vars - base, .kinds = kinds.items };
    }
    return .{ .base = base, .stages = stages };
}

const Visitor = struct {
    arena: std.mem.Allocator,
    digests: *[n_kinds]KindDigest,
    start: [n_kinds]usize,
    end: [n_kinds]usize,
    base: u32,
    seen: [n_kinds]usize = @splat(0),
    failure: ?anyerror = null,

    pub fn gate(self: *Visitor, kind: usize, g: circuit_summary.Gate) void {
        if (self.start[kind] + self.seen[kind] >= self.end[kind]) return;
        self.seen[kind] += 1;
        self.digests[kind].gate(self.arena, g, self.base) catch |err| {
            self.failure = self.failure orelse err;
        };
    }
};

/// Asserts `actual` equals the `statement_trace.json` record `expected`,
/// kind digests first, then (on a mismatch) the first differing window.
pub fn expectTrace(expected: Value, actual: Trace) !void {
    try std.testing.expectEqual(try fixture.unsigned(u64, try fixture.field(expected, "base")), actual.base);
    const stages = try fixture.array(try fixture.field(expected, "stages"));
    try std.testing.expectEqual(stages.len, actual.stages.len);
    for (stages, actual.stages) |stage, got| {
        errdefer std.debug.print("statement trace mismatch in stage {s}\n", .{got.stage});
        try std.testing.expectEqualStrings(try fixture.string(try fixture.field(stage, "stage")), got.stage);
        try std.testing.expectEqual(try fixture.unsigned(u64, try fixture.field(stage, "n_vars")), got.n_vars);
        const kinds = try fixture.array(try fixture.field(stage, "kinds"));
        try std.testing.expectEqual(kinds.len, got.kinds.len);
        for (kinds, got.kinds) |kind, got_kind| {
            try std.testing.expectEqualStrings(try fixture.string(try fixture.field(kind, "kind")), got_kind.kind);
            const windows = try fixture.array(try fixture.field(kind, "windows"));
            try std.testing.expectEqual(windows.len, got_kind.windows.len);
            for (windows, got_kind.windows, 0..) |want, have, index| {
                errdefer std.debug.print("first differing {s} window: gates [{d}, {d})\n", .{ got_kind.kind, index * window, (index + 1) * window });
                try std.testing.expectEqual(try fixture.digest(want), have);
            }
            try std.testing.expectEqual(try fixture.unsigned(u64, try fixture.field(kind, "count")), got_kind.count);
            try std.testing.expectEqual(try fixture.digest(try fixture.field(kind, "sha256")), got_kind.sha256);
        }
    }
}
