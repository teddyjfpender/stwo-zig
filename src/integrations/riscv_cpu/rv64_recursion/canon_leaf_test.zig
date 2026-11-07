//! M9 canon-leaf tests: the 15-block basket maps onto the catalog; class keys recur across blocks.
//! Vector: canon_leaf_basket.json = the per-segment declarations of the 15 M3 accepted basket bundles
//! (trimmed copy of vectors/reports/rv64-m9-prep/canon-leaf/segment-shapes-15.json). The expected counts are the
//! ones scripts/rv64_m9_canon_leaf_catalog.py reports (catalog-r4.json): Python and Zig must agree.
const std = @import("std");
const testing = std.testing;
const L = @import("canon_leaf.zig");
const Canon = @import("../word16_global_execution/ethereum/canon_native.zig");
const V1 = @import("../word16_global_execution/ethereum/canon_native_rungs.zig");
const W = @import("../word16_global_execution/services/wire.zig");
const T = @import("../word16_global_execution/services/types.zig");

const Truth = struct { family: T.Family, logs: [2]u32 };
const Block = struct { block: u64, cpus: []W.CpuDeclaration, truths: []Truth };
const Basket = struct { schema: []const u8, blocks: []Block };

fn basket(a: std.mem.Allocator) !std.json.Parsed(Basket) {
    return std.json.parseFromSlice(Basket, a, @embedFile("canon_leaf_basket.json"), .{ .ignore_unknown_fields = true });
}
fn dwordLayout(b: Block) bool {
    for (b.cpus) |c| if (c.bridges.ls_dword != null) return true;
    return false;
}
fn exactKey(d: W.CpuDeclaration) [32]u8 {
    // Today's leaf class is a function of the exact declaration (rootverify leafKey); hash the full vector + flags.
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    const v = Canon.cpuVector(d);
    h.update(std.mem.sliceAsBytes(&v));
    h.update(std.mem.asBytes(&Canon.layoutFlags(d.geometry)));
    return h.finalResult();
}
const Census = struct {
    leaves: usize = 0,
    misses: usize = 0,
    used: std.AutoHashMapUnmanaged(u32, void) = .{},
    exact: std.AutoHashMapUnmanaged([32]u8, void) = .{},
    miss_blocks: std.AutoHashMapUnmanaged(u64, void) = .{},
    fn deinit(self: *Census, a: std.mem.Allocator) void {
        self.used.deinit(a);
        self.exact.deinit(a);
        self.miss_blocks.deinit(a);
    }
};
fn census(a: std.mem.Allocator, table: anytype, b: []const Block) !Census {
    var c = Census{};
    errdefer c.deinit(a);
    for (b) |blk| {
        for (blk.cpus, 0..) |d, i| {
            c.leaves += 1;
            try c.exact.put(a, exactKey(d), {});
            const class = L.cpuClass(table, d, i, blk.cpus.len, dwordLayout(blk)) catch {
                c.misses += 1;
                try c.miss_blocks.put(a, blk.block, {});
                continue;
            };
            try c.used.put(a, class.index, {});
        }
        for (blk.truths) |t| {
            c.leaves += 1;
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(std.mem.asBytes(&@intFromEnum(t.family)));
            h.update(std.mem.sliceAsBytes(&t.logs));
            try c.exact.put(a, h.finalResult(), {});
            const class = L.truthClass(table, t.family, t.logs) catch {
                c.misses += 1;
                try c.miss_blocks.put(a, blk.block, {});
                continue;
            };
            try c.used.put(a, class.index, {});
        }
    }
    return c;
}

test "canon-leaf mode selector: default off, unknown refused" {
    try testing.expectEqual(L.Mode.off, try L.parseMode(null));
    try testing.expectEqual(L.Mode.off, try L.parseMode("0"));
    try testing.expectEqual(L.Mode.on, try L.parseMode("1"));
    try testing.expectEqual(L.Mode.audit, try L.parseMode("audit"));
    try testing.expectError(error.UnknownCanonLeafMode, L.parseMode("2"));
}

test "canon-leaf catalog is well formed: 72 classes, cpu_log-major CPU rungs, cpu_last ladder 16..22, ascending truths" {
    try testing.expectEqual(@as(u32, 72), L.count(L.Catalog));
    var seen = std.AutoHashMap(u32, void).init(testing.allocator);
    defer seen.deinit();
    for (L.Catalog.CPU) |e| {
        for (e.rungs[1..], 0..) |v, i| try testing.expect(v[0] >= e.rungs[i][0]);
        for (e.rungs) |v| try testing.expectEqual(@as(u32, 5), v[12]);
        if (e.family == .cpu_last) for (16..23) |log| {
            var found = false;
            for (e.rungs) |v| found = found or v[0] == log;
            try testing.expect(found);
        };
        for (0..e.rungs.len) |r| try seen.put(L.indexOf(L.Catalog, e.family, 0, @intCast(r)).?, {});
    }
    for (L.Catalog.TRUTH) |e| {
        for (e.logs[1..], 0..) |l, i| try testing.expect(l > e.logs[i]);
        for (0..e.logs.len) |r| try seen.put(L.indexOf(L.Catalog, e.family, e.aux, @intCast(r)).?, {});
    }
    // Indices are a bijection onto [0, 72): a constant-index table of depth ceil(log2 72) = 7.
    try testing.expectEqual(@as(u32, 72), seen.count());
    var it = seen.keyIterator();
    while (it.next()) |k| try testing.expect(k.* < 72);
}

test "canon-leaf: every one of the 579 basket leaves maps onto the catalog; 53 classes cover 15 blocks (389 exact today)" {
    const a = testing.allocator;
    const parsed = try basket(a);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 15), parsed.value.blocks.len);
    var c = try census(a, L.Catalog, parsed.value.blocks);
    defer c.deinit(a);
    try testing.expectEqual(@as(usize, 579), c.leaves);
    try testing.expectEqual(@as(usize, 0), c.misses);
    try testing.expectEqual(@as(u32, 53), c.used.count());
    try testing.expectEqual(@as(u32, 389), c.exact.count());
    std.debug.print("RV64_M9_CANON_LEAF leaves={d} exact_classes={d} catalog={d} used={d} misses={d}\n", .{ c.leaves, c.exact.count(), L.count(L.Catalog), c.used.count(), c.misses });
}

test "canon-leaf: the frozen canon-native v1 table (14 blocks, R=4) misses 3 basket leaves under the strict roster" {
    // Regression evidence for the design: v1 rungs mix cpu_log values inside a rung group and were derived without
    // 25229951, so 3 leaves (24628595 cpu_last, 25229951 cpu_first, 26235168 cpu_last at cpu_log 17) have no class.
    const a = testing.allocator;
    const parsed = try basket(a);
    defer parsed.deinit();
    var c = try census(a, V1, parsed.value.blocks);
    defer c.deinit(a);
    try testing.expectEqual(@as(usize, 3), c.misses);
    for ([_]u64{ 24628595, 25229951, 26235168 }) |b| try testing.expect(c.miss_blocks.contains(b));
}

fn inputs(class: L.LeafClass) L.KeyInputs {
    return .{ .class = class, .rung_table_id = L.rungTableId(L.Catalog), .native_profile = @splat(1), .image = @splat(2), .pcs_config = @splat(3), .outer_domain = @splat(4), .outer_shape = 2 };
}

test "canon-leaf class keys recur across blocks: equal for different exact segments of one class, distinct across classes" {
    const a = testing.allocator;
    const parsed = try basket(a);
    defer parsed.deinit();
    // Per class: the first exact declaration seen and its key; every later member must give the same key.
    var first = std.AutoHashMap(u32, struct { exact: [32]u8, key: [32]u8, block: u64 }).init(a);
    defer first.deinit();
    var cross_block_recurrences: usize = 0;
    var distinct_exact_same_key: usize = 0;
    for (parsed.value.blocks) |blk| for (blk.cpus, 0..) |d, i| {
        const class = try L.cpuClass(L.Catalog, d, i, blk.cpus.len, dwordLayout(blk));
        const key = L.classKey(inputs(class));
        if (first.get(class.index)) |f| {
            try testing.expectEqualSlices(u8, &f.key, &key);
            if (f.block != blk.block) cross_block_recurrences += 1;
            if (!std.mem.eql(u8, &f.exact, &exactKey(d))) distinct_exact_same_key += 1;
        } else try first.put(class.index, .{ .exact = exactKey(d), .key = key, .block = blk.block });
    };
    // Most CPU leaves land in a class first seen in another block (the cross-block hit rate the catalog buys).
    try testing.expect(cross_block_recurrences > 250);
    try testing.expect(distinct_exact_same_key > 250);
    // All 72 catalog keys are distinct; any key input change moves the key.
    var keys = std.AutoHashMap([32]u8, void).init(a);
    defer keys.deinit();
    for (L.Catalog.CPU) |e| for (0..e.rungs.len) |r| {
        try keys.put(L.classKey(inputs(.{ .kind = .cpu, .family = e.family, .rung = @intCast(r), .index = L.indexOf(L.Catalog, e.family, 0, @intCast(r)).? })), {});
    };
    for (L.Catalog.TRUTH) |e| for (0..e.logs.len) |r| {
        try keys.put(L.classKey(inputs(.{ .kind = .truth, .family = e.family, .aux = e.aux, .rung = @intCast(r), .index = L.indexOf(L.Catalog, e.family, e.aux, @intCast(r)).? })), {});
    };
    try testing.expectEqual(@as(u32, 72), keys.count());
    const base = inputs(.{ .kind = .cpu, .family = .cpu_middle, .rung = 1, .index = L.indexOf(L.Catalog, .cpu_middle, 0, 1).? });
    const k0 = L.classKey(base);
    inline for (.{ "native_profile", "image", "pcs_config", "outer_domain", "rung_table_id" }) |field| {
        var m = base;
        @field(m, field)[0] ^= 1;
        try testing.expect(!std.mem.eql(u8, &k0, &L.classKey(m)));
    }
    var s = base;
    s.outer_shape = 1;
    try testing.expect(!std.mem.eql(u8, &k0, &L.classKey(s)));
    // The rung table id binds the catalog: the frozen v1 table gives another id.
    try testing.expect(!std.mem.eql(u8, &L.rungTableId(L.Catalog), &L.rungTableId(V1)));
}

test "canon-leaf strict fit: cpu_log is a class constant, a missing component refuses, padding a present one is allowed" {
    const a = testing.allocator;
    const parsed = try basket(a);
    defer parsed.deinit();
    const blk = parsed.value.blocks[0];
    const d = blk.cpus[1];
    const class = try L.cpuClass(L.Catalog, d, 1, blk.cpus.len, true);
    var rung: Canon.CpuVector = undefined;
    for (L.Catalog.CPU) |e| if (e.family == class.family) {
        rung = e.rungs[class.rung];
    };
    try testing.expect(L.strictFit(d, rung, true));
    var other = rung;
    other[0] -= 1; // a different cpu_log is a different class
    try testing.expect(!L.strictFit(d, other, true));
    const v = Canon.cpuVector(d);
    for (v, 0..) |log, c| if (log != 0 and c >= 15 and c < 38) { // an unpaired bridge component
        var gone = rung;
        gone[c] = 0; // the rung lacks a component the segment uses
        try testing.expect(!L.strictFit(d, gone, true));
        break;
    };
}
