//! gn-node piece-only harness on REAL recorded data (test-only file; opt-in).
//!
//!   STWO_RV64_M8_GN_NODE_RECORDS=<dir>   node-*.gnr + pcs-*.gnp from
//!                                        outer_seed_record.zig (legacy path)
//!   STWO_RV64_M8_GN_NODE_TREE=<tree.json> the run's recursion-om31/tree.json
//!   STWO_RV64_M8_GPU_BASE / STWO_RV64_M8_JOBS_LIBRARY  (device arm)
//!
//! For every recorded fold/root node: build the class seed program from its
//! children's recorded classes, run the host mirror and (device arm) the
//! kernel over the children's regions, and require byte identity of every
//! output with the legacy host values: all seed records, the outputs and the
//! transcript checkpoint. For every recorded leaf: the proof part of its
//! seeds from the native child's recorded PCS image (the statement tail is
//! the native producer's, copied). Negative arms corrupt one input class per
//! check and require the named verdict. Prints one GN_NODE_HARNESS line per
//! node ([M] GPU time by CUDA events, host enqueue time) and a summary.
const std = @import("std");
const S = @import("outer_seed_device.zig");
const O = @import("ops.zig");

const Loaded = struct {
    a: std.mem.Allocator,
    nodes: std.AutoHashMapUnmanaged(u32, S.Record) = .empty,
    node_words: std.ArrayListUnmanaged([]u32) = .empty,
    pcs: std.ArrayListUnmanaged(S.PcsRecord) = .empty,
    children: std.AutoHashMapUnmanaged(u32, []u32) = .empty,
    fn deinit(self: *Loaded) void {
        var it = self.nodes.valueIterator();
        while (it.next()) |r| r.deinit(self.a);
        self.nodes.deinit(self.a);
        for (self.pcs.items) |p| self.a.free(p.shape.trees);
        self.pcs.deinit(self.a);
        for (self.node_words.items) |w| self.a.free(w);
        self.node_words.deinit(self.a);
        var ci = self.children.valueIterator();
        while (ci.next()) |c| self.a.free(c.*);
        self.children.deinit(self.a);
    }
};

fn readWords(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8) ![]u32 {
    const bytes = try dir.readFileAlloc(a, name, 1 << 30);
    defer a.free(bytes);
    const w = try a.alloc(u32, bytes.len / 4);
    @memcpy(std.mem.sliceAsBytes(w), bytes[0 .. w.len * 4]);
    return w;
}

fn load(a: std.mem.Allocator, path: []const u8, tree_path: ?[]const u8) !Loaded {
    var out = Loaded{ .a = a };
    errdefer out.deinit();
    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |e| {
        if (e.kind != .file) continue;
        if (std.mem.endsWith(u8, e.name, ".gnr")) {
            const w = try readWords(a, dir, e.name);
            try out.node_words.append(a, w);
            const r = try S.Record.parse(a, w);
            try out.nodes.put(a, r.ordinal, r);
        } else if (std.mem.endsWith(u8, e.name, ".gnp")) {
            const w = try readWords(a, dir, e.name);
            try out.node_words.append(a, w);
            try out.pcs.append(a, try S.PcsRecord.parse(a, w));
        }
    }
    if (tree_path) |tp| {
        const bytes = try std.fs.cwd().readFileAlloc(a, tp, 64 << 20);
        defer a.free(bytes);
        const Tree = struct { nodes: []const struct { children: []const u32 } };
        const parsed = try std.json.parseFromSlice(Tree, a, bytes, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        for (parsed.value.nodes, 0..) |n, i| if (n.children.len != 0) try out.children.put(a, @intCast(i), try a.dupe(u32, n.children));
    }
    return out;
}

const fold_domain: u32 = 0x4f464c31;
fn versionWord(arity: usize) u32 {
    return if (arity == 2) 2 else (@as(u32, @intCast(arity)) << 8) | 2;
}

/// Class wire capacity used by the harness (production: the class bound
/// outer_encode.maxEncodedBytes): one bound over every record, 64-aligned.
fn wireWords(l: *const Loaded) u32 {
    var m: usize = 0;
    var it = l.nodes.valueIterator();
    while (it.next()) |r| m = @max(m, r.wire.len);
    return @intCast(std.mem.alignForward(usize, 1 + (m + 3) / 4, 64));
}

const Gpu = struct {
    libs: O.Libraries,
    peer: O.Peer,
    seed: S.Symbols,
    ctx: *anyopaque,
    stream: *anyopaque,
    fn open() !?Gpu {
        const base = std.posix.getenv("STWO_RV64_M8_GPU_BASE") orelse return null;
        const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return null;
        var libs = try O.Libraries.open(base, addon);
        errdefer libs.close();
        var ctx: ?*anyopaque = null;
        try O.check(libs.ops.wait.context_create(&.{ .device_ordinal = 0 }, &ctx));
        var stream: ?*anyopaque = null;
        try O.check(libs.ops.wait.lane_stream(ctx.?, 0, &stream));
        return .{ .libs = libs, .peer = try O.Peer.open(&libs.addon), .seed = try S.Symbols.load(&libs.addon), .ctx = ctx.?, .stream = stream.? };
    }
    fn close(self: *Gpu) void {
        _ = self.libs.ops.wait.context_destroy(self.ctx);
        self.libs.close();
    }
    fn alloc(self: *Gpu, words: usize) ![*]u32 {
        var p: ?[*]u32 = null;
        try O.check(self.libs.ops.exec.alloc_u32(self.ctx, @max(words, 1), &p));
        return p.?;
    }
    fn free(self: *Gpu, p: [*]u32) void {
        _ = self.libs.ops.exec.free_u32(self.ctx, p);
    }
    fn up(self: *Gpu, dst: [*]u32, src: []const u32) !void {
        try O.check(self.libs.ops.exec.copy_async(dst, src.ptr, src.len * 4, @intFromEnum(O.CopyKind.h2d), self.stream));
    }
    fn down(self: *Gpu, dst: []u32, src: [*]const u32) !void {
        try O.check(self.libs.ops.exec.copy_async(dst.ptr, src, dst.len * 4, @intFromEnum(O.CopyKind.d2h), self.stream));
    }
    fn event(self: *Gpu) !*anyopaque {
        var e: ?*anyopaque = null;
        try O.check(self.peer.event_create_timed(&e));
        return e.?;
    }
    fn mark(self: *Gpu, e: *anyopaque) !void {
        try O.check(self.libs.ops.exec.event_record(e, self.stream));
    }
    fn sync(self: *Gpu, e: *anyopaque) !void {
        try O.check(self.libs.ops.wait.event_sync(e));
    }
};

/// Result of one device seed fill.
const DeviceRun = struct { seed_status: u32, bind_status: u32, gpu_us: u64, host_enqueue_ns: u64, launches: u32 };

fn runDevice(gpu: *Gpu, a: std.mem.Allocator, prog: S.Program, regions: []const []const u32, seeds_out: []u32, outputs_out: ?[]u32, checkpoint_out: ?*[9]u32) !DeviceRun {
    const d_prog = try gpu.alloc(prog.words.len);
    defer gpu.free(d_prog);
    try gpu.up(d_prog, prog.words);
    var d_children: [S.max_children]?[*]u32 = @splat(null);
    defer for (d_children) |c| if (c) |p| gpu.free(p);
    for (regions, 0..) |r, k| {
        d_children[k] = try gpu.alloc(r.len);
        try gpu.up(d_children[k].?, r);
    }
    const n_seeds = prog.header(S.P.n_seeds);
    const d_seeds = try gpu.alloc(5 * @as(usize, n_seeds));
    defer gpu.free(d_seeds);
    const scratch_words = @as(usize, prog.header(S.P.scratch_words)) + 8;
    const d_scratch = try gpu.alloc(scratch_words);
    defer gpu.free(d_scratch);
    const d_status = try gpu.alloc(64);
    defer gpu.free(d_status);
    const n_out: usize = if (outputs_out) |o| o.len else 0;
    const d_out = try gpu.alloc(@max(n_out, 4));
    defer gpu.free(d_out);
    const e0 = try gpu.event();
    const e1 = try gpu.event();
    try gpu.mark(e0);
    var timer = try std.time.Timer.start();
    var io = S.Io{
        .program = d_prog,
        .program_words = prog.words.len,
        .children = undefined,
        .children_words = @splat(0),
        .seeds = d_seeds,
        .seeds_words = 5 * @as(u64, n_seeds),
        .scratch = d_scratch,
        .scratch_words = scratch_words,
        .seed_status = &d_status[0],
        .n_children = @intCast(regions.len),
        .n_ops = prog.header(S.P.n_ops),
        .n_caps = prog.header(S.P.n_caps),
    };
    for (&io.children, 0..) |*c, k| c.* = d_children[k];
    for (regions, 0..) |r, k| io.children_words[k] = r.len;
    if (outputs_out != null) {
        io.bind_status = &d_status[1];
        io.outputs = d_out;
        io.outputs_words = @intCast(n_out);
        io.checkpoint = d_status + 16;
    }
    try O.check(gpu.seed.fill(gpu.ctx, 0, &io));
    const host_ns = timer.read();
    try gpu.mark(e1);
    try gpu.down(seeds_out, d_seeds);
    var status: [32]u32 = undefined;
    try gpu.down(&status, d_status);
    if (outputs_out) |o| try gpu.down(o, d_out);
    const e2 = try gpu.event();
    try gpu.mark(e2);
    try gpu.sync(e2);
    var us: u64 = 0;
    try O.check(gpu.peer.event_elapsed_us(e0, e1, &us));
    if (checkpoint_out) |c| @memcpy(c, status[16..25]);
    _ = a;
    return .{ .seed_status = status[0], .bind_status = if (outputs_out != null) status[1] else 0, .gpu_us = us, .host_enqueue_ns = host_ns, .launches = @as(u32, 3) + @intFromBool(prog.header(S.P.n_caps) != 0) };
}

fn firstDiff(x: []const u32, y: []const u32) ?usize {
    for (x, y, 0..) |p, q, i| if (p != q) return i;
    return if (x.len == y.len) null else @min(x.len, y.len);
}

test "gn-node harness: device seed fill, statement and checkpoint on recorded real nodes" {
    const path = std.posix.getenv("STWO_RV64_M8_GN_NODE_RECORDS") orelse return error.SkipZigTest;
    const a = std.heap.c_allocator;
    var l = try load(a, path, std.posix.getenv("STWO_RV64_M8_GN_NODE_TREE"));
    defer l.deinit();
    var gpu_opt = try Gpu.open();
    defer if (gpu_opt) |*g| g.close();
    const cap_log: u32 = 3;
    const wire_words = wireWords(&l);
    var folds: u32 = 0;
    var folds_ok: u32 = 0;
    var leaves: u32 = 0;
    var leaves_ok: u32 = 0;
    var failures: u32 = 0;
    var ords: std.ArrayListUnmanaged(u32) = .empty;
    defer ords.deinit(a);
    var kit = l.nodes.keyIterator();
    while (kit.next()) |k| try ords.append(a, k.*);
    std.mem.sort(u32, ords.items, {}, std.sort.asc(u32));
    for (ords.items) |ord| {
        const r = l.nodes.getPtr(ord).?;
        const seeds = r.seeds;
        const n = seeds.len / 5;
        const vars = try a.alloc(u32, n);
        defer a.free(vars);
        for (vars, 0..) |*v, i| v.* = seeds[5 * i];
        if (!r.is_leaf) {
            folds += 1;
            const kids = l.children.get(ord) orelse {
                std.debug.print("GN_NODE_HARNESS ordinal={d} kind=fold error=NoTree\n", .{ord});
                failures += 1;
                continue;
            };
            var classes: [S.max_children]S.ChildClass = undefined;
            var regions: [S.max_children][]u32 = undefined;
            var made: usize = 0;
            defer for (regions[0..made]) |x| a.free(x);
            var missing = false;
            for (kids, 0..) |kid, i| {
                const c = l.nodes.getPtr(kid) orelse {
                    missing = true;
                    break;
                };
                classes[i] = .{ .shape = c.shape, .wire_words = wire_words, .n_outputs = @intCast(c.expected.len / 4), .identity = c.identity, .fixed_root = c.fixed_root };
                regions[i] = try c.region(a, wire_words);
                made += 1;
            }
            if (missing) {
                std.debug.print("GN_NODE_HARNESS ordinal={d} kind=fold error=ChildNotRecorded\n", .{ord});
                failures += 1;
                continue;
            }
            const tape = try S.tapeLength(classes[0..kids.len], cap_log, a);
            if (tape > n) {
                std.debug.print("GN_NODE_HARNESS ordinal={d} kind=fold error=TapeLongerThanSeeds tape={d} seeds={d}\n", .{ ord, tape, n });
                failures += 1;
                continue;
            }
            const constants = try a.alloc([4]u32, n - tape);
            defer a.free(constants);
            for (constants, 0..) |*c, i| c.* = seeds[5 * i + 1 ..][0..4].*;
            var profile: S.Hash = undefined;
            @memcpy(&profile, regions[0][3..11]);
            const stmt = S.Statement{ .domain = fold_domain, .version_word = versionWord(kids.len), .n_outputs = @intCast(r.expected.len / 4), .prefix = r.prefix[0..8].*, .identity = r.identity, .fixed_root = r.fixed_root, .profile = profile };
            var warm = try std.time.Timer.start();
            const prog = try S.buildFold(a, classes[0..kids.len], cap_log, vars, constants, stmt);
            defer prog.deinit(a);
            const warm_ns = warm.read();
            const out = try a.alloc(u32, seeds.len);
            defer a.free(out);
            const scratch = try a.alloc(u32, prog.header(S.P.scratch_words) + 8);
            defer a.free(scratch);
            var cregions: [S.max_children][]const u32 = undefined;
            for (regions[0..kids.len], 0..) |x, i| cregions[i] = x;
            var host_timer = try std.time.Timer.start();
            const v = S.fillHost(prog, cregions[0..kids.len], scratch, out);
            const mirror_ns = host_timer.read();
            const seeds_eq = v == 0 and std.mem.eql(u32, out, seeds);
            var outputs: [64]u32 = undefined;
            const n_out = r.expected.len;
            var cp: [9]u32 = undefined;
            const bv = S.statementHost(prog, cregions[0..kids.len], outputs[0..n_out], &cp);
            const out_eq = std.mem.eql(u32, outputs[0..n_out], r.expected);
            const cp_eq = std.mem.eql(u32, &cp, &r.checkpoint);
            var dev_line: [256]u8 = undefined;
            var dev_text: []const u8 = "device=skipped";
            var dev_ok = true;
            if (gpu_opt) |*gpu| {
                const dseeds = try a.alloc(u32, seeds.len);
                defer a.free(dseeds);
                var doutputs: [64]u32 = undefined;
                var dcp: [9]u32 = undefined;
                const d = try runDevice(gpu, a, prog, cregions[0..kids.len], dseeds, doutputs[0..n_out], &dcp);
                const d_seeds_eq = d.seed_status == 0 and std.mem.eql(u32, dseeds, seeds);
                const d_out_eq = d.bind_status == 0 and std.mem.eql(u32, doutputs[0..n_out], r.expected);
                const d_cp_eq = std.mem.eql(u32, &dcp, &r.checkpoint);
                dev_ok = d_seeds_eq and d_out_eq and d_cp_eq;
                dev_text = try std.fmt.bufPrint(&dev_line, "device_seed_status=0x{x} device_bind_status=0x{x} device_seeds_identical={} device_outputs_identical={} device_checkpoint_identical={} gpu_us={d} host_enqueue_ns={d} launches={d}", .{ d.seed_status, d.bind_status, d_seeds_eq, d_out_eq, d_cp_eq, d.gpu_us, d.host_enqueue_ns, d.launches });
            }
            const first = firstDiff(out, seeds);
            std.debug.print("GN_NODE_HARNESS ordinal={d} kind=fold children={d} seeds={d} tape={d} constants={d} caps={d} ops={d} program_words={d} warm_ns={d} mirror_ns={d} seed_status=0x{x} seeds_identical={} first_diff={?d} bind_status=0x{x} outputs_identical={} checkpoint_identical={} {s}\n", .{ ord, kids.len, n, tape, n - tape, prog.header(S.P.n_caps), prog.header(S.P.n_ops), prog.words.len, warm_ns, mirror_ns, v, seeds_eq, if (first) |f| f / 5 else null, bv, out_eq, cp_eq, dev_text });
            if (seeds_eq and bv == 0 and out_eq and cp_eq and dev_ok) folds_ok += 1 else failures += 1;
            // Negative arms (first fold only): one corruption per check.
            if (folds == 1 and seeds_eq) try negatives(a, &gpu_opt, prog, cregions[0..kids.len], wire_words, classes[0].shape);
        } else {
            leaves += 1;
            // Find the native child's PCS image: its MAIN root (tree 1) as
            // 16 half-word seeds right after its FIXED root's 16.
            var found = false;
            for (l.pcs.items) |p| {
                const L = S.Layout.of(p.shape) catch continue;
                if (L.n_trees < 2) continue;
                const root1 = p.image[L.roots + 8 ..][0..8];
                var start: ?usize = null;
                var i: usize = 16;
                outer: while (i + 16 <= n) : (i += 1) {
                    for (0..8) |w| {
                        if (seeds[5 * (i + 2 * w) + 1] != (root1[w] & 0xffff) or seeds[5 * (i + 2 * w + 1) + 1] != (root1[w] >> 16)) continue :outer;
                    }
                    start = i - 16;
                    break;
                }
                const s0 = start orelse continue;
                found = true;
                const child = S.ChildClass{ .shape = p.shape, .wire_words = 64, .n_outputs = 0, .identity = @splat(0), .fixed_root = @splat(0) };
                const proof_len = try S.leafTapeLength(a, child, cap_log);
                const tail: u32 = @intCast(n - s0 - proof_len);
                const constants = try a.alloc([4]u32, s0);
                defer a.free(constants);
                for (constants, 0..) |*c, j| c.* = seeds[5 * j + 1 ..][0..4].*;
                const n_out = r.expected.len;
                const outputs_at: u32 = @intCast(64 + p.image.len + 4 * tail);
                const stmt = S.Statement{ .kind = 2, .outputs_at = outputs_at, .domain = 0, .version_word = 0, .n_outputs = @intCast(n_out / 4), .prefix = r.prefix[0..8].*, .identity = r.identity, .fixed_root = r.fixed_root, .profile = @splat(0) };
                const prog = try S.buildLeaf(a, child, cap_log, tail, vars, constants, stmt);
                defer prog.deinit(a);
                // Native child region: [len][wire placeholder][image][tail seeds][outputs]
                // (tail + outputs: the native producer's words; copied here).
                const region = try a.alloc(u32, outputs_at + n_out);
                defer a.free(region);
                @memset(region, 0);
                region[0] = 1;
                @memcpy(region[64..][0..p.image.len], p.image);
                for (0..tail) |j| @memcpy(region[64 + p.image.len + 4 * j ..][0..4], seeds[5 * (s0 + proof_len + j) + 1 ..][0..4]);
                @memcpy(region[outputs_at..][0..n_out], r.expected);
                const out = try a.alloc(u32, seeds.len);
                defer a.free(out);
                const scratch = try a.alloc(u32, prog.header(S.P.scratch_words) + 8);
                defer a.free(scratch);
                const regs = [_][]const u32{region};
                var host_timer = try std.time.Timer.start();
                const v = S.fillHost(prog, &regs, scratch, out);
                const mirror_ns = host_timer.read();
                const eq = v == 0 and std.mem.eql(u32, out, seeds);
                var outputs: [64]u32 = undefined;
                var cp: [9]u32 = undefined;
                const bv = S.statementHost(prog, &regs, outputs[0..n_out], &cp);
                const cp_eq = bv == 0 and std.mem.eql(u32, &cp, &r.checkpoint);
                var dev_line: [256]u8 = undefined;
                var dev_text: []const u8 = "device=skipped";
                var dev_ok = true;
                if (gpu_opt) |*gpu| {
                    const dseeds = try a.alloc(u32, seeds.len);
                    defer a.free(dseeds);
                    var doutputs: [64]u32 = undefined;
                    var dcp: [9]u32 = undefined;
                    const d = try runDevice(gpu, a, prog, &regs, dseeds, doutputs[0..n_out], &dcp);
                    const d_eq = d.seed_status == 0 and std.mem.eql(u32, dseeds, seeds);
                    const d_cp = d.bind_status == 0 and std.mem.eql(u32, &dcp, &r.checkpoint);
                    dev_ok = d_eq and d_cp;
                    dev_text = try std.fmt.bufPrint(&dev_line, "device_seed_status=0x{x} device_seeds_identical={} device_checkpoint_identical={} gpu_us={d} host_enqueue_ns={d} launches={d}", .{ d.seed_status, d_eq, d_cp, d.gpu_us, d.host_enqueue_ns, d.launches });
                }
                const first = firstDiff(out, seeds);
                std.debug.print("GN_NODE_HARNESS ordinal={d} kind=leaf seeds={d} constants={d} proof_seeds={d} tail_seeds={d} caps={d} ops={d} mirror_ns={d} seed_status=0x{x} seeds_identical={} first_diff={?d} checkpoint_identical={} {s}\n", .{ ord, n, s0, proof_len, tail, prog.header(S.P.n_caps), prog.header(S.P.n_ops), mirror_ns, v, eq, if (first) |f| f / 5 else null, cp_eq, dev_text });
                dev_ok = dev_ok and cp_eq;
                if (eq and dev_ok) leaves_ok += 1 else failures += 1;
                break;
            }
            if (!found) {
                std.debug.print("GN_NODE_HARNESS ordinal={d} kind=leaf error=NativeImageNotRecorded seeds={d}\n", .{ ord, n });
                failures += 1;
            }
        }
    }
    std.debug.print("GN_NODE_HARNESS_SUMMARY folds={d} folds_identical={d} leaves={d} leaves_identical={d} failures={d} device={}\n", .{ folds, folds_ok, leaves, leaves_ok, failures, gpu_opt != null });
    try std.testing.expectEqual(@as(u32, 0), failures);
}

/// One corruption per verdict detail; each must be refused by the mirror
/// and (device arm) by the kernel with the same word.
fn negatives(a: std.mem.Allocator, gpu_opt: *?Gpu, prog: S.Program, regions: []const []const u32, wire_words: u32, shape0: S.Shape) !void {
    const L = try S.Layout.of(shape0);
    const Case = struct { name: []const u8, at: usize, value: ?u32, xor: u32, seed: []const S.SeedDetail, bind: ?S.BindDetail };
    const t0 = L.trees[1];
    const cases = [_]Case{
        .{ .name = "path_sibling", .at = wire_words + t0.paths + 3, .value = null, .xor = 1, .seed = &.{ .cap_root, .cap_mismatch }, .bind = null },
        .{ .name = "queried_value", .at = wire_words + t0.values + 5, .value = 0x7fff_ffff, .xor = 0, .seed = &.{.noncanonical}, .bind = null },
        .{ .name = "query_range", .at = wire_words + L.queries, .value = 0xffff_fff0, .xor = 0, .seed = &.{.query_range}, .bind = null },
        .{ .name = "image_header", .at = wire_words, .value = 0, .xor = 0, .seed = &.{.image_header}, .bind = null },
        .{ .name = "empty_region", .at = 0, .value = 0, .xor = 0, .seed = &.{.region}, .bind = null },
        .{ .name = "wire_magic", .at = 1, .value = 0, .xor = 0, .seed = &.{}, .bind = .magic },
        .{ .name = "child_identity", .at = 11, .value = null, .xor = 4, .seed = &.{}, .bind = .identity },
        .{ .name = "child_outputs", .at = 19, .value = null, .xor = 1, .seed = &.{}, .bind = .outputs },
        .{ .name = "child_fixed_root", .at = wire_words + L.roots, .value = null, .xor = 2, .seed = &.{}, .bind = .fixed_root },
    };
    for (cases) |c| {
        const bad = try a.dupe(u32, regions[0]);
        defer a.free(bad);
        if (c.value) |v| bad[c.at] = v else bad[c.at] ^= c.xor;
        var regs: [S.max_children][]const u32 = undefined;
        @memcpy(regs[0..regions.len], regions);
        regs[0] = bad;
        const out = try a.alloc(u32, 5 * @as(usize, prog.header(S.P.n_seeds)));
        defer a.free(out);
        const scratch = try a.alloc(u32, prog.header(S.P.scratch_words) + 8);
        defer a.free(scratch);
        const v = S.fillHost(prog, regs[0..regions.len], scratch, out);
        var outputs: [64]u32 = undefined;
        var cp: [9]u32 = undefined;
        const n_out = 4 * @as(usize, prog.header(S.P.n_outputs));
        const bv = S.statementHost(prog, regs[0..regions.len], outputs[0..n_out], &cp);
        var dv: u32 = 0;
        var dbv: u32 = 0;
        if (gpu_opt.*) |*gpu| {
            var doutputs: [64]u32 = undefined;
            var dcp: [9]u32 = undefined;
            const d = try runDevice(gpu, a, prog, regs[0..regions.len], out, doutputs[0..n_out], &dcp);
            dv = d.seed_status;
            dbv = d.bind_status;
        }
        var seed_ok = c.seed.len == 0;
        var dev_seed_ok = c.seed.len == 0;
        for (c.seed) |d| {
            const want = (@as(u32, 0x0305) << 16) | @intFromEnum(d);
            seed_ok = seed_ok or v == want;
            dev_seed_ok = dev_seed_ok or dv == want;
        }
        // A bind case keeps the seeds valid (the tape copies the bad value):
        // only child_binding may refuse it.
        if (c.seed.len == 0 and c.bind != null and c.at != wire_words + L.roots) {
            seed_ok = seed_ok and v == 0;
            dev_seed_ok = dev_seed_ok and dv == 0;
        }
        const want_bind: u32 = if (c.bind) |d| (@as(u32, 0x0306) << 16) | @intFromEnum(d) else 0;
        const bind_ok = c.bind == null or bv == want_bind;
        const dev_ok = gpu_opt.* == null or (dev_seed_ok and (c.bind == null or dbv == want_bind));
        std.debug.print("GN_NODE_NEGATIVE case={s} seed_status=0x{x} bind_status=0x{x} device_seed_status=0x{x} device_bind_status=0x{x} expected_bind=0x{x} fail_closed={}\n", .{ c.name, v, bv, dv, dbv, want_bind, seed_ok and bind_ok and dev_ok });
        try std.testing.expect(seed_ok and bind_ok and dev_ok);
    }
}

test "gn-node: outer_device restates the outer kernels / checks constants exactly" {
    const D = @import("outer_device.zig");
    try std.testing.expectEqual(@import("outer_checks.zig").field_index, D.lookup_field_index);
    try std.testing.expect(D.Copy == @import("outer_kernels.zig").Copy);
}
