//! rowpar planner tool (M9 prep, standalone; zig build-exe plan_main.zig):
//!   plan_main <node.m9rp> <out.m9rw> [blake=0|1] [strands=0|1] [max_strand=N] [check=0|1]
//! Reads a recorded node (rv64_m9_witness_rowpar_dump_test_root.zig format),
//! builds the rowpar plan, optionally proves on the CPU that both the DAG
//! record order and the rowpar order reproduce the recorded reference values
//! byte for byte, prints one JSON stats line and writes the GPU plan:
//!   header[8] = { 0x5752394d "M9RW", 1, n_levels, n_strands, n_units, n_blake, n_tasks, 0 }
//!   level_ends[n_levels], strand_ends[n_strands], units[n_units], blake[n_blake * 48]
const std = @import("std");
const Plan = @import("plan.zig");

const Node = struct {
    n_vars: u32,
    tasks: []Plan.Task,
    indices: []u32,
    ends: []u32,
    seeds: [][5]u32,
    reference: [][4]u32,
};

fn readNode(a: std.mem.Allocator, path: []const u8) !Node {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const size = (try file.stat()).size;
    if (size % 4 != 0) return error.BadNodeLength;
    const words = try a.alloc(u32, size / 4);
    if (try file.readAll(std.mem.sliceAsBytes(words)) != size) return error.BadNodeLength;
    if (words.len < 8 or words[0] != 0x5052394d or words[1] != 1) return error.BadNode;
    const n_vars = words[2];
    const n_tasks = words[3];
    const n_indices = words[4];
    const n_levels = words[5];
    const n_seeds = words[6];
    var o: usize = 8;
    const ends = words[o..][0..n_levels];
    o += n_levels;
    const tasks = std.mem.bytesAsSlice(Plan.Task, std.mem.sliceAsBytes(words[o..][0 .. n_tasks * 8]));
    o += n_tasks * 8;
    const indices = words[o..][0..n_indices];
    o += n_indices;
    const seeds = std.mem.bytesAsSlice([5]u32, std.mem.sliceAsBytes(words[o..][0 .. n_seeds * 5]));
    o += n_seeds * 5;
    const reference = std.mem.bytesAsSlice([4]u32, std.mem.sliceAsBytes(words[o..][0 .. @as(usize, n_vars) * 4]));
    o += @as(usize, n_vars) * 4;
    if (o != words.len) return error.BadNodeLength;
    return .{ .n_vars = n_vars, .tasks = @alignCast(tasks), .indices = indices, .ends = ends, .seeds = @alignCast(seeds), .reference = @alignCast(reference) };
}

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    if (args.len < 3) {
        std.debug.print("usage: plan_main <node.m9rp> <out.m9rw> [blake=0|1] [strands=0|1] [max_strand=N] [check=0|1]\n", .{});
        std.process.exit(2);
    }
    var options = Plan.Options{};
    var check = true;
    for (args[3..]) |arg| {
        if (std.mem.startsWith(u8, arg, "blake=")) options.blake = arg[6] == '1';
        if (std.mem.startsWith(u8, arg, "strands=")) options.strands = arg[8] == '1';
        if (std.mem.startsWith(u8, arg, "max_strand=")) options.max_strand_records = try std.fmt.parseInt(u32, arg[11..], 10);
        if (std.mem.startsWith(u8, arg, "check=")) check = arg[6] == '1';
        if (std.mem.startsWith(u8, arg, "blake_cost=")) options.blake_cost = try std.fmt.parseInt(u32, arg[11..], 10);
    }
    const node = try readNode(a, args[1]);
    var timer = try std.time.Timer.start();
    var plan = try Plan.build(a, node.tasks, node.indices, node.n_vars, node.ends, options);
    defer plan.deinit();
    const plan_ns = timer.lap();
    var dag_ok = true;
    var rowpar_ok = true;
    if (check) {
        const x = try a.alloc([4]u32, node.n_vars);
        defer a.free(x);
        const init = try a.alloc([4]u32, node.n_vars);
        defer a.free(init);
        @memset(init, .{ 0, 0, 0, 0 });
        for (node.seeds) |s| init[s[0]] = s[1..5].*;
        var status: u32 = 0;
        @memcpy(x, init);
        Plan.executeDag(node.tasks, node.indices, x, &status);
        dag_ok = status == 0 and std.mem.eql(u8, std.mem.sliceAsBytes(x), std.mem.sliceAsBytes(node.reference));
        @memcpy(x, init);
        status = 0;
        Plan.execute(&plan, node.tasks, node.indices, x, &status);
        rowpar_ok = status == 0 and std.mem.eql(u8, std.mem.sliceAsBytes(x), std.mem.sliceAsBytes(node.reference));
    }
    var file = try std.fs.cwd().createFile(args[2], .{});
    defer file.close();
    var buffer: [1 << 16]u8 = undefined;
    var w = file.writer(&buffer);
    const io = &w.interface;
    const header = [8]u32{ 0x5752394d, 1, @intCast(plan.level_ends.len), @intCast(plan.strand_ends.len), @intCast(plan.units.len), @intCast(plan.blake.len), @intCast(node.tasks.len), 0 };
    try io.writeAll(std.mem.sliceAsBytes(&header));
    try io.writeAll(std.mem.sliceAsBytes(plan.level_ends));
    try io.writeAll(std.mem.sliceAsBytes(plan.strand_ends));
    try io.writeAll(std.mem.sliceAsBytes(plan.units));
    try io.writeAll(std.mem.sliceAsBytes(plan.blake));
    try io.flush();
    var kinds = [_]u64{0} ** 16;
    for (node.tasks) |t| kinds[t.kind] += 1;
    const s = plan.stats;
    var out_buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writerStreaming(&out_buf);
    try stdout.interface.print("{{\"node\":\"{s}\",\"vars\":{},\"tasks\":{},\"dag_levels\":{},\"blake\":{},\"strands_on\":{},\"max_strand\":{},\"blake_units\":{},\"blake_inline\":{},\"blake_tasks\":{},\"plain_units\":{},\"strands\":{},\"levels\":{},\"critical_records\":{},\"critical_blake\":{},\"max_level_width\":{},\"max_strand_records\":{},\"plan_ms\":{d:.1},\"cpu_dag_eq_reference\":{},\"cpu_rowpar_eq_reference\":{},\"kinds\":[{f}]}}\n", .{ std.fs.path.basename(args[1]), node.n_vars, node.tasks.len, s.dag_levels, options.blake, options.strands, options.max_strand_records, s.blake_units, s.blake_inline, s.blake_tasks, s.plain_units, s.strands, s.levels, s.critical_records, s.critical_blake, s.max_level_width, s.max_strand_records, @as(f64, @floatFromInt(plan_ns)) / 1e6, dag_ok, rowpar_ok, KindList{ .k = kinds } });
    try stdout.interface.flush();
    if (check and !(dag_ok and rowpar_ok)) std.process.exit(1);
}
const KindList = struct {
    k: [16]u64,
    pub fn format(self: KindList, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.k, 0..) |x, i| try w.print("{s}{}", .{ if (i == 0) "" else ",", x });
    }
};
