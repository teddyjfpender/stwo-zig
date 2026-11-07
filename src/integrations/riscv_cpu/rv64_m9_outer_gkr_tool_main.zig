//! rv64-m9-outer-gkr-tool: CPU-only prototype/cost oracle for the M9 outer GKR in recursion nodes.
//! Refuses to run unless STWO_RV64_M9_OUTER_GKR=1 (default off; nothing else reads the flag).
//!
//!   cost-raw <name> <eq> <qm31_ops> <triple_xor> <m31_to_u32> <blake_g_gate> [v1|v2]
//!       in-circuit verifier gate counts of ONE child section of the node class with these raw rows
//!       (shape-only, counted from the circuit code; JSON line)
//!   node <shift> <seed>     end-to-end CPU node round on the real D2 CPU leaf roster, row logs - shift
//!   m5-crosscheck           shape-only cost of the M5 constant classes (compare with the M5 [M] receipt)
const std = @import("std");
const P = @import("outer_gkr/profile.zig");
const S = @import("outer_gkr/section.zig");
const N = @import("outer_gkr/m9_node.zig");

fn emit(a: std.mem.Allocator, value: anytype) !void {
    const s = try std.fmt.allocPrint(a, "{f}\n", .{std.json.fmt(value, .{})});
    defer a.free(s);
    try std.fs.File.stdout().writeAll(s);
}

fn costLine(a: std.mem.Allocator, name: []const u8, class: *const P.Class, raw: ?[5]u64) !void {
    var timer = try std.time.Timer.start();
    const cost = try N.verifierCost(a, class);
    var logs: [P.N_COMPONENTS]u32 = undefined;
    for (&logs, class.row_logs) |*o, r| o.* = r;
    try emit(a, .{
        .name = name,
        .class_id = class.id,
        .binding_version = class.version(),
        .raw = raw,
        .row_logs = logs,
        .layers = class.layers(),
        .rounds = class.rounds(),
        .instances = class.instances.len,
        .facts = N.facts(class),
        .section_bytes = S.sectionBytes(class),
        .blake_g_gate = cost.blake_g_gate,
        .qm31_ops = cost.qm31_ops,
        .m31_to_u32 = cost.m31_to_u32,
        .triple_xor = cost.triple_xor,
        .eq = cost.eq,
        .draws = cost.draws,
        .variables = cost.variables,
        .measure_ns = timer.read(),
    });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const sel = N.selection() catch {
        try std.fs.File.stderr().writeAll("error: " ++ N.FLAG ++ " must be unset, 0 or 1\n");
        std.process.exit(1);
    };
    if (sel != .on) {
        try std.fs.File.stderr().writeAll("refused: " ++ N.FLAG ++ " is off (default); set it to 1 for this CPU prototype\n");
        std.process.exit(3);
    }
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 2) return error.Usage;
    if (std.mem.eql(u8, args[1], "cost-raw")) {
        if (args.len < 8) return error.Usage;
        var raw: [5]u64 = undefined;
        for (&raw, args[3..8]) |*r, s| r.* = try std.fmt.parseInt(u64, s, 10);
        const version: P.BindingVersion = if (args.len > 8 and std.mem.eql(u8, args[8], "v1")) .legacy_v1 else .cyclic_eq_v2;
        var owned = try N.classFor(a, args[2], N.rowLogs(raw), version);
        defer owned.deinit(a);
        try costLine(a, args[2], &owned.class, raw);
    } else if (std.mem.eql(u8, args[1], "node")) {
        if (args.len < 4) return error.Usage;
        const shift = try std.fmt.parseInt(u8, args[2], 10);
        const seed = try std.fmt.parseInt(u64, args[3], 10);
        var owned = try N.classFor(a, "leaf-cpu-d2-scaled", N.scaled(N.rowLogs(N.LEAF_CPU_D2_RAW), shift), .cyclic_eq_v2);
        defer owned.deinit(a);
        const r = try N.runNode(a, &owned.class, seed);
        var logs: [P.N_COMPONENTS]u32 = undefined;
        for (&logs, owned.class.row_logs) |*o, x| o.* = x;
        try emit(a, .{ .shift = shift, .row_logs = logs, .report = r });
    } else if (std.mem.eql(u8, args[1], "m5-crosscheck")) {
        try costLine(a, P.LEAF_CPU_24628607.name, &P.LEAF_CPU_24628607, null);
        try costLine(a, P.FOLD_24628607.name, &P.FOLD_24628607, null);
    } else return error.Usage;
}
