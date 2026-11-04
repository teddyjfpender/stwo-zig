//! rv64-outer-gkr-tool: producer, FRESH-PROCESS receiver and cost oracle for the outer LogUp-GKR
//! section (profile outer_gkr_om31_strict_v1). Every `verify` is a new process with no cache.
//!
//!   info <class>                                       class facts (JSON)
//!   seed <class> <salt>                                 9-word CUDA traversal seed after header+salt
//!   prove-cpu <class> <inputs-seed> <balanced:0|1> <out.bin>
//!   verify <section.bin> [--inputs-seed N] [--balanced] [--no-closure] [--no-terminal]
//!   cost <section.bin> [--inputs-seed N] [--balanced]  in-circuit gadget gate counts (JSON)
//! Exit 0 = accepted, 2 = rejected (with the error name on stdout), 1 = usage/IO.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("outer_gkr/profile.zig");
const S = @import("outer_gkr/section.zig");
const CG = @import("outer_gkr/circuit.zig");
const O = core.fields.om31.OM31;
const M31 = core.fields.m31.M31;

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    std.fs.File.stdout().writeAll(s) catch {};
}
fn readWords(a: std.mem.Allocator, path: []const u8) ![]u32 {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
    defer a.free(bytes);
    if (bytes.len % 4 != 0) return error.MalformedOuterGkrSection;
    const words = try a.alloc(u32, bytes.len / 4);
    for (words, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}
fn writeWords(path: []const u8, words: []const u32) !void {
    const f = try std.fs.cwd().createFile(path, .{});
    defer f.close();
    var buf: [4096]u8 = undefined;
    var at: usize = 0;
    for (words) |w| {
        std.mem.writeInt(u32, buf[at..][0..4], w, .little);
        at += 4;
        if (at == buf.len) {
            try f.writeAll(&buf);
            at = 0;
        }
    }
    try f.writeAll(buf[0..at]);
}

const Options = struct { inputs_seed: ?u64 = null, balanced: bool = false, closure: bool = true, terminal: bool = true };
fn options(args: []const []const u8) !Options {
    var o = Options{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--inputs-seed")) {
            i += 1;
            if (i == args.len) return error.Usage;
            o.inputs_seed = try std.fmt.parseInt(u64, args[i], 0);
        } else if (std.mem.eql(u8, args[i], "--balanced")) {
            o.balanced = true;
        } else if (std.mem.eql(u8, args[i], "--no-closure")) {
            o.closure = false;
        } else if (std.mem.eql(u8, args[i], "--no-terminal")) {
            o.terminal = false;
        } else return error.Usage;
    }
    return o;
}

fn classInfo(c: *const P.Class) void {
    var classic: u64 = 0;
    var binding: u64 = 0;
    var main_cells: u64 = 0;
    for (0..P.N_COMPONENTS) |k| {
        const comp: P.Component = @enumFromInt(k);
        const rows = @as(u64, 1) << @intCast(c.row_logs[k]);
        main_cells += P.FACTS[k].main * rows;
        classic += P.classicInteractionBaseColumns(comp) * rows;
        binding += (if (P.gkrBound(comp)) P.BINDING_BASE_COLUMNS else P.classicInteractionBaseColumns(comp)) * rows;
    }
    out("{{\"class\":\"{s}\",\"id\":{},\"instances\":{},\"layers\":{},\"rounds\":{},\"instance_layers\":{},\"fractions\":{},\"section_bytes\":{},\"main_cells\":{},\"classic_interaction_cells\":{},\"hybrid_interaction_cells\":{},\"conservative_mass\":{}}}\n", .{ c.name, c.id, c.instances.len, c.layers(), c.rounds(), c.instanceLayers(), c.fractions(), S.sectionBytes(c), main_cells, classic, binding, c.conservativeMass() });
}

fn receive(a: std.mem.Allocator, words: []const u32, o: Options) !void {
    var section = try S.decode(a, words);
    defer section.deinit(a);
    var channel = S.benchChannel();
    var timer = try std.time.Timer.start();
    var verified = try S.verify(a, &channel, &section);
    defer verified.deinit(a);
    const verify_ns = timer.read();
    if (o.closure) try S.requireClosure(&verified, O.zero());
    var terminal_ns: u64 = 0;
    if (o.terminal) {
        const seed = o.inputs_seed orelse return error.Usage;
        timer.reset();
        var inputs = try S.synthetic(a, section.class, seed, o.balanced);
        defer inputs.deinit(a);
        const expected = try S.terminalExpected(a, &inputs, &verified);
        defer a.free(expected);
        try S.requireTerminal(&verified, expected);
        terminal_ns = timer.read();
    }
    out("{{\"accepted\":true,\"class\":\"{s}\",\"profile\":\"{s}\",\"draws\":{},\"closure_checked\":{},\"terminal_checked\":{},\"verify_ns\":{},\"terminal_ns\":{},\"section_bytes\":{}}}\n", .{ section.class.name, P.PROFILE_NAME, verified.draws, o.closure, o.terminal, verify_ns, terminal_ns, words.len * 4 });
}

pub fn main() !u8 {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = if (@import("builtin").mode == .Debug) gpa.allocator() else std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 3) {
        out("usage: see source header\n", .{});
        return 1;
    }
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "info")) {
        classInfo(try P.classByName(args[2]));
        return 0;
    }
    if (std.mem.eql(u8, cmd, "seed")) {
        if (args.len != 4) return 1;
        const class = try P.classByName(args[2]);
        const start = S.benchChannel();
        const seed = try S.deviceSeed(&start, class, O.fromBase(M31.fromCanonical(try std.fmt.parseInt(u32, args[3], 0))));
        for (seed) |w| out("{} ", .{w});
        out("\n", .{});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "prove-cpu")) {
        if (args.len != 6) return 1;
        const class = try P.classByName(args[2]);
        var inputs = try S.synthetic(a, class, try std.fmt.parseInt(u64, args[3], 0), std.mem.eql(u8, args[4], "1"));
        defer inputs.deinit(a);
        const start = S.benchChannel();
        var timer = try std.time.Timer.start();
        var section = try S.proveCpu(a, &start, class, &inputs);
        defer section.deinit(a);
        const prove_ns = timer.read();
        const words = try S.encode(a, &section);
        defer a.free(words);
        try writeWords(args[5], words);
        out("{{\"class\":\"{s}\",\"cpu_prove_ns\":{},\"section_bytes\":{},\"salt\":{}}}\n", .{ class.name, prove_ns, words.len * 4, section.salt.toM31Array()[0].v });
        return 0;
    }
    if (std.mem.eql(u8, cmd, "verify")) {
        const o = options(args[3..]) catch return 1;
        const words = readWords(a, args[2]) catch |err| {
            out("{{\"accepted\":false,\"error\":\"{s}\"}}\n", .{@errorName(err)});
            return 2;
        };
        defer a.free(words);
        receive(a, words, o) catch |err| {
            out("{{\"accepted\":false,\"error\":\"{s}\"}}\n", .{@errorName(err)});
            return 2;
        };
        return 0;
    }
    if (std.mem.eql(u8, cmd, "cost")) {
        const o = options(args[3..]) catch return 1;
        const words = try readWords(a, args[2]);
        defer a.free(words);
        var section = try S.decode(a, words);
        defer section.deinit(a);
        var channel = S.benchChannel();
        var verified = try S.verify(a, &channel, &section);
        defer verified.deinit(a);
        var terminal: ?[][2]O = null;
        var inputs: ?S.Inputs = null;
        defer if (inputs) |*i| i.deinit(a);
        defer if (terminal) |t| a.free(t);
        if (o.inputs_seed) |seed| {
            inputs = try S.synthetic(a, section.class, seed, o.balanced);
            terminal = try S.terminalExpected(a, &inputs.?, &verified);
        }
        var timer = try std.time.Timer.start();
        const cost = try CG.measure(a, &section, verified.root_sum.neg(), terminal);
        const ns = timer.read();
        out("{{\"class\":\"{s}\",\"layers\":{},\"instances\":{},\"rounds\":{},\"draws\":{},\"blake_g_gate\":{},\"qm31_ops\":{},\"m31_to_u32\":{},\"triple_xor\":{},\"eq\":{},\"variables\":{},\"valid\":{},\"terminal_from_inputs\":{},\"build_ns\":{}}}\n", .{ section.class.name, section.class.layers(), section.class.instances.len, section.class.rounds(), cost.draws, cost.blake_g_gate, cost.qm31_ops, cost.m31_to_u32, cost.triple_xor, cost.eq, cost.variables, cost.valid, terminal != null, ns });
        return if (cost.valid) 0 else 2;
    }
    return 1;
}
