//! rv64-native-gkr-tool (stream native-gkr): native LogUp-GKR v1 sections outside the production path.
//!   shape  <census-declared.json>                 exact v1 roster per native proof: instances, layers, facts,
//!                                                 binding pairs, INTER cells, section bytes (JSON on stdout)
//!   prove  <census-declared.json> <proof> <out>   synthetic fractions on that proof's REAL v1 roster, CPU
//!                                                 reference prove; writes the encoded section (u32 LE words)
//!   verify <census-declared.json> <proof> <in>    FRESH-process receiver: decode against the roster derived
//!                                                 here, verify (strict draws, shape, local closure), exposed
//!                                                 global claims == recomputed, binding of every component;
//!                                                 prints {"accepted":..} and exits 1 on reject (never panics)
//! <proof> is "cpu-<i>" or "truth-<i>". Fractions are deterministic (seed 0x5eed), so prover and receiver
//! derive the same MAIN-side view independently (in production that view is the OODS-authenticated MAIN).
const std = @import("std");
const R = @import("roster.zig");
const S = @import("section.zig");

const Slot = struct { name: []const u8, log: u32, local_terms: u32, ram_queries: u32 = 0, other_queries: u32 = 0, other_relation: []const u8 };
const Part = struct { kind: []const u8, log: u32, local_queries: u32 = 0, global_queries: u32 = 0, global_relation: []const u8 };
const Census = struct { cpus: []struct { slots: []Slot }, truths: []struct { family: []const u8, parts: []Part } };

fn kindIndex(relation: []const u8) usize {
    if (std.mem.eql(u8, relation, "kio")) return @intFromEnum(R.Kind.kio);
    if (std.mem.eql(u8, relation, "wire")) return @intFromEnum(R.Kind.wire);
    return @intFromEnum(R.Kind.ram);
}
fn specsFor(a: std.mem.Allocator, census: Census, which: []const u8) ![]R.ComponentSpec {
    var list = std.ArrayList(R.ComponentSpec).empty;
    if (std.mem.startsWith(u8, which, "cpu-")) {
        const i = try std.fmt.parseInt(usize, which[4..], 10);
        if (i >= census.cpus.len) return error.UnknownProof;
        for (census.cpus[i].slots, 0..) |s, k| {
            var terms: [R.KINDS]u32 = @splat(0);
            terms[0] = s.local_terms;
            terms[@intFromEnum(R.Kind.ram)] = s.ram_queries;
            if (s.other_queries != 0) terms[kindIndex(s.other_relation)] = s.other_queries;
            try list.append(a, .{ .origin = .{ 0x100, @intCast(k) }, .row_log = s.log, .terms = terms });
        }
    } else if (std.mem.startsWith(u8, which, "truth-")) {
        const i = try std.fmt.parseInt(usize, which[6..], 10);
        if (i >= census.truths.len) return error.UnknownProof;
        for (census.truths[i].parts, 0..) |p, k| {
            var terms: [R.KINDS]u32 = @splat(0);
            terms[0] = p.local_queries;
            if (p.global_queries != 0) terms[kindIndex(p.global_relation)] = p.global_queries;
            try list.append(a, .{ .origin = .{ 0x200, @intCast(k) }, .row_log = p.log, .terms = terms });
        }
    } else return error.UnknownProof;
    return list.toOwnedSlice(a);
}
fn channel() S.RawChannel {
    var c = S.RawChannel.init();
    c.mixU32s(&.{ 0x4e47_4b52, 0x544f4f4c });
    return c;
}
fn scope(which: []const u8) S.Scope {
    var s = S.Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .shared = @splat(4), .ordinal = 0 };
    std.crypto.hash.sha2.Sha256.hash(which, &s.main, .{});
    return s;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const gpa = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    const out = std.fs.File.stdout();
    if (args.len < 3) return error.Usage;
    const census = try std.json.parseFromSliceLeaky(Census, a, try std.fs.cwd().readFileAlloc(a, args[2], 64 << 20), .{ .ignore_unknown_fields = true });
    if (std.mem.eql(u8, args[1], "shape")) {
        const Row = struct { proof: []const u8, instances: usize, layers: u32, gkr_facts: u64, binding_pairs: usize, v1_inter_cells: u64, section_bytes: usize };
        var rows = std.ArrayList(Row).empty;
        for (0..census.cpus.len + census.truths.len) |i| {
            const name = if (i < census.cpus.len) try std.fmt.allocPrint(a, "cpu-{d}", .{i}) else try std.fmt.allocPrint(a, "truth-{d}", .{i - census.cpus.len});
            var roster = try R.derive(a, try specsFor(a, census, name));
            try rows.append(a, .{ .proof = name, .instances = roster.instances.len, .layers = roster.layers(), .gkr_facts = roster.gkrFacts(), .binding_pairs = roster.bindingPairs(), .v1_inter_cells = roster.interCells(), .section_bytes = 4 * S.wordCount(&roster) });
        }
        try out.writeAll(try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-native-gkr-shape/v1", .label = "D (exact from the v1 roster)", .proofs = rows.items }, .{ .whitespace = .indent_1 }));
        try out.writeAll("\n");
        return;
    }
    if (args.len != 5) return error.Usage;
    const which = args[3];
    var roster = try R.derive(gpa, try specsFor(a, census, which));
    defer roster.deinit();
    var timer = try std.time.Timer.start();
    var inputs = try S.syntheticInputs(gpa, &roster, 0x5eed);
    defer inputs.deinit(gpa);
    const inputs_ns = timer.lap();
    const sc = scope(which);
    if (std.mem.eql(u8, args[1], "prove")) {
        const ch = channel();
        var section = try S.proveCpu(gpa, &ch, &roster, &sc, &inputs);
        defer section.deinit(gpa);
        const prove_ns = timer.lap();
        const words = try S.encode(gpa, &roster, &section);
        defer gpa.free(words);
        try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = std.mem.sliceAsBytes(words) });
        try out.writeAll(try std.fmt.allocPrint(a, "{{\"proof\":\"{s}\",\"instances\":{d},\"layers\":{d},\"gkr_facts\":{d},\"section_bytes\":{d},\"inputs_ns\":{d},\"cpu_prove_ns\":{d},\"salt\":{d}}}\n", .{ which, roster.instances.len, roster.layers(), roster.gkrFacts(), 4 * words.len, inputs_ns, prove_ns, section.salt.toM31Array()[0].v }));
        return;
    }
    if (!std.mem.eql(u8, args[1], "verify")) return error.Usage;
    const bytes = try std.fs.cwd().readFileAlloc(a, args[4], 1 << 30);
    var accepted = false;
    var reason: []const u8 = "ok";
    blk: {
        if (bytes.len % 4 != 0) {
            reason = "MalformedNativeGkrSection";
            break :blk;
        }
        const words = try a.alloc(u32, bytes.len / 4);
        for (words, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        var section = S.decode(gpa, &roster, words) catch |e| {
            reason = @errorName(e);
            break :blk;
        };
        defer section.deinit(gpa);
        var ch = channel();
        var v = S.verify(gpa, &ch, &roster, &sc, &section) catch |e| {
            reason = @errorName(e);
            break :blk;
        };
        defer v.deinit(gpa);
        const closing = try S.globalSums(&roster, &inputs);
        if (!v.global.ram.eql(closing.ram) or !v.global.kio.eql(closing.kio) or !v.global.wire.eql(closing.wire)) {
            reason = "NativeGkrGlobalClosureMismatch";
            break :blk;
        }
        const b = S.drawBinding(&ch, &roster) catch |e| {
            reason = @errorName(e);
            break :blk;
        };
        S.requireBinding(gpa, &roster, &v, &inputs, &b) catch |e| {
            reason = @errorName(e);
            break :blk;
        };
        accepted = true;
    }
    const verify_ns = timer.lap();
    try out.writeAll(try std.fmt.allocPrint(a, "{{\"proof\":\"{s}\",\"accepted\":{any},\"reason\":\"{s}\",\"inputs_ns\":{d},\"verify_ns\":{d}}}\n", .{ which, accepted, reason, inputs_ns, verify_ns }));
    if (!accepted) std.process.exit(1);
}
