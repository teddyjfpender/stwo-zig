//! Host-only topology census (diagnostic). Never enters a proof, transcript or
//! authority identity. Separates the structural gate graph of a recursive
//! verifier circuit from its interned constant VALUES and its witness-origin
//! shape, so the producer/receiver can see why two nodes have distinct
//! authorities. Enabled by STWO_RV64_TOPOLOGY_CENSUS=1; optional
//! STWO_RV64_TOPOLOGY_DUMP_DIR receives the constant table per node.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");

pub const Fingerprint = struct {
    /// All gate lists, outputs and var count. Constants enter only as var ids.
    gates: [32]u8,
    /// Interned constant table, in first-use order (key limbs + var id).
    constants: [32]u8,
    /// Witness-origin kinds and operands (not values).
    origins: [32]u8,
    n_vars: u32,
    n_constants: usize,
    n_origins: usize,
};

fn feed(h: *std.crypto.hash.sha2.Sha256, comptime T: type, items: []const T) void {
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, items.len, .little);
    h.update(&len);
    h.update(std.mem.sliceAsBytes(items));
}

pub fn compute(ctx: *const C.Context) Fingerprint {
    const c = &ctx.circuit;
    var g = std.crypto.hash.sha2.Sha256.init(.{});
    var nv: [4]u8 = undefined;
    std.mem.writeInt(u32, &nv, c.n_vars, .little);
    g.update(&nv);
    feed(&g, circuit.builder.circuit.BinaryGate, c.add.items);
    feed(&g, circuit.builder.circuit.BinaryGate, c.sub.items);
    feed(&g, circuit.builder.circuit.BinaryGate, c.mul.items);
    feed(&g, circuit.builder.circuit.BinaryGate, c.pointwise_mul.items);
    feed(&g, circuit.builder.circuit.EqGate, c.eq.items);
    feed(&g, circuit.builder.circuit.TripleXorGate, c.triple_xor.items);
    feed(&g, circuit.builder.circuit.M31ToU32Gate, c.m31_to_u32.items);
    feed(&g, circuit.builder.circuit.BlakeGGate, c.blake_g_gate.items);
    feed(&g, u32, c.permutation.ends.items);
    feed(&g, u32, c.permutation.inputs.items);
    feed(&g, u32, c.permutation.outputs.items);
    feed(&g, u32, c.output.items);
    var k = std.crypto.hash.sha2.Sha256.init(.{});
    feed(&k, u128, ctx.constants.keys());
    feed(&k, circuit.builder.Var, ctx.constants.values());
    var o = std.crypto.hash.sha2.Sha256.init(.{});
    var n_origins: usize = 0;
    if (ctx.witness_metadata) |metadata| {
        n_origins = metadata.origins.items.len;
        for (metadata.origins.items) |origin| {
            var buf: [13]u8 = undefined;
            std.mem.writeInt(u32, buf[0..4], origin.out, .little);
            buf[4] = @intFromEnum(origin.kind);
            std.mem.writeInt(u32, buf[5..9], origin.a, .little);
            std.mem.writeInt(u32, buf[9..13], origin.b, .little);
            o.update(&buf);
        }
    }
    return .{ .gates = g.finalResult(), .constants = k.finalResult(), .origins = o.finalResult(), .n_vars = c.n_vars, .n_constants = ctx.constants.count(), .n_origins = n_origins };
}

pub fn enabled() bool {
    const value = std.posix.getenv("STWO_RV64_TOPOLOGY_CENSUS") orelse return false;
    return std.mem.eql(u8, value, "1");
}

/// Logs one line per node; `label` is e.g. "leaf-cpu-0003" or "fold-[0,4)".
pub fn report(ctx: *const C.Context, label: []const u8, stage: []const u8) void {
    if (!enabled()) return;
    const f = compute(ctx);
    std.debug.print("TOPOLOGY_CENSUS label={s} stage={s} n_vars={d} n_constants={d} n_origins={d} gates={x} constants={x} origins={x}\n", .{ label, stage, f.n_vars, f.n_constants, f.n_origins, f.gates, f.constants, f.origins });
    const dir_path = std.posix.getenv("STWO_RV64_TOPOLOGY_DUMP_DIR") orelse return;
    dump(ctx, dir_path, label, stage) catch |err| std.debug.print("TOPOLOGY_CENSUS dump_error={s}\n", .{@errorName(err)});
}

fn dump(ctx: *const C.Context, dir_path: []const u8, label: []const u8, stage: []const u8) !void {
    var dir = try std.fs.cwd().makeOpenPath(dir_path, .{});
    defer dir.close();
    var name_buffer: [160]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "{s}.{s}.constants.bin", .{ label, stage });
    var file = try dir.createFile(name, .{});
    defer file.close();
    // Record: u128 key, u32 var id (little-endian), first-use order.
    for (ctx.constants.keys(), ctx.constants.values()) |key, v| {
        var buf: [20]u8 = undefined;
        std.mem.writeInt(u128, buf[0..16], key, .little);
        std.mem.writeInt(u32, buf[16..20], v.idx, .little);
        try file.writeAll(&buf);
    }
}
