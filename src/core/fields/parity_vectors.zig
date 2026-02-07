const std = @import("std");
const cm31_mod = @import("cm31.zig");
const m31_mod = @import("m31.zig");
const qm31_mod = @import("qm31.zig");

const M31 = m31_mod.M31;
const CM31 = cm31_mod.CM31;
const QM31 = qm31_mod.QM31;

const M31Vector = struct {
    a: u32,
    b: u32,
    add: u32,
    sub: u32,
    mul: u32,
    inv_a: u32,
    div_ab: u32,
};

const CM31Vector = struct {
    a: [2]u32,
    b: [2]u32,
    add: [2]u32,
    sub: [2]u32,
    mul: [2]u32,
    inv_a: [2]u32,
    div_ab: [2]u32,
};

const QM31Vector = struct {
    a: [4]u32,
    b: [4]u32,
    add: [4]u32,
    sub: [4]u32,
    mul: [4]u32,
    inv_a: [4]u32,
    div_ab: [4]u32,
};

const VectorFile = struct {
    meta: struct {
        upstream_commit: []const u8,
        sample_count: usize,
    },
    m31: []M31Vector,
    cm31: []CM31Vector,
    qm31: []QM31Vector,
};

fn parseVectors(allocator: std.mem.Allocator) !std.json.Parsed(VectorFile) {
    const raw = @embedFile("../../../vectors/fields.json");
    return std.json.parseFromSlice(VectorFile, allocator, raw, .{
        .ignore_unknown_fields = false,
    });
}

fn m31From(x: u32) M31 {
    return M31.fromCanonical(x);
}

fn cm31From(v: [2]u32) CM31 {
    return CM31.fromU32Unchecked(v[0], v[1]);
}

fn qm31From(v: [4]u32) QM31 {
    return QM31.fromU32Unchecked(v[0], v[1], v[2], v[3]);
}

test "field vectors: m31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.m31.len == parsed.value.meta.sample_count);
    for (parsed.value.m31) |v| {
        const a = m31From(v.a);
        const b = m31From(v.b);
        try std.testing.expect(a.add(b).eql(m31From(v.add)));
        try std.testing.expect(a.sub(b).eql(m31From(v.sub)));
        try std.testing.expect(a.mul(b).eql(m31From(v.mul)));
        try std.testing.expect((try a.inv()).eql(m31From(v.inv_a)));
        try std.testing.expect((try a.div(b)).eql(m31From(v.div_ab)));
    }
}

test "field vectors: cm31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.cm31.len == parsed.value.meta.sample_count);
    for (parsed.value.cm31) |v| {
        const a = cm31From(v.a);
        const b = cm31From(v.b);
        try std.testing.expect(a.add(b).eql(cm31From(v.add)));
        try std.testing.expect(a.sub(b).eql(cm31From(v.sub)));
        try std.testing.expect(a.mul(b).eql(cm31From(v.mul)));
        try std.testing.expect((try a.inv()).eql(cm31From(v.inv_a)));
        try std.testing.expect((try a.div(b)).eql(cm31From(v.div_ab)));
    }
}

test "field vectors: qm31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.qm31.len == parsed.value.meta.sample_count);
    for (parsed.value.qm31) |v| {
        const a = qm31From(v.a);
        const b = qm31From(v.b);
        try std.testing.expect(a.add(b).eql(qm31From(v.add)));
        try std.testing.expect(a.sub(b).eql(qm31From(v.sub)));
        try std.testing.expect(a.mul(b).eql(qm31From(v.mul)));
        try std.testing.expect((try a.inv()).eql(qm31From(v.inv_a)));
        try std.testing.expect((try a.div(b)).eql(qm31From(v.div_ab)));
    }
}
