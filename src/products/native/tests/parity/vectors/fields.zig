//! Prime-field, extension-field, circle, FFT, and Blake3 oracle vectors.

const std = @import("std");
const circle_mod = @import("stwo_core").circle;
const fft_mod = @import("stwo_core").fft;
const vcs_blake3 = @import("stwo_core").vcs.blake3_hash;
const m31_mod = @import("stwo_core").fields.m31;
const fixtures = @import("fixtures.zig");

const M31_CIRCLE_GEN = circle_mod.M31_CIRCLE_GEN;
const M31 = m31_mod.M31;
const parseVectors = fixtures.parseVectors;
const m31From = fixtures.m31From;
const cm31From = fixtures.cm31From;
const qm31From = fixtures.qm31From;
const circleM31From = fixtures.circleM31From;

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

test "field vectors: circle m31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.circle_m31.len == parsed.value.meta.sample_count);
    for (parsed.value.circle_m31) |v| {
        const a = M31_CIRCLE_GEN.mul(@as(u128, v.a_scalar));
        const b = M31_CIRCLE_GEN.mul(@as(u128, v.b_scalar));
        try std.testing.expect(a.eql(circleM31From(v.a)));
        try std.testing.expect(b.eql(circleM31From(v.b)));
        try std.testing.expectEqual(v.log_order_a, a.logOrder());
        try std.testing.expect(a.add(b).eql(circleM31From(v.add)));
        try std.testing.expect(a.sub(b).eql(circleM31From(v.sub)));
        try std.testing.expect(a.double().eql(circleM31From(v.double_a)));
        try std.testing.expect(a.conjugate().eql(circleM31From(v.conjugate_a)));
    }
}

test "field vectors: fft m31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.fft_m31.len == parsed.value.meta.sample_count);
    for (parsed.value.fft_m31) |v| {
        var a = m31From(v.a);
        var b = m31From(v.b);
        const twid = m31From(v.twid);

        fft_mod.butterfly(M31, &a, &b, twid);
        try std.testing.expect(a.eql(m31From(v.butterfly[0])));
        try std.testing.expect(b.eql(m31From(v.butterfly[1])));

        const itwid = try twid.inv();
        fft_mod.ibutterfly(M31, &a, &b, itwid);
        try std.testing.expect(a.eql(m31From(v.ibutterfly[0])));
        try std.testing.expect(b.eql(m31From(v.ibutterfly[1])));
    }
}

test "field vectors: blake3 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.blake3.len > 0);
    for (parsed.value.blake3) |v| {
        const hash = vcs_blake3.Blake3Hasher.hash(v.data);
        try std.testing.expectEqualSlices(u8, v.hash[0..], hash[0..]);

        const concat = vcs_blake3.Blake3Hasher.concatAndHash(v.left, v.right);
        try std.testing.expectEqualSlices(u8, v.concat_hash[0..], concat[0..]);
    }
}
