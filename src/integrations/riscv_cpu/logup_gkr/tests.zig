//! WGKR-LS-RANGE-v0 adversarial and roundtrip suite (filter: "logup-gkr").
const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const W = @import("witness.zig");
const P = @import("protocol.zig");
const MP = @import("mle_point.zig");
const Air = @import("air.zig");

test {
    _ = @import("mle_point.zig");
}

const small = W.Statement{ .ls_log = 6, .tail_log = 4, .hi_log = 6, .lo_log = 4 };

fn proveSmall(a: std.mem.Allocator, variant: P.Variant, fault: P.Fault, statement: W.Statement, witness: *const W.Witness) ![]u8 {
    const result = try P.prove(a, P.testConfig(), .{ .statement = statement, .variant = variant, .fault = fault, .witness = witness }, null);
    return result.bytes;
}

test "logup-gkr: classic and gkr variants prove and fresh-verify the same witness" {
    const a = std.testing.allocator;
    var w = try W.Witness.synthetic(a, small, 7);
    defer w.deinit();
    for ([_]P.Variant{ .classic, .gkr }) |variant| {
        const bytes = try proveSmall(a, variant, .none, small, &w);
        defer a.free(bytes);
        _ = try P.verify(a, P.testConfig(), small, variant, bytes);
        // The receiver's variant comes from its own configuration.
        const other: P.Variant = if (variant == .classic) .gkr else .classic;
        try std.testing.expectError(error.VariantMismatch, P.verify(a, P.testConfig(), small, other, bytes));
    }
}

/// Splits a bundle into (prefix through claims, gkr bytes, suffix from stark length).
const Parts = struct { head: []const u8, gkr: []const u8, tail: []const u8 };
fn split(bytes: []const u8) Parts {
    var at: usize = 8 + 4 + 16;
    const n_claims = std.mem.readInt(u32, bytes[at..][0..4], .little);
    at += 4 + 16 * n_claims;
    const gkr_len = std.mem.readInt(u32, bytes[at..][0..4], .little);
    return .{ .head = bytes[0..at], .gkr = bytes[at + 4 .. at + 4 + gkr_len], .tail = bytes[at + 4 + gkr_len ..] };
}

fn rebuild(a: std.mem.Allocator, bytes: []const u8, proof: *const @import("stwo_prover_engine").lookups.gkr_verifier.GkrBatchProof) ![]u8 {
    const parts = split(bytes);
    const gkr = try P.encodeGkr(a, proof);
    defer a.free(gkr);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, parts.head);
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(gkr.len), .little);
    try out.appendSlice(a, &len);
    try out.appendSlice(a, gkr);
    try out.appendSlice(a, parts.tail);
    return out.toOwnedSlice(a);
}

const Tamper = enum { round_coeff, layer_mask, drop_layer, zero_root_denominator, noncanonical };

fn tampered(a: std.mem.Allocator, bytes: []const u8, how: Tamper) ![]u8 {
    if (how == .noncanonical) {
        const out = try a.dupe(u8, bytes);
        const parts = split(bytes);
        const offset = parts.head.len + 4 + 4 + 4 + 4; // n_instances, n_masks, n_claims, first coordinate
        std.mem.writeInt(u32, out[offset..][0..4], core.fields.m31.Modulus, .little);
        return out;
    }
    var proof = try P.decodeGkr(a, split(bytes).gkr);
    defer proof.deinit(a);
    switch (how) {
        .round_coeff => {
            const poly = &proof.sumcheck_proofs[5].round_polys[2];
            poly.coeffs[0] = poly.coeffs[0].add(QM31.one());
        },
        .layer_mask => {
            const mask = &proof.layer_masks_by_instance[0][7];
            mask.columns[1][0] = mask.columns[1][0].add(QM31.one());
        },
        .drop_layer => {
            const masks = proof.layer_masks_by_instance[0];
            var last = masks[masks.len - 1];
            last.deinit(a);
            proof.layer_masks_by_instance[0] = try a.realloc(masks, masks.len - 1);
        },
        .zero_root_denominator => proof.output_claims_by_instance[1][1] = QM31.zero(),
        .noncanonical => unreachable,
    }
    return rebuild(a, bytes, &proof);
}

test "logup-gkr: tampered GKR transcript material is rejected at the scalar checks" {
    const a = std.testing.allocator;
    var w = try W.Witness.synthetic(a, small, 11);
    defer w.deinit();
    const bytes = try proveSmall(a, .gkr, .none, small, &w);
    defer a.free(bytes);
    const cases = [_]struct { how: Tamper, err: anyerror }{
        .{ .how = .round_coeff, .err = error.InvalidSumcheck },
        .{ .how = .layer_mask, .err = error.CircuitCheckFailure },
        .{ .how = .drop_layer, .err = error.GkrShapeMismatch },
        .{ .how = .zero_root_denominator, .err = error.GkrZeroRootDenominator },
        .{ .how = .noncanonical, .err = error.NonCanonicalField },
    };
    for (cases) |case| {
        const bad = try tampered(a, bytes, case.how);
        defer a.free(bad);
        try std.testing.expectError(case.err, P.verify(a, P.testConfig(), small, .gkr, bad));
    }
}

/// `expected == null` means rejection by the STARK itself (R7): OODS mismatch.
fn expectProverFault(a: std.mem.Allocator, fault: P.Fault, expected: ?anyerror) !void {
    var w = try W.Witness.synthetic(a, small, 23);
    defer w.deinit();
    const bytes = try proveSmall(a, .gkr, fault, small, &w);
    defer a.free(bytes);
    if (P.verify(a, P.testConfig(), small, .gkr, bytes)) |_| {
        std.debug.print("fault {s} was ACCEPTED\n", .{@tagName(fault)});
        return error.FaultAccepted;
    } else |err| {
        try std.testing.expectEqual(expected orelse error.OodsNotMatching, err);
    }
}

test "logup-gkr: forged multiplicity in the last mask is rejected by nu == 1" {
    try expectProverFault(std.testing.allocator, .forge_numerator, error.GkrNumeratorNotOne);
}

test "logup-gkr: committed column mutated after GKR is rejected by the STARK binding" {
    try expectProverFault(std.testing.allocator, .mutate_main_after_gkr, null);
}

test "logup-gkr: mutation applied to MAIN and GKR consistently fails closure" {
    try expectProverFault(std.testing.allocator, .mutate_main_consistent, error.UnclosedRangeLookup);
}

test "logup-gkr: eq column cell flip is rejected by the STARK" {
    try expectProverFault(std.testing.allocator, .eq_cell_flip, null);
}

test "logup-gkr: AIR prefix using delta + 1 is rejected by the STARK" {
    try expectProverFault(std.testing.allocator, .shift_delta, null);
}

test "logup-gkr: out-of-range value proved honestly through GKR fails closure" {
    const a = std.testing.allocator;
    for ([_]P.Variant{ .gkr, .classic }) |variant| {
        var w = try W.Witness.synthetic(a, small, 31);
        defer w.deinit();
        w.instances[1].lanes[3][2] = @as(u32, 1) << @intCast(small.hi_log);
        // The honest prover refuses an unbalanced witness.
        try std.testing.expectError(error.UnbalancedRangeLookup, proveSmall(a, variant, .none, small, &w));
        const bytes = try proveSmall(a, variant, .skip_closure_check, small, &w);
        defer a.free(bytes);
        try std.testing.expectError(error.UnclosedRangeLookup, P.verify(a, P.testConfig(), small, variant, bytes));
    }
}

test "logup-gkr: terminal coordinates in {0, 1} are rejected (R5)" {
    const ch = Air.Challenges{ .z_hi = QM31.fromU32Unchecked(3, 4, 5, 6), .c_hi = QM31.one(), .z_lo = QM31.fromU32Unchecked(9, 1, 2, 3), .c_lo = QM31.one() };
    var r: [10]QM31 = undefined;
    for (&r, 0..) |*v, i| v.* = QM31.fromU32Unchecked(@intCast(100 + i), 7, 0, 1);
    _ = try P.Binding.init(&r, 6, ch, QM31.one());
    r[2] = QM31.one();
    try std.testing.expectError(error.DegenerateEvalPoint, P.Binding.init(&r, 6, ch, QM31.one()));
    // A lane coordinate in {0, 1} is harmless: only r_row enters the eq column.
    r[2] = QM31.fromU32Unchecked(5, 0, 0, 0);
    r[8] = QM31.zero();
    _ = try P.Binding.init(&r, 6, ch, QM31.one());
}

test "logup-gkr: single-instance batch and receiver statement binding" {
    const a = std.testing.allocator;
    const st = W.Statement{ .ls_log = 5, .tail_log = 0, .hi_log = 6, .lo_log = 3 };
    var w = try W.Witness.synthetic(a, st, 3);
    defer w.deinit();
    const bytes = try proveSmall(a, .gkr, .none, st, &w);
    defer a.free(bytes);
    _ = try P.verify(a, P.testConfig(), st, .gkr, bytes);
    var other = st;
    other.ls_log = 6;
    try std.testing.expectError(error.StatementMismatch, P.verify(a, P.testConfig(), other, .gkr, bytes));
}

test "logup-gkr: classic tampered ledger claim is rejected" {
    const a = std.testing.allocator;
    var w = try W.Witness.synthetic(a, small, 41);
    defer w.deinit();
    const bytes = try proveSmall(a, .classic, .none, small, &w);
    defer a.free(bytes);
    const bad = try a.dupe(u8, bytes);
    defer a.free(bad);
    // Shift claim 0 and claim 1 by +1/-1: closure still holds, the STARK must reject.
    const c0 = 8 + 4 + 16 + 4;
    std.mem.writeInt(u32, bad[c0..][0..4], (std.mem.readInt(u32, bad[c0..][0..4], .little) + 1) % core.fields.m31.Modulus, .little);
    std.mem.writeInt(u32, bad[c0 + 16 ..][0..4], (std.mem.readInt(u32, bad[c0 + 16 ..][0..4], .little) + core.fields.m31.Modulus - 1) % core.fields.m31.Modulus, .little);
    if (P.verify(a, P.testConfig(), small, .classic, bad)) |_| return error.TamperAccepted else |_| {}
}

test "logup-gkr: witness file roundtrip" {
    const a = std.testing.allocator;
    var w = try W.Witness.synthetic(a, small, 5);
    defer w.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile("w.bin", .{});
        defer f.close();
        try W.write(&w, f);
    }
    var f = try tmp.dir.openFile("w.bin", .{});
    defer f.close();
    try std.testing.expectEqual(@as(u64, 24 + 2 * w.cells()), try f.getEndPos());
    var r = try W.read(a, f);
    defer r.deinit();
    for (w.slice(), r.slice()) |x, y| for (x.lanes, y.lanes) |p, q| try std.testing.expectEqualSlices(u32, p, q);
}

test "logup-gkr: parallel clone-free GKR prover is byte-identical to the reference prover" {
    const a = std.testing.allocator;
    const F = @import("fast_gkr.zig");
    const lookups = @import("stwo_prover_engine").lookups;
    const MleSecure = lookups.mle.Mle(QM31);
    var draw = P.Channel{};
    draw.mixU32s(&.{0x46415354});
    const sizes = [_]usize{ 1 << 9, 1 << 6, 1 << 9 };
    var dens: [3][]QM31 = undefined;
    for (&dens, sizes) |*d, n| d.* = try draw.drawSecureFelts(a, n);
    defer for (dens) |d| a.free(d);
    const num2 = try a.alloc(QM31, sizes[2]);
    defer a.free(num2);
    for (num2, 0..) |*v, i| v.* = if (i % 7 == 0) QM31.fromU32Unchecked(@intCast(i), 1, 0, 3) else QM31.one();

    var reference_layers: [3]lookups.gkr_prover.Layer = .{
        .{ .LogUpSingles = .{ .denominators = try MleSecure.initOwned(try a.dupe(QM31, dens[0])) } },
        .{ .LogUpSingles = .{ .denominators = try MleSecure.initOwned(try a.dupe(QM31, dens[1])) } },
        .{ .LogUpGeneric = .{ .numerators = try MleSecure.initOwned(try a.dupe(QM31, num2)), .denominators = try MleSecure.initOwned(try a.dupe(QM31, dens[2])) } },
    };
    defer for (&reference_layers) |*l| l.deinit(a);
    var ch_ref = P.Channel{};
    var reference = try lookups.gkr_prover.proveBatch(a, &ch_ref, &reference_layers);
    defer reference.deinit(a);

    for ([_]usize{ 1, 3 }) |threads| {
        var inputs = [_]F.Input{
            .{ .num = null, .den = try a.dupe(QM31, dens[0]) },
            .{ .num = null, .den = try a.dupe(QM31, dens[1]) },
            .{ .num = try a.dupe(QM31, num2), .den = try a.dupe(QM31, dens[2]) },
        };
        var ch_fast = P.Channel{};
        var fast = try F.proveBatch(a, &ch_fast, &inputs, .{ .threads = threads, .min_parallel = 16 }, null);
        defer fast.deinit(a);
        const x = try P.encodeGkr(a, &reference.proof);
        defer a.free(x);
        const y = try P.encodeGkr(a, &fast.proof);
        defer a.free(y);
        try std.testing.expectEqualSlices(u8, x, y);
        try std.testing.expectEqualSlices(u8, &ch_ref.digestBytes(), &ch_fast.digestBytes());
        try std.testing.expectEqualSlices(QM31, reference.artifact.ood_point, fast.artifact.ood_point);
        for (reference.artifact.claims_to_verify_by_instance, fast.artifact.claims_to_verify_by_instance) |r, f| try std.testing.expectEqualSlices(QM31, r, f);
    }
}

test "logup-gkr: bundle is identical with the reference and the parallel GKR prover" {
    const a = std.testing.allocator;
    var w = try W.Witness.synthetic(a, small, 77);
    defer w.deinit();
    var x = try P.prove(a, P.testConfig(), .{ .statement = small, .variant = .gkr, .witness = &w, .gkr_prover = .reference }, null);
    defer x.deinit(a);
    var y = try P.prove(a, P.testConfig(), .{ .statement = small, .variant = .gkr, .witness = &w, .gkr_prover = .fast, .gkr_threads = 3 }, null);
    defer y.deinit(a);
    try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
}
