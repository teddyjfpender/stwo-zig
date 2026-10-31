const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const native = @import("../rv64_multiplication_native.zig");
const Mul = native.Mul;
const L = Mul.layout;
const fixture = @import("rv64_multiplication_test.zig");
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
test "MUL and BYTE one PCS production proof fresh receiver and previous masks" {
    const requests = fixture.requests();
    const public = native.Public{ .requests = &requests, .log_size = 7 };
    var bundle = try native.prove(a, public, std.process.hasEnvVarConstant("STWO_RV64_MULTIPLICATION_REFERENCE"));
    defer bundle.deinit(a);
    const claims = bundle.claims;
    const wire = @import("stwo_proof_wire");
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    try native.verifyOwned(a, public, claims, try wire.decodeProofBytesBinary(a, encoded));
    for (0..2) |family| {
        var wrong = try wire.decodeProofBytesBinary(a, encoded);
        const tree: usize = if (family == 0) 1 else 2;
        const column = if (family == 0) L.COUNT else L.INTERACTION - 1;
        wrong.commitment_scheme_proof.sampled_values.items[tree][column][1] = wrong.commitment_scheme_proof.sampled_values.items[tree][column][1].add(Q.one());
        try std.testing.expectError(error.OodsNotMatching, native.verifyOwned(a, public, claims, wrong));
    }
    var balanced = claims;
    balanced.multiplication = balanced.multiplication.add(Q.one());
    balanced.bytes = balanced.bytes.sub(Q.one());
    try std.testing.expectError(error.OodsNotMatching, native.verifyOwned(a, public, balanced, try wire.decodeProofBytesBinary(a, encoded)));
    const artifact = std.process.getEnvVarOwned(a, "STWO_RV64_MULTIPLICATION_ARTIFACT_DIR") catch null;
    defer if (artifact) |path| a.free(path);
    if (artifact) |path| {
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const pj = try std.json.Stringify.valueAlloc(a, public, .{});
        defer a.free(pj);
        const cj = try std.json.Stringify.valueAlloc(a, claims, .{});
        defer a.free(cj);
        try dir.writeFile(.{ .sub_path = "public.json", .data = pj });
        try dir.writeFile(.{ .sub_path = "claims.json", .data = cj });
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
        for (0..2) |family| {
            var wrong = try wire.decodeProofBytesBinary(a, encoded);
            defer wrong.deinit(a);
            const tree: usize = if (family == 0) 1 else 2;
            const column = if (family == 0) L.COUNT else L.INTERACTION - 1;
            wrong.commitment_scheme_proof.sampled_values.items[tree][column][1] = wrong.commitment_scheme_proof.sampled_values.items[tree][column][1].add(Q.one());
            const corrupt = try wire.encodeProofBytesBinary(a, wrong);
            defer a.free(corrupt);
            try dir.writeFile(.{ .sub_path = if (family == 0) "bad-count-prefix.bin" else "bad-state-prefix.bin", .data = corrupt });
        }
    }
}

test "colluding MUL result and perfectly matching byte/typed claims fail arithmetic" {
    const input = [_]Mul.trace.Request{.{ .opcode = .MULH, .a = 0xffffffffffffffff, .b = 0xffffffffffffffff, .result = 1 }};
    // True signed high(-1 * -1) is0. Producer can make all range and typed
    // claims agree with result1; the schoolbook/high-correction AIR rejects.
    try std.testing.expectError(error.ConstraintsNotSatisfied, native.prove(a, .{ .requests = &input, .log_size = 5 }, false));
}
