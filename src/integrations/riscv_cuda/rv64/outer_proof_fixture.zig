//! Actual native OM31 circuit proof qualification through the production device
//! factory. Modes live in the existing AIR tool; this is not another prover.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Service = @import("pcs_native.zig");
const TC = @import("trace_commit.zig");
const RC = @import("resident_composition.zig");
const Device = @import("outer_source.zig");
pub const Mode = enum { control, gpu, verify };
pub fn run(a: std.mem.Allocator, mode: Mode, input: []const u8, directory: []const u8) !void {
    var ctx = try circuit.builder.Context(Outer.protocol.Q).init(a, 8);
    defer ctx.deinit();
    const expected: [32]u8 = @splat(0x42);
    var outputs: [8]circuit.builder.Var = undefined;
    for (&outputs, 0..) |*out, i| out.* = try ctx.guess(circuit.builder.ivalue.packU32(Outer.protocol.Q, std.mem.readInt(u32, expected[4 * i ..][0..4], .little)));
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    try circuit.common.finalize.padToTargets(Outer.protocol.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var key = try Outer.prove.Authority.init(a, &pp);
    defer key.deinit();
    try std.fs.cwd().makePath(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    if (mode == .verify) {
        const bytes = try std.fs.cwd().readFileAlloc(a, input, Outer.wire.MAX_BYTES);
        defer a.free(bytes);
        var decoded = try Outer.wire.decode(a, key.identity, 8, bytes);
        defer decoded.deinit();
        var capture = try Outer.prove.verify(a, &key, decoded.outputs, decoded.claims, &decoded.proof);
        defer capture.deinit(a);
        try checkOutputs(decoded.outputs, expected);
        std.debug.print("OM31_OUTER_DEVICE_FRESH_RECEIVER accepted=true profile=q108-p20-fold4\n", .{});
        return;
    }
    if (mode == .control) {
        var proof = try Outer.prove.prove(a, &key, ctx.values());
        defer proof.deinit();
        var capture = try Outer.prove.verify(a, &key, proof.outputs, proof.claims, &proof.proof.proof);
        defer capture.deinit(a);
        const encoded = try Outer.wire.encode(a, key.identity, proof.outputs, proof.claims, &proof.proof.proof);
        defer a.free(encoded);
        try dir.writeFile(.{ .sub_path = "control.om31", .data = encoded });
        return;
    }
    var service = try Service.Context.init(input, 0, 28 << 30);
    defer service.deinit();
    try service.enableImmutableSetup(2 << 30);
    var commit = try TC.Context.init(&service);
    defer commit.deinit();
    var composition = try RC.Context.initNumerical(a, &service);
    defer composition.deinit();
    var factory = try Device.Context.init(a, &service, &commit, &composition);
    defer factory.deinit();
    var first: ?[]u8 = null;
    defer if (first) |bytes| a.free(bytes);
    for (0..2) |ordinal| {
        var timer = try std.time.Timer.start();
        var proof = try Outer.device_prove.prove(a, &key, ctx.values(), @intCast(ordinal), factory.factory());
        defer proof.deinit();
        const prove_ns = timer.lap();
        var capture = try Outer.prove.verify(a, &key, proof.outputs, proof.claims, &proof.proof.proof);
        defer capture.deinit(a);
        try checkOutputs(proof.outputs, expected);
        const encoded = try Outer.wire.encode(a, key.identity, proof.outputs, proof.claims, &proof.proof.proof);
        defer a.free(encoded);
        if (first) |old| {
            if (!std.mem.eql(u8, old, encoded)) return error.WarmOuterProofByteMismatch;
        } else first = try a.dupe(u8, encoded);
        if (dir.readFileAlloc(a, "control.om31", Outer.wire.MAX_BYTES)) |control| {
            defer a.free(control);
            if (!std.mem.eql(u8, control, encoded)) return error.NativeOuterProofByteMismatch;
        } else |err| if (err != error.FileNotFound) return err;
        const name = try std.fmt.allocPrint(a, "gpu-{}.om31", .{ordinal});
        defer a.free(name);
        try dir.writeFile(.{ .sub_path = name, .data = encoded });
        std.debug.print("OM31_OUTER_DEVICE_PROOF ordinal={} fresh_accepted=true bytes={} prove_ns={} profile=q108-p20-fold4\n", .{ ordinal, encoded.len, prove_ns });
    }
}
fn checkOutputs(outputs: []const Outer.protocol.Q, digest: [32]u8) !void {
    if (outputs.len != 8) return error.OuterOutputCount;
    for (outputs, 0..) |output, i| if (!output.eql(circuit.builder.ivalue.packU32(Outer.protocol.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little)))) return error.OuterDigestMismatch;
}
