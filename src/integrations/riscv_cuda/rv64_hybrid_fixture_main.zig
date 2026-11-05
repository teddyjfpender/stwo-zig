//! Focused hybrid CUDA proof qualification and independent CPU reception.
//! This fixture does not select an Ethereum production profile.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Receiver = CPU.rv64_outer_hybrid_receiver;
const Device = CPU.rv64_outer_hybrid_device;
const Wire = CPU.rv64_outer_hybrid_wire;
const Native = @import("rv64/pcs_native.zig");
const Trace = @import("rv64/trace_commit.zig");
const Composition = @import("rv64/resident_composition.zig");
const Source = @import("rv64/outer_source.zig");
const Q = Outer.protocol.Q;
const a = std.heap.page_allocator;
const N = 180;
fn expected() [N]Q {
    var result: [N]Q = undefined;
    result[0] = Q.fromU32Unchecked(11, 3, 7, 9).mul(Q.fromU32Unchecked(17, 0, 0, 0));
    for (result[1..], 1..) |*out, i| out.* = Circuit.builder.ivalue.packU32(Q, @intCast(i * 17 + 0x42424242));
    return result;
}
fn graph() !Circuit.builder.Context(Q) {
    var ctx = try Circuit.builder.Context(Q).initTraceOnly(a, N);
    errdefer ctx.deinit();
    const x = try ctx.guess(Q.fromU32Unchecked(11, 3, 7, 9));
    const y = try ctx.guess(Q.fromU32Unchecked(17, 0, 0, 0));
    var outputs: [N]Circuit.builder.Var = undefined;
    outputs[0] = try ctx.mul(x, y);
    const values = expected();
    for (outputs[1..], values[1..]) |*out, value| out.* = try ctx.guess(value);
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    try Circuit.common.finalize.padToTargets(Q, &ctx, Circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    return ctx;
}
fn checkOutputs(values: []const Q) !void {
    const want = expected();
    if (values.len != want.len) return error.FixtureOutputCount;
    for (values, want) |value, target| if (!value.eql(target)) return error.FixtureOutputMismatch;
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 3 and std.mem.eql(u8, args[1], "--write-aot")) {
        try std.fs.cwd().makePath(args[2]);
        var directory = try std.fs.cwd().openDir(args[2], .{});
        defer directory.close();
        return @import("rv64/outer_hybrid_aot.zig").write(a, directory);
    }
    const prove = args.len == 4 and std.mem.eql(u8, args[1], "--prove");
    const verify = args.len == 3 and std.mem.eql(u8, args[1], "--verify");
    const child = args.len == 3 and std.mem.eql(u8, args[1], "--check-child");
    if (!prove and !verify and !child) return error.UsageHybridFixture;
    var ctx = try graph();
    defer ctx.deinit();
    var pp = try Circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var authority = try Outer.prove.Authority.init(a, &pp);
    defer authority.deinit();
    var key = try Receiver.Key.init(a, &authority, 1);
    defer key.deinit();
    if (verify or child) {
        const bytes = try std.fs.cwd().readFileAlloc(a, args[2], Wire.MAX_BYTES);
        defer a.free(bytes);
        var decoded = try Wire.decode(a, &key, bytes);
        defer decoded.deinit();
        try checkOutputs(decoded.base.outputs);
        const capture = try key.verify(a, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof);
        if (child) try CPU.rv64_outer_hybrid_child.checkFixture(a, &key, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof, &capture);
        std.debug.print("HYBRID_FRESH_RECEIVER_OK outputs={} bytes={} identity={x}\n", .{ N, bytes.len, key.identity });
        return;
    }
    var native = try Native.Context.init(args[2], 0, 28 << 30);
    defer native.deinit();
    var trace = try Trace.Context.init(&native);
    defer trace.deinit();
    var composition = try Composition.Context.initNumerical(a, &native);
    defer composition.deinit();
    var source = try Source.Context.init(a, &native, &trace, &composition);
    defer source.deinit();
    const factory = try source.factoryForHybrid();
    const want = expected();
    var first: ?[]u8 = null;
    defer if (first) |bytes| a.free(bytes);
    for (0..2) |round| {
        var produced = try Device.proveFromCircuit(a, &key, &ctx, &want, @intCast(round), factory, null);
        defer produced.deinit();
        _ = try key.verify(a, produced.base.outputs, produced.base.claims, &produced.section, &produced.base.proof.proof);
        const bytes = try Wire.encode(a, &key, produced.base.outputs, produced.base.claims, &produced.section, &produced.base.proof.proof);
        if (first) |prior| {
            defer a.free(bytes);
            if (!std.mem.eql(u8, prior, bytes)) return error.HybridWarmProofBytesChanged;
        } else first = bytes;
        std.debug.print("HYBRID_GPU_FIXTURE_OK round={} outputs={} bytes={} identity={x}\n", .{ round, N, bytes.len, key.identity });
    }
    try std.fs.cwd().writeFile(.{ .sub_path = args[3], .data = first.? });
}
