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
    const wrapped_mode = args.len == 4 and std.mem.eql(u8, args[1], "--prove-wrapped");
    const frontier = args.len == 4 and std.mem.eql(u8, args[1], "--prove-frontier");
    const prove = args.len == 4 and (std.mem.eql(u8, args[1], "--prove") or wrapped_mode or frontier);
    const verify = args.len == 3 and std.mem.eql(u8, args[1], "--verify");
    const child = args.len == 3 and std.mem.eql(u8, args[1], "--check-child");
    const mutants = args.len == 3 and std.mem.eql(u8, args[1], "--check-child-mutants");
    if (!prove and !verify and !child and !mutants) return error.UsageHybridFixture;
    var ctx = try graph();
    defer ctx.deinit();
    var pp = try Circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var authority = try Outer.prove.Authority.init(a, &pp);
    defer authority.deinit();
    var key = try Receiver.Key.init(a, &authority, 256);
    defer key.deinit();
    if (verify or child or mutants) {
        const bytes = try std.fs.cwd().readFileAlloc(a, args[2], Wire.MAX_BYTES);
        defer a.free(bytes);
        var decoded = try Wire.decode(a, &key, bytes);
        defer decoded.deinit();
        try checkOutputs(decoded.base.outputs);
        var capture = try key.verify(a, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof);
        defer capture.deinit(a);
        if (child) {
            var restored = try CPU.rv64_om31_outer_wrap.restoreForOutputs(a, &pp, &authority, &expected(), @splat(0), bytes, true);
            defer restored.deinit();
            const RV = CPU.rv64_root_verify;
            const compact = try RV.VerifierKey.fromAuthority(&authority);
            if (!std.mem.eql(u8, &(try RV.effectiveIdentityForFamily(a, &compact, true)), &restored.effectiveIdentity())) return error.HybridCompactIdentity;
            const kids = [_]CPU.rv64_om31_outer.Child{ restored.asChild(), restored.asChild() };
            const compact_keys = [_]*const RV.VerifierKey{ &compact, &compact };
            if (!std.mem.eql(u8, &(try RV.foldClassKeyKForFamily(&compact_keys, true)), &(try CPU.rv64_om31_outer.classKey(&kids)))) return error.HybridCompactClass;
            if (RV.foldDigestKForFamily(&.{ .{ .key = &compact, .digest = @splat(0) }, .{ .key = &compact, .digest = @splat(0) } }, true)) |_| return error.LegacyCompactAcceptedNonDigestOutputs else |err| if (err != error.InvalidOm31CircuitOutputCount) return err;
            const C = CPU.rv64_outer_hybrid_child.common;
            var child_ctx = try C.Context.init(a, 0);
            defer child_ctx.deinit();
            C.lane.begin(&child_ctx);
            var active = true;
            defer if (active) C.lane.finish() catch {};
            const authenticated = try CPU.rv64_om31_outer.verifyChild(&child_ctx, restored.asChild());
            for (authenticated.identity, 0..) |wire, i| try child_ctx.eq(wire.get(), try child_ctx.constant(Circuit.builder.ivalue.packU32(Q, std.mem.readInt(u32, restored.effectiveIdentity()[4 * i ..][0..4], .little))));
            const fixed = try Circuit.builder.blake.constantHash(Q, &child_ctx, Circuit.builder.blake.hashValueFromDigest(Q, authority.fixedRoot()));
            for (authenticated.fixed_root.words, fixed.words) |wire, want| try child_ctx.eq(wire.get(), want.get());
            for (authenticated.outputs, expected()) |wire, want| try child_ctx.eq(wire, try child_ctx.constant(want));
            active = false;
            try C.lane.finish();
            try child_ctx.finalize(false);
            if (!try child_ctx.isCircuitValid()) return error.HybridAuthenticatedWireBinding;
            std.debug.print("HYBRID_AUTHENTICATED_CHILD_OK vars={} outputs={}\n", .{ child_ctx.circuit.n_vars, authenticated.outputs.len });
        }
        if (mutants) {
            const Check = CPU.rv64_outer_hybrid_child;
            var rejected: usize = 0;
            const saved_salt = decoded.section.salt;
            decoded.section.salt = saved_salt.add(Outer.protocol.O.one());
            if (Check.checkFixture(a, &key, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof, &capture)) |_| return error.HybridSaltMutantAccepted else |_| {
                rejected += 1;
            }
            decoded.section.salt = saved_salt;
            const root = &decoded.section.proof.output_claims_by_instance[0][0];
            const saved_root = root.*;
            root.* = root.add(Outer.protocol.O.one());
            if (Check.checkFixture(a, &key, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof, &capture)) |_| return error.HybridRootMutantAccepted else |_| {
                rejected += 1;
            }
            root.* = saved_root;
            const sampled = &decoded.base.proof.commitment_scheme_proof.sampled_values.items[2][CPU.rv64_outer_hybrid_air.interactionStart(.triple_xor)][0];
            const saved_sample = sampled.*;
            sampled.* = sampled.add(Outer.protocol.O.one());
            if (Check.checkFixture(a, &key, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof, &capture)) |_| return error.HybridEqMaskMutantAccepted else |_| {
                rejected += 1;
            }
            sampled.* = saved_sample;
            var claims = decoded.base.claims.toArray();
            claims[2] = Outer.protocol.O.one();
            if (Check.checkFixture(a, &key, decoded.base.outputs, Outer.witness.Claims.fromArray(claims), &decoded.section, &decoded.base.proof, &capture)) |_| return error.HybridClassicSlotMutantAccepted else |_| {
                rejected += 1;
            }
            std.debug.print("HYBRID_CHILD_MUTANTS_REJECTED cases={}\n", .{rejected});
        }
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
    if (frontier) source.gkr_mode = .recomputed_frontier;
    const factory = try source.factoryForHybrid();
    const want = expected();
    var first: ?[]u8 = null;
    defer if (first) |bytes| a.free(bytes);
    for (0..2) |round| {
        if (wrapped_mode) {
            const Wrap = CPU.rv64_om31_outer_wrap;
            var prep = try Wrap.prepareHostForOutputs(a, &ctx, factory, N);
            defer prep.deinit(a);
            var proved = try Wrap.proveDeviceForOutputs(a, &ctx, &prep, &want, @intCast(round), factory, true);
            var owns_proved = true;
            defer if (owns_proved) proved.deinit(a);
            var wrapped = try Wrap.finishProvedForOutputs(a, &proved, &want, @splat(0));
            owns_proved = false;
            defer wrapped.deinit();
            const kid = wrapped.asChild();
            if (!std.mem.eql(u8, &wrapped.effectiveIdentity(), &(try kid.effectiveIdentity())) or kid.hybrid == null) return error.HybridWrappedChildIdentity;
            const bytes = try wrapped.serialize(a);
            if (first) |prior| {
                defer a.free(bytes);
                if (!std.mem.eql(u8, prior, bytes)) return error.HybridWarmProofBytesChanged;
            } else first = bytes;
            std.debug.print("HYBRID_WRAPPED_FIXTURE_OK round={} outputs={} bytes={}\n", .{ round, N, bytes.len });
            continue;
        }
        var produced = try Device.proveFromCircuit(a, &key, &ctx, &want, @intCast(round), factory, null);
        defer produced.deinit();
        var capture = try key.verify(a, produced.base.outputs, produced.base.claims, &produced.section, &produced.base.proof.proof);
        defer capture.deinit(a);
        const bytes = try Wire.encode(a, &key, produced.base.outputs, produced.base.claims, &produced.section, &produced.base.proof.proof);
        if (first) |prior| {
            defer a.free(bytes);
            if (!std.mem.eql(u8, prior, bytes)) return error.HybridWarmProofBytesChanged;
        } else first = bytes;
        std.debug.print("HYBRID_GPU_FIXTURE_OK round={} outputs={} bytes={} identity={x}\n", .{ round, N, bytes.len, key.identity });
    }
    try std.fs.cwd().writeFile(.{ .sub_path = args[3], .data = first.? });
}
