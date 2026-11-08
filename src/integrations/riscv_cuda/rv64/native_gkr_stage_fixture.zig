//! Cold qualification of the production implicit-source traversal against a
//! complete CPU GKR batch over the same independent source-IR evaluations.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const V = CPU.rv64_native_gkr_v2;
const S = CPU.rv64_native_gkr_section;
const G = @import("native_gkr_codegen.zig");
const Stage = @import("native_gkr_stage.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub fn run(a: std.mem.Allocator, path: []const u8) !void {
    var artifact = try G.record(a, .{ .origin = .{ .bridge = .keccak } }, .fractions);
    defer artifact.deinit();
    const log = 5;
    const rows = 32;
    const shape = try G.Authority.shape(artifact.descriptor);
    const RawRoster = @FieldType(CPU.rv64_native_gkr_roster.Plan, "roster");
    const Spec = std.meta.Child(@FieldType(RawRoster, "components"));
    var roster = try V.derive(a, &[_]Spec{.{ .origin = G.Source.Frame.originWords(artifact.descriptor.origin), .row_log = log, .terms = artifact.terms }});
    defer roster.deinit();
    var random = std.Random.DefaultPrng.init(0xB121093);
    var semantic: [G.P.count]O = undefined;
    for (&semantic, 0..) |*value, i| value.* = if (i < G.P.local) O.fromBase(M.fromCanonical(random.random().uintLessThan(u32, 65536))) else @import("joined_fixture_support.zig").random(random.random());
    var elements: V.LocalElements = undefined;
    for (&elements.z, &elements.alpha, 0..) |*z, *alpha, i| {
        z.* = semantic[G.P.local + 2 * i];
        alpha.* = semantic[G.P.local + 2 * i + 1];
    }
    var packed_program = artifact.program;
    packed_program.parameters = try a.alloc(O, artifact.parameter_slots.len);
    defer a.free(packed_program.parameters);
    for (packed_program.parameters, artifact.parameter_slots) |*value, slot| value.* = semantic[slot];
    const Column = CPU.rv64_device_pcs.Column;
    var trees: [2][]M = undefined;
    var columns: [2][]Column = undefined;
    var made: usize = 0;
    defer for (0..made) |i| {
        for (columns[i]) |column| a.free(column.coefficients);
        a.free(columns[i]);
        a.free(trees[i]);
    };
    for (&trees, &columns, [2]usize{ shape.fixed, shape.main }) |*tree, *cols, width| {
        tree.* = try a.alloc(M, width * rows);
        errdefer a.free(tree.*);
        cols.* = try a.alloc(Column, width);
        var cc: usize = 0;
        errdefer {
            for (cols.*[0..cc]) |column| a.free(column.coefficients);
            a.free(cols.*);
        }
        for (tree.*) |*value| value.* = M.fromCanonical(random.random().uintLessThan(u32, 65536));
        for (cols.*, 0..) |*column, i| {
            const evaluation = try engine.poly.circle.evaluation.CircleEvaluation.init(core.poly.circle.canonic.CanonicCoset.new(log).circleDomain(), tree.*[i * rows ..][0..rows]);
            const polynomial = try engine.poly.circle.poly.interpolateFromEvaluation(a, evaluation);
            column.* = .{ .log_size = log, .coefficients = polynomial.coeffs };
            cc += 1;
        }
        made += 1;
    }
    const GP = engine.lookups.gkr_prover.ForField(O);
    const ML = engine.lookups.mle;
    const layers = try a.alloc(GP.Layer, roster.instances.len);
    defer a.free(layers);
    const nums = try a.alloc([]M, layers.len);
    defer a.free(nums);
    const dens = try a.alloc([]O, layers.len);
    defer a.free(dens);
    var initialized: usize = 0;
    defer for (0..initialized) |i| {
        a.free(nums[i]);
        a.free(dens[i]);
    };
    for (roster.instances, layers, nums, dens) |instance, *layer, *n, *d| {
        n.* = try a.alloc(M, @intCast(instance.facts()));
        errdefer a.free(n.*);
        d.* = try a.alloc(O, @intCast(instance.facts()));
        initialized += 1;
        @memset(n.*, M.zero());
        @memset(d.*, O.one());
        layer.* = .{ .LogUpMultiplicities = .{ .numerators = try ML.MleFor(O, M).initBorrowed(n.*), .denominators = try ML.MleFor(O, O).initBorrowed(d.*) } };
    }
    const inputs = try a.alloc(O, packed_program.inputs.len);
    defer a.free(inputs);
    for (0..rows) |row| {
        for (inputs, packed_program.inputs) |*value, input| value.* = O.fromBase(trees[input.tree][input.column * rows + core.utils.offsetBitReversedCircleDomainIndex(row, log, log, input.offset)]);
        const output = try packed_program.evaluate(a, inputs);
        defer a.free(output);
        var query: usize = 0;
        for (roster.instances, nums, dens) |instance, n, d| {
            for (0..instance.terms) |lane| {
                const numerator = output[2 * (query + lane)].toM31Array();
                for (numerator[1..]) |word| if (!word.isZero()) return error.NativeGkrNumeratorNotBase;
                n[lane * rows + row] = numerator[0];
                d[lane * rows + row] = output[2 * (query + lane) + 1];
            }
            query += instance.terms;
        }
    }
    var seed = S.RawChannel.init();
    seed.mixU32s(&.{ 1, 2, 3, 0xff010203 });
    var native_channel = seed;
    var reference = try GP.proveBatch(a, &native_channel, layers);
    defer reference.proof.deinit(a);
    defer reference.artifact.deinit(a);
    var service = try @import("pcs_native.zig").Context.init(path, 0, 512 << 20);
    defer service.deinit();
    var stage = try Stage.Context.init(&service, a);
    defer stage.deinit();
    const callbacks = try Stage.Callbacks.load(&service.library, "native_cpu_keccak");
    const scope = S.Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .shared = @splat(4), .ordinal = 0 };
    const request = Stage.Request{ .scope = scope, .roster = &roster, .byte_cap = 512 << 20, .items = &.{.{ .artifact = &artifact, .callbacks = callbacks, .fixed = columns[0], .main = columns[1], .parameters = &semantic }} };
    const allocation_bytes = try Stage.allocationBytes(a, request);
    defer a.free(allocation_bytes);
    var allocation_total: usize = 0;
    for (allocation_bytes) |bytes_| allocation_total += bytes_;
    try std.testing.expectEqual((try Stage.cost(request)).transient_bytes, allocation_total);
    try std.testing.expectEqual(request.items.len + 5, allocation_bytes.len);
    var proof = try stage.numericalProof(a, request, elements, seed);
    defer proof.deinit(a);
    const gpu_section = S.Section{ .salt = O.zero(), .proof = proof };
    const native_section = S.Section{ .salt = O.zero(), .proof = reference.proof };
    const actual = try V.encode(a, &roster, &gpu_section);
    defer a.free(actual);
    const expected = try V.encode(a, &roster, &native_section);
    defer a.free(expected);
    try std.testing.expectEqualSlices(u32, expected, actual);
    const GV = engine.lookups.gkr_verifier.ForField(O);
    var channel = seed;
    const gates = try a.alloc(GV.Gate, roster.instances.len);
    defer a.free(gates);
    @memset(gates, .LogUp);
    var artifact_gpu = try GV.partiallyVerifyBatch(a, gates, &proof, &channel);
    defer artifact_gpu.deinit(a);
    try std.testing.expectEqualSlices(u8, &native_channel.inner.digest, &channel.inner.digest);
    try std.testing.expectEqual(native_channel.inner.n_draws, channel.inner.n_draws);
    try std.testing.expectEqualSlices(O, reference.artifact.ood_point, artifact_gpu.ood_point);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(actual), &digest, .{});
    std.debug.print("NATIVE_GKR_SOURCE_BATCH cpu_bridge_keccak=true groups={} facts={} proof_words={} byte_exact=true channel_exact=true row_point_exact=true sha256={s}\n", .{ roster.instances.len, roster.gkrFacts(), actual.len, std.fmt.bytesToHex(digest, .lower) });
}
test "actual CPU implicit source full production GPU traversal matches complete CPU proof" {
    const a = std.testing.allocator;
    const library = std.process.getEnvVarOwned(a, "STWO_NATIVE_GKR_SOURCE_LIBRARY") catch return error.SkipZigTest;
    defer a.free(library);
    try run(a, library);
}
