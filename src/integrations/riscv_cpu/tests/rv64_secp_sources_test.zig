const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Sources = @import("../rv64_secp_sources.zig");
const S = Sources.S;
const F = @import("../crypto/secp_bridge_fixture.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
fn challenges() Sources.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x53534f55, 37 });
    const bytes = channel.drawSecureFelt();
    const ram = @import("stwo_riscv_frontend").rv64_air.relations.Challenges.draw(&channel);
    return Sources.Challenges.draw(&channel, bytes, ram);
}
fn run(a: std.mem.Allocator) !void {
    const kind: Sources.Kind = .add;
    const calls = try F.makeCallsWithFormat(a, S.program.get(kind), 3, .little_endian_words_v2);
    defer a.free(calls);
    const geometry = try Sources.Geometry.minimal(kind, 3);
    var materials = try Sources.Materials.init(a, kind, geometry);
    defer materials.deinit();
    var trace = try Sources.Trace.initPrepared(a, &materials, calls, 1, .little_endian_words_v2);
    defer trace.deinit();
    try std.testing.expect(trace.product.fixed.ptr == materials.product_fixed.ptr and trace.linear.fixed.ptr == materials.linear_fixed.ptr and trace.bridge.fixed.ptr == materials.bridge_fixed.ptr);
    try std.testing.expect(!trace.product.owns_fixed and !trace.linear.owns_fixed and !trace.bridge.owns_fixed);
    const inputs = try a.alloc(S.trace.Input, calls.len);
    defer a.free(inputs);
    for (calls, inputs) |call, *input| {
        input.coordinates = @splat(0);
        for (input.coordinates[0..6], 0..) |*coordinate, c| {
            for (0..4) |lane| coordinate.* |= @as(u256, call.before[4 * c + lane]) << @as(u8, @intCast(64 * lane));
        }
    }
    var reference = try S.batch.Batch.initWithLogs(a, &S.program.add, inputs, 1, geometry.product_log, geometry.linear_log);
    defer reference.deinit();
    try std.testing.expectEqualSlices(M, reference.product.main, trace.product.main);
    try std.testing.expectEqualSlices(M, reference.linear.main, trace.linear.main);
    var mass: u64 = 0;
    for (trace.byte_counts) |count| mass += count;
    try std.testing.expectEqual((try geometry.validate(kind, 3, 1)).byte_queries, mass);
}
test "projective source preparation borrows immutable matrices and cleans every allocation" {
    try run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, run, .{});
}
test "projective source interaction publication is atomic and main lifetime is explicit" {
    const a = std.testing.allocator;
    const calls = try F.makeCallsWithFormat(a, &S.program.add, 3, .little_endian_words_v2);
    defer a.free(calls);
    const geometry = try Sources.Geometry.minimal(.add, 3);
    var materials = try Sources.Materials.init(a, .add, geometry);
    defer materials.deinit();
    var trace = try Sources.Trace.initPrepared(a, &materials, calls, 1, .little_endian_words_v2);
    defer trace.deinit();
    var columns: [Sources.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
    var at: usize = 0;
    try std.testing.expectError(error.InvalidSecpSourcePhase, trace.appendInteraction(&columns, &at));
    try std.testing.expectError(error.InvalidSecpSourcePhase, trace.releaseMetadata());
    var wrong = challenges();
    wrong.call.offset = Q.zero();
    wrong.call.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, trace.generate(wrong));
    try std.testing.expect(trace.claims == null);
    try std.testing.expectEqual(@as(usize, 0), trace.product.interaction.len);
    try std.testing.expectEqual(@as(usize, 0), trace.linear.interaction.len);
    try std.testing.expectEqual(@as(usize, 0), trace.bridge.interaction.len);
    const claims = try trace.generate(challenges());
    try claims.validateCanonical();
    try trace.appendInteraction(&columns, &at);
    try std.testing.expectEqual(columns.len, at);
    try trace.releaseMain();
    var main: [Sources.MAIN]engine.pcs.ColumnEvaluation = undefined;
    at = 0;
    try std.testing.expectError(error.InvalidSecpSourcePhase, trace.appendMain(&main, &at));
    try std.testing.expect(materials.product_fixed.len != 0);
}
test "projective sources preserve independent logs and exact global component offsets" {
    const a = std.testing.allocator;
    const geometry = Sources.Geometry{ .product_log = 8, .linear_log = 7, .bridge_log = 6 };
    const mass = try geometry.validate(.add, 3, 37);
    try std.testing.expectEqual(@as(u64, 284 * 256 + 128 * 128 + 42 * 64), mass.byte_queries);
    try std.testing.expectEqual(@as(u64, 48), mass.product_identities);
    const components = try Sources.Components.init(.add, geometry, 3, 37, .little_endian_words_v2, .{ .fixed = 5, .main = 7, .interaction = 11 }, challenges(), .{ .product = Q.zero(), .linear = Q.zero(), .bridge = Q.zero() });
    try components.product.validate();
    try components.linear.validate();
    try components.bridge.validate();
    try std.testing.expectEqual(@as(usize, 5 + 30), components.bridge.offsets.fixed);
    try std.testing.expectEqual(@as(usize, 7 + 319), components.linear.offsets.main);
    try std.testing.expectEqual(@as(usize, 11 + 384 + 176), components.bridge.offsets.interaction);
    const logs = try a.alloc(u32, Sources.MAIN + 3);
    defer a.free(logs);
    @memset(logs, 0);
    var at: usize = 3;
    try geometry.appendLogs(logs, &at, 1);
    try std.testing.expectEqual(logs.len, at);
    try std.testing.expectEqual(@as(u32, 8), logs[3]);
    try std.testing.expectEqual(@as(u32, 7), logs[3 + 319]);
    try std.testing.expectEqual(@as(u32, 6), logs[3 + 319 + 200]);
    var fixed: [Sources.FIXED]engine.pcs.ColumnEvaluation = undefined;
    var material = try Sources.Materials.init(a, .add, geometry);
    defer material.deinit();
    at = 0;
    try material.appendFixed(&fixed, &at);
    try std.testing.expectEqual(fixed.len, at);
}
fn metadataArenaRun(a: std.mem.Allocator) !void {
    const calls = try F.makeCallsWithFormat(a, &S.program.add, 3, .little_endian_words_v2);
    defer a.free(calls);
    const geometry = try Sources.Geometry.minimal(.add, 3);
    var materials = try Sources.Materials.init(a, .add, geometry);
    defer materials.deinit();
    var original = try Sources.Trace.initPrepared(a, &materials, calls, 1, .little_endian_words_v2);
    defer original.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var released = try Sources.Trace.initPreparedWithMainAllocator(a, arena.allocator(), &materials, calls, 1, .little_endian_words_v2);
    defer released.deinit();
    _ = try released.takeMain();
    arena.deinit();
    owns_arena = false;
    const ch = challenges();
    const l = try original.generate(ch);
    const r = try released.generate(ch);
    try std.testing.expect(l.product.eql(r.product) and l.linear.eql(r.linear) and l.bridge.eql(r.bridge));
    try std.testing.expectEqualSlices(M, original.product.interaction, released.product.interaction);
    try std.testing.expectEqualSlices(M, original.linear.interaction, released.linear.interaction);
    try std.testing.expectEqualSlices(M, original.bridge.interaction, released.bridge.interaction);
    try std.testing.expectEqual(@as(usize, 0), released.product.lookup_bytes.len);
    try std.testing.expectEqual(@as(usize, 0), released.linear.lookup_bytes.len);
    try std.testing.expectEqual(@as(usize, 0), released.bridge.metadata.len);
}
test "projective metadata generates identical interactions after the entire main arena dies" {
    try metadataArenaRun(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, metadataArenaRun, .{});
}
test "projective packed lookup packets match all original byte and typed wire inputs" {
    const a = std.testing.allocator;
    for ([_]Sources.Kind{ .add, .double }) |kind| {
        const p = S.program.get(kind);
        const calls = try F.makeCallsWithFormat(a, p, 3, .little_endian_words_v2);
        defer a.free(calls);
        const geometry = try Sources.Geometry.minimal(kind, 3);
        var trace = try Sources.Trace.init(a, kind, calls, 1, .little_endian_words_v2, geometry);
        defer trace.deinit();
        for ([_]*const S.trace.Trace{ &trace.product, &trace.linear }) |part| {
            const n = part.size();
            const width = S.layout.main(part.kind);
            var original: [319]Q = undefined;
            var packed_values: [319]Q = undefined;
            for (0..n) |logical| {
                const physical = @import("stwo_riscv_frontend").rv64_air.witness.physical(logical, part.log_size);
                var fixed: [S.layout.FIXED]Q = undefined;
                for (&fixed, 0..) |*v, c| v.* = Q.fromBase(part.fixed[c * n + physical]);
                for (original[0..width], 0..) |*v, c| v.* = Q.fromBase(part.main[c * n + physical]);
                try part.metadataRow(logical, packed_values[0..width]);
                for (0..S.layout.byteCount(part.kind)) |i| try std.testing.expect(S.equations.byte(part.kind, original[0..width], i).eql(S.equations.byte(part.kind, packed_values[0..width], i)));
                const left = S.equations.Row{ .fixed = &fixed, .main = original[0..width] };
                const right = S.equations.Row{ .fixed = &fixed, .main = packed_values[0..width] };
                for (0..3) |event| {
                    const lt = S.equations.wireTuple(part.kind, p, left, event);
                    const rt = S.equations.wireTuple(part.kind, p, right, event);
                    for (lt, rt) |x, y| try std.testing.expect(x.eql(y));
                    try std.testing.expect(S.equations.wireCoefficient(left, event).eql(S.equations.wireCoefficient(right, event)));
                }
            }
        }
        const n = trace.bridge.size();
        for (0..n) |logical| {
            const row = try trace.bridge.metadataRow(logical);
            const physical = @import("stwo_riscv_frontend").rv64_air.witness.physical(logical, trace.bridge.log_size);
            for (row, 0..) |v, c| try std.testing.expect(v.eql(trace.bridge.main[c * n + physical]));
        }
    }
}
