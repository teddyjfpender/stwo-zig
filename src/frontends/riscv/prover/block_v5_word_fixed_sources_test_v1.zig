//! Original native graph/transcript routing only; no private witness, capture,
//! admitted owner or proof is synthesized. Typed production bodies are retained.
const std = @import("std");
const core = @import("stwo_core");
const Word = @import("../recursion/block_v5_word_recursive_fixed_v1.zig");
const Equation = @import("../recursion/air/block_v5_word_recursive_shape_composition_v1.zig");
const Transcript = @import("../recursion/block_v5_word_recursive_fixed_transcript_v1.zig");
const Sources = @import("../recursion/air/block_v5_recursive_parent_fixed_sources_v1.zig");
const Deep = @import("../recursion/air/pcs_deep_circuit.zig");
const Fri = @import("../recursion/air/fri_verifier_circuit.zig");
const Plan = @import("../recursion/air/blake3_transcript_plan.zig").Plan;
const Roots = @import("../recursion/air/blake3_root_sources.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Private = @import("../recursion/air/blake3_private_word.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Roster = @import("../recursion/block_v5_recursive_parent_fixed_roster_v1.zig");
const Assembly = @import("../recursion/block_v5_recursive_parent_fixed_assembly_v1.zig");
const Pcs = @import("../recursion/block_v5_native_recursive_fixed_pcs_v1.zig");
fn RoutingProfile(comptime family: Equation.Family) type {
    const Shape = Word.ForFamily(family).Shape;
    return struct {
        const Self = @This();
        pub const commitment_trees = 4;
        shape: *const Shape,
        columns: [4][]const u32,
        widths: []const u32,
        config: core.pcs.PcsConfig,
        lifting_log: u32,
        seal: [32]u8,
        fn init(shape: *const Shape) Self {
            var columns: [4][]const u32 = undefined;
            for (shape.columns, &columns) |logs, *out| out.* = logs;
            return .{ .shape = shape, .columns = columns, .widths = shape.widths, .config = shape.config, .lifting_log = shape.lifting_log, .seal = shape.seal };
        }
        pub fn validate(self: *const Self) !void {
            try self.shape.validateAgainst(self.shape.row_log, self.shape.config);
            if (!std.meta.eql(self.config, self.shape.config) or !std.meta.eql(self.seal, self.shape.seal) or self.lifting_log != self.shape.lifting_log) return error.InvalidTestRoutingProfile;
            for (self.columns, self.shape.columns) |actual, expected| if (actual.ptr != expected.ptr or actual.len != expected.len) return error.InvalidTestRoutingProfile;
            if (self.widths.ptr != self.shape.widths.ptr or self.widths.len != self.shape.widths.len) return error.InvalidTestRoutingProfile;
        }
        pub fn deepProfile(self: *const Self) Deep.Profile {
            return self.shape.deepProfile();
        }
        pub fn friProfile(self: *const Self) Fri.Profile {
            return self.shape.friProfile();
        }
    };
}
fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 1) };
}
fn parity(comptime family: Equation.Family) !void {
    @setEvalBranchQuota(20_000);
    const a = std.testing.allocator;
    const Shape = Word.ForFamily(family).Shape;
    const shape = try Shape.init(a, if (family == .ram_lanes) 5 else 16, try config(), .{});
    defer shape.deinit();
    var composition = try Equation.ForFamily(family).compile(a, shape);
    defer composition.deinit();
    var dg = try Deep.build(a, shape.deepProfile());
    defer dg.deinit();
    var fg = try Fri.build(a, shape.friProfile());
    defer fg.deinit();
    var plan = try Transcript.ForFamily(family).recordForShape(a, shape, 1, .{});
    defer plan.deinit();
    const actual = try Sources.Owned.compileNativeWord(a, shape, &composition, &dg, &fg, &plan);
    defer actual.deinit();
    const cold = try Sources.Owned.compileNativeWord(a, shape, &composition, &dg, &fg, &plan);
    defer cold.deinit();
    inline for (.{ "challenges", "claims", "samples", "terminal", "payload_bytes", "roots" }) |name| {
        inline for (.{ 12, 11, 10, 2, 9 }) |slot| try std.testing.expectEqualDeep(try @field(cold, name).metadata(slot), try @field(actual, name).metadata(slot));
    }
    // The native equation's public inputs and first two roots must have NO
    // private producer. They are closed by independently supplied public ports.
    try std.testing.expectEqual(@as(usize, 0), (try actual.roots.metadata(2)).len);
    inline for (.{ 12, 11, 10, 2, 9 }) |slot| try std.testing.expectEqual(@as(usize, 0), (try actual.claims.metadata(slot)).len);
    const words = try actual.roots.metadata(9);
    try std.testing.expectEqual(@as(usize, 8 * (2 + shape.widths.len) + 2), words.len);
    var cursor: usize = 0;
    var root_index: usize = 2;
    for (plan.fixed.root_reads) |receipt| if (receipt.source.circuit == Roots.CIRCUIT) {
        try std.testing.expectEqualDeep(try Roots.caller(root_index), receipt.source);
        for (receipt.uses, 0..) |reads, coordinate| {
            const row = try Private.logicalRow(receipt.source.circuit, receipt.source.first_wire + @as(u32, @intCast(coordinate)), reads + 1, 0);
            try std.testing.expectEqualDeep(Storage.compactFixed(Private, row), words[cursor]);
            cursor += 1;
        }
        root_index += 1;
    };
    for (words[0..cursor]) |row| try std.testing.expect(row[2].toU32() >= 16);
    // Original two-phase nonce read multiplicities remain exact, not defaults.
    var nonce_reads: [2]u32 = @splat(0);
    for (plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == 4_100_001) {
        for (&nonce_reads, receipt.uses) |*total, uses| total.* += uses;
    };
    for (nonce_reads, 0..) |reads, coordinate| {
        const row = try Private.logicalRow(4_100_001, @intCast(2 + coordinate), reads, 0);
        try std.testing.expectEqualDeep(Storage.compactFixed(Private, row), words[cursor + coordinate]);
    }
    try std.testing.expect((try actual.samples.metadata(11)).len != 0);
    try std.testing.expect((try actual.challenges.metadata(12)).len != 0);
    try std.testing.expect((try actual.terminal.metadata(10)).len != 0);
    // Exercise the real full original append/fusion/partition kernel with
    // independent actual native graph, transcript and PCS routing outputs.
    var profile = RoutingProfile(family).init(shape);
    const pcs = try Pcs.ForCommitments(4).Owned.compile(a, &profile, &dg, &fg, &plan);
    defer pcs.deinit();
    var arithmetic = try Assembly.Arithmetic.init(a, .{ composition.circuit.graph(), dg.graph(), fg.graph() });
    defer arithmetic.deinit();
    const selectors = try Assembly.selectorsForGraphs(a, &dg, &fg);
    const fixed = try Roster.compileOriginalRoster(a, actual, null, pcs.openings, pcs.ports, &plan, &pcs.paths, &arithmetic, selectors, &dg);
    defer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
    const logs = try @import("../recursion/blake3_parent_fixed_key_v1.zig").rowLogs(fixed);
    inline for (0..Storage.Airs.len) |i| {
        try std.testing.expect(logs[i] >= 1);
        try std.testing.expect(fixed[i].len <= @as(usize, 1) << @intCast(logs[i]));
    }
    const hash = plan.fixed.hash_metadata.?;
    var hash_count: usize = 0;
    inline for (@import("../recursion/air/blake3_g_partition.zig").SHARDS) |slot| hash_count += fixed[slot].len;
    try std.testing.expectEqual(hash.g_rows.len + pcs.paths.metadata.g_rows.len, hash_count);
    try std.testing.expectEqual(hash.xor_rows.len + pcs.paths.metadata.xor_rows.len, fixed[1].len);
    try std.testing.expectEqual(arithmetic.fused.fixed[1].len, fixed[3].len);
    try std.testing.expectEqual(arithmetic.fused.fixed[2].len, fixed[4].len);
    try std.testing.expectEqual(arithmetic.fused.fixed[3].len, fixed[5].len);
    try std.testing.expect(fixed[18].len + fixed[19].len != 0);
}
test "word fixed sources: native RAM private root and sample suppliers preserve external public ports" {
    try parity(.ram_lanes);
}
test "word fixed sources: native range16 original 52-pair draw and terminal suppliers" {
    try parity(.range16);
}
fn allocation(a: std.mem.Allocator, shape: *const Word.ForFamily(.ram_lanes).Shape, composition: *const Equation.ForFamily(.ram_lanes).Compiled, dg: *const Deep.Circuit, fg: *const Fri.Circuit, plan: *const Plan) !void {
    const rows = try Sources.Owned.compileNativeWord(a, shape, composition, dg, fg, plan);
    defer rows.deinit();
}
test "word fixed sources: original arena and retained owner release through every allocation failure" {
    const a = std.testing.allocator;
    const Shape = Word.ForFamily(.ram_lanes).Shape;
    const shape = try Shape.init(a, 5, try config(), .{});
    defer shape.deinit();
    var composition = try Equation.ForFamily(.ram_lanes).compile(a, shape);
    defer composition.deinit();
    var dg = try Deep.build(a, shape.deepProfile());
    defer dg.deinit();
    var fg = try Fri.build(a, shape.friProfile());
    defer fg.deinit();
    var plan = try Transcript.ForFamily(.ram_lanes).recordForShape(a, shape, 1, .{});
    defer plan.deinit();
    try std.testing.checkAllAllocationFailures(a, allocation, .{ shape, &composition, &dg, &fg, &plan });
    const budget = try Budget.create(a, 32 << 20);
    const rows = Sources.Owned.compileNativeWord(budget.allocator(), shape, &composition, &dg, &fg, &plan) catch |err| {
        budget.destroy();
        return err;
    };
    budget.destroy();
    defer rows.deinit();
    try rows.roots.finish();
    try rows.samples.finish();
}
