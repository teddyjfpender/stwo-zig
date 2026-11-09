//! Experimental source-only dot topology. Caller supplies independently derived
//! whole-graph use counts; witness data never chooses IDs, resets or fanout.
const std = @import("std");
const Core = @import("stwo_core");
const Row = @import("row.zig");
const M = Core.fields.m31.M31;
pub const Term = struct { weight: [2]u32, scalar: u32 };
pub const Call = struct { terms: []const Term, outputs: [2]u32 };
pub const Source = struct {
    allocator: std.mem.Allocator,
    fixed: [][Row.FIXED]M,
    raw_rows: usize,
    calls: usize,
    logical_terms: usize,
    identity: [32]u8,
    pub fn deinit(self: *Source) void {
        self.allocator.free(self.fixed);
        self.* = undefined;
    }
    pub fn compile(a: std.mem.Allocator, calls: []const Call, uses: []const u32) !Source {
        if (calls.len == 0 or uses.len == 0 or uses.len >= Core.fields.m31.Modulus) return error.InvalidNativeDotSource;
        var mass: u64 = 0;
        for (uses) |use| {
            if (use >= Core.fields.m31.Modulus) return error.NativeDotCharacteristic;
            mass = try std.math.add(u64, mass, use);
        }
        if (mass >= Core.fields.m31.Modulus) return error.NativeDotCharacteristic;
        var raw_rows: usize = 0;
        var logical_terms: usize = 0;
        for (calls, 0..) |call, index| {
            for (call.outputs) |id| if (id == 0 or id >= uses.len) return error.InvalidNativeDotOutput;
            if (call.outputs[0] == call.outputs[1]) return error.InvalidNativeDotOutput;
            for (calls[0..index]) |prior| for (prior.outputs) |id| if (id == call.outputs[0] or id == call.outputs[1]) return error.DuplicateNativeDotProducer;
            const first_output = @min(call.outputs[0], call.outputs[1]);
            for (call.terms) |term| for ([_]u32{ term.weight[0], term.weight[1], term.scalar }) |id| {
                if (id >= first_output or id >= uses.len) return error.CyclicNativeDotSource;
            };
            // Empty dots have one explicit zero-weight/zero-scalar row and two
            // fresh zero outputs. No free or unconstrained output shortcut.
            raw_rows = try std.math.add(usize, raw_rows, @max(1, call.terms.len));
            logical_terms = try std.math.add(usize, logical_terms, call.terms.len);
        }
        if (raw_rows >= Core.fields.m31.Modulus / 3) return error.NativeDotCharacteristic;
        const rows = try std.math.ceilPowerOfTwo(usize, @max(16, raw_rows));
        const fixed = try a.alloc([Row.FIXED]M, rows);
        errdefer a.free(fixed);
        @memset(fixed, @splat(M.zero()));
        var at: usize = 0;
        for (calls) |call| {
            const count = @max(1, call.terms.len);
            for (0..count) |i| {
                const term = if (call.terms.len == 0) Term{ .weight = .{ 0, 0 }, .scalar = 0 } else call.terms[i];
                const f = &fixed[at];
                f[0] = M.fromCanonical(term.weight[0]);
                f[1] = M.fromCanonical(term.weight[1]);
                f[2] = M.fromCanonical(term.scalar);
                f[Row.ENABLED] = M.one();
                f[Row.FIRST] = M.fromCanonical(@intFromBool(i == 0));
                f[Row.LAST] = M.fromCanonical(@intFromBool(i + 1 == count));
                if (i + 1 == count) for (call.outputs, 0..) |id, j| {
                    f[Row.OUTPUT_IDS + j] = M.fromCanonical(id);
                    f[Row.OUTPUT_USES + j] = M.fromCanonical(uses[id]);
                };
                at += 1;
            }
        }
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("opstack/experimental-native-dot/source-v1/17main10fixed24inter/base-scalar6tuple/reset-last");
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, @intCast(calls.len), .little);
        hash.update(&bytes);
        std.mem.writeInt(u64, &bytes, @intCast(logical_terms), .little);
        hash.update(&bytes);
        for (fixed) |row| for (row) |v| {
            std.mem.writeInt(u32, bytes[0..4], v.v, .little);
            hash.update(bytes[0..4]);
        };
        return .{ .allocator = a, .fixed = fixed, .raw_rows = raw_rows, .logical_terms = logical_terms, .calls = calls.len, .identity = hash.finalResult() };
    }
};
