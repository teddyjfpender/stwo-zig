//! Explicit truth geometry, separate from CPU's <=128-query frame. The current
//! GKR engine materializes row×query facts; admission MUST precede allocation.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
pub const Role = enum { keccak, chi, xor5, product, linear, bytes };
pub const Instance = struct {
    role: Role,
    row_log: u32,
    queries: u32,
    keccak_policy: A.crypto.keccak.equations.BatchPolicy = .triple_v2,
    byte_policy: A.crypto.secp256k1.layout.BytePolicy = .local,
    pub fn laneLog(self: @This()) !u32 {
        if (self.queries == 0 or self.queries > 2048) return error.InvalidTruthGkrQueries;
        return @intCast(std.math.log2_int_ceil(u32, self.queries));
    }
    pub fn variables(self: @This()) !u32 {
        const n = try std.math.add(u32, self.row_log, try self.laneLog());
        if (self.row_log < 5 or self.row_log > 22 or n > 30) return error.InvalidTruthGkrGeometry;
        const mass = try std.math.mul(u64, @as(u64, 1) << @intCast(self.row_log), self.queries);
        if (mass >= core.fields.m31.Modulus) return error.TruthGkrMassExceeded;
        return n;
    }
    pub fn rows(self: @This()) !usize {
        _ = try self.variables();
        return @as(usize, 1) << @intCast(self.row_log);
    }
    pub fn facts(self: @This()) !usize {
        return @as(usize, 1) << @intCast(try self.variables());
    }
};
pub fn forSource(source: *const R.TruthSource) ![3]Instance {
    return switch (source.*) {
        .keccak => |s| .{ .{ .role = .keccak, .row_log = s.permutation.log_size, .queries = @intCast(s.permutation.policy.lookups()), .keccak_policy = s.permutation.policy }, .{ .role = .chi, .row_log = s.chi.log_size, .queries = 1, .keccak_policy = s.permutation.policy }, .{ .role = .xor5, .row_log = s.xor5.log_size, .queries = 1, .keccak_policy = s.permutation.policy } },
        .secp => |s| .{ .{ .role = .product, .row_log = s.batch.product.log_size, .queries = @intCast(A.crypto.secp256k1.layout.byteCountFor(.product, s.batch.product.byte_policy)), .byte_policy = s.batch.product.byte_policy }, .{ .role = .linear, .row_log = s.batch.linear.log_size, .queries = @intCast(A.crypto.secp256k1.layout.byteCountFor(.linear, s.batch.linear.byte_policy)), .byte_policy = s.batch.linear.byte_policy }, .{ .role = .bytes, .row_log = 8, .queries = 1 } },
        else => return error.GkrV3ServiceUnsupported,
    };
}
pub const Plan = struct {
    input_bytes: usize = 0,
    core_owned_bytes: usize = 0,
    binding_bytes: usize = 0,
    peak_bytes: usize = 0,
    /// Explicit conservative current-engine contract: 36 input bytes/fact,
    /// cloned36 +upper-layer64 bytes/fact; binding includes16witness+10aux M31
    /// columns. Existing MAIN/PCS owners need separate coordinator leases.
    pub fn admit(instances: []const Instance, limit: usize) !Plan {
        if (limit == 0) return error.MissingTruthGkrBudget;
        var p = Plan{};
        for (instances) |instance| {
            const facts = try instance.facts();
            const rows = try instance.rows();
            p.input_bytes = try std.math.add(usize, p.input_bytes, try std.math.mul(usize, facts, 36));
            p.core_owned_bytes = try std.math.add(usize, p.core_owned_bytes, try std.math.mul(usize, facts, 100));
            p.binding_bytes = try std.math.add(usize, p.binding_bytes, try std.math.mul(usize, rows, 104));
        }
        p.peak_bytes = @max(try std.math.add(usize, p.input_bytes, p.core_owned_bytes), try std.math.add(usize, p.input_bytes, p.binding_bytes));
        if (p.peak_bytes > limit) return error.TruthGkrBudgetExceeded;
        return p;
    }
};
