//! Prover-only storage policy. It changes no columns, roots, transcript or AIR.
//! Coefficients remain owned by the original commitment and query openings
//! reconstruct bounded column batches rather than retaining the entire LDE.
const std = @import("std");
const core = @import("stwo_core");
pub const Policy = union(enum) {
    resident,
    coefficients: struct { minimum_trace_log: u32 = 18 },
    pub fn validate(self: Policy) !void {
        switch (self) {
            .resident => {},
            .coefficients => |value| if (value.minimum_trace_log < 1 or value.minimum_trace_log > 24) return error.InvalidV7InputStorage,
        }
    }
    pub fn minimumCommitmentLog(self: Policy, config: core.pcs.PcsConfig) !?u32 {
        try self.validate();
        return switch (self) {
            .resident => null,
            .coefficients => |value| blk: {
                const log = try std.math.add(u32, value.minimum_trace_log, config.fri_config.log_blowup_factor);
                if (log > 30) return error.InvalidV7InputStorage;
                break :blk log;
            },
        };
    }
    pub fn selected(self: Policy, raw_log: u32) !bool {
        try self.validate();
        return switch (self) {
            .resident => false,
            .coefficients => |value| raw_log >= value.minimum_trace_log,
        };
    }
};
