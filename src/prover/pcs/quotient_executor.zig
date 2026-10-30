//! Explicit proof-owned numerical DEEP executor. This changes computation,
//! never the transcript, commitments, samples, or verifier. No fallback exists:
//! a requested executor error aborts the proof. The owner must outlive proving.
const std = @import("std");
const Provider = @import("quotients/lazy_provider.zig").LazyQuotientProvider;
const Column = @import("../secure_column.zig").SecureColumnByCoords;

pub const Executor = struct {
    pub const RawInputs = RawInputBackend;
    context: *anyopaque,
    run: *const fn (*anyopaque, std.mem.Allocator, *Provider, *Column) anyerror!void,

    pub fn execute(self: *const Executor, allocator: std.mem.Allocator, provider: *Provider, output: *Column) !void {
        if (output.len() != provider.domain_size) return error.ShapeMismatch;
        try self.run(self.context, allocator, provider, output);
        // Existing logical CPU/Metal work receipts cannot attest a different
        // implementation. Its device/transfer receipt is owned by the executor.
        if (provider.work_recorder) |work| work.markIncomplete();
    }
};

/// Raw sources and exact original sample/line plans, without CPU row folding.
pub const RawInputBackend = struct {
    pub const rawQuotientInputs = true;
    pub const supportsCompactQuotientInputs = true;
    pub const preservesRawCoefficientInputs = true;
};
