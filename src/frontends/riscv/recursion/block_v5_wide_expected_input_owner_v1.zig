//! One immutable expected input root per independently admitted public job.
//! This is public policy custody, not an in-circuit B5PD/input-link receipt.
const std = @import("std");
const File = @import("../prover/block_v5_global_expected_public_file_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const VERSION: u32 = 1;
pub const Expected = struct { root: [32]u8, word_count: u32 };
/// Canonical word order/length framing is independent of host byte order.
/// Only a trusted whole-job caller derives this; proof files do not choose it.
pub fn derive(words: []const u32) !Expected {
    const count = std.math.cast(u32, words.len) orelse return error.WideInputResourceLimit;
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo-zig/block-v5/expected-public-input-root/v1\x00");
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, words.len, .little);
    hash.update(&length);
    var buffer: [1024]u8 = undefined;
    var cursor: usize = 0;
    while (cursor < words.len) {
        const take = @min(buffer.len / 4, words.len - cursor);
        for (words[cursor..][0..take], 0..) |word, index| std.mem.writeInt(u32, buffer[4 * index ..][0..4], word, .little);
        hash.update(buffer[0 .. 4 * take]);
        cursor += take;
    }
    var root: [32]u8 = undefined;
    hash.final(&root);
    return .{ .root = root, .word_count = count };
}
pub const Owned = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    job: *File.Owned,
    cached: Expected,
    references: std.atomic.Value(usize) = .init(1),
    pub const complete_source_authority = false;
    pub const input_digest_link_proved = false;
    /// The immutable parsed input is borrowed from job; the owner computes its
    /// expected root ONCE. Keep the independent Expected returned by derive/
    /// expectation in verifier policy; do not replace it with a received root.
    pub fn init(a: std.mem.Allocator, job: *File.Owned) !*Owned {
        const cached = try derive(job.expected().input_words);
        const lease = Budget.fromAllocator(a);
        if (lease) |owner| _ = owner.retain();
        errdefer if (lease) |owner| owner.destroy();
        const retained = try job.retain();
        errdefer retained.deinit();
        const self = try a.create(Owned);
        self.* = .{ .allocator = a, .allocation_owner = lease, .job = retained, .cached = cached };
        return self;
    }
    pub fn expectation(self: *const Owned) Expected {
        return self.cached;
    }
    /// policy is independently held. It is not recomputed from this mutable
    /// object during validation; input storage has an explicit immutable lease.
    pub fn require(self: *const Owned, policy: Expected) !void {
        if (self.references.load(.acquire) == 0 or !std.meta.eql(self.cached, policy) or policy.word_count != self.job.expected().input_words.len) return error.UntrustedWideExpectedInput;
    }
    pub fn retain(self: *Owned) !*Owned {
        var before = self.references.load(.acquire);
        while (true) {
            if (before == 0 or before == std.math.maxInt(usize)) return error.WideInputReferenceLimit;
            if (self.references.cmpxchgWeak(before, before + 1, .acq_rel, .acquire)) |observed| before = observed else return self;
        }
    }
    pub fn deinit(self: *Owned) void {
        const before = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(before != 0);
        if (before != 1) return;
        const a = self.allocator;
        const lease = self.allocation_owner;
        self.job.deinit();
        a.destroy(self);
        if (lease) |owner| owner.destroy();
    }
};
