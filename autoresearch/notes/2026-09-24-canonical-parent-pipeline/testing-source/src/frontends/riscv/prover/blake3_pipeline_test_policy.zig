const std = @import("std");
// Local qualification authority. Production callers supply their sealed policy;
// the shared scheduler validates its own CPU and memory reservations regardless.
pub const Policy = struct {
    total_cpu_tokens: usize,
    cpu_tokens_per_node: usize,
    proof_worker_count: usize,
    total_rss_bytes: usize,
    rss_bytes_per_node: usize,
    pub fn validate(self: *const Policy) !void {
        if (self.total_cpu_tokens == 0 or self.total_cpu_tokens > try std.Thread.getCpuCount() or
            self.cpu_tokens_per_node == 0 or self.cpu_tokens_per_node > self.total_cpu_tokens or
            self.proof_worker_count == 0 or self.proof_worker_count > self.cpu_tokens_per_node or
            self.total_rss_bytes == 0 or self.rss_bytes_per_node == 0 or
            self.rss_bytes_per_node > self.total_rss_bytes) return error.InvalidTestPolicy;
    }
    pub fn engineWorkerCount(self: *const Policy) !usize {
        try self.validate();
        return self.proof_worker_count;
    }
};
