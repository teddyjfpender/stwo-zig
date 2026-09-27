//! Explicit, pinned sequential batch sharing one bounded workspace.
const std = @import("std");
const producer = @import("recursive_segment_v2_detached_parent_producer.zig");

pub const MAX_REQUESTS = 64;
pub const Input = struct {
    version: u32,
    session_byte_budget: usize,
    pcs_plan_byte_budget: usize = 256 * 1024 * 1024,
    retained_scratch_byte_limit: usize,
    requests: []const []const []const u8,
};
pub const Admitted = struct {
    parsed: std.json.Parsed(Input),
    pub fn deinit(self: *Admitted) void {
        self.parsed.deinit();
    }
};
pub fn admit(allocator: std.mem.Allocator, path: []const u8, pin_text: []const u8) !Admitted {
    var pin: [32]u8 = undefined;
    if (pin_text.len != 64) return error.InvalidParentBatchPin;
    _ = try std.fmt.hexToBytes(&pin, pin_text);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 20);
    defer allocator.free(bytes);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (!std.meta.eql(pin, actual)) return error.ParentBatchPinMismatch;
    const parsed = try std.json.parseFromSlice(Input, allocator, bytes, .{ .allocate = .alloc_always });
    errdefer parsed.deinit();
    if (parsed.value.version != 1 or parsed.value.requests.len == 0 or parsed.value.requests.len > MAX_REQUESTS or
        parsed.value.session_byte_budget == 0 or parsed.value.session_byte_budget > 256 * 1024 * 1024 or
        parsed.value.retained_scratch_byte_limit > 512 * 1024 * 1024 or parsed.value.pcs_plan_byte_budget > 512 * 1024 * 1024) return error.InvalidParentBatchLimits;
    for (parsed.value.requests, 0..) |request, index| {
        const args = try producer.parseArguments(request);
        if (args.parent_key == null) return error.ParentBatchRequiresAdmittedKey;
        for (parsed.value.requests[0..index]) |previous| {
            const prior = try producer.parseArguments(previous);
            if (std.mem.eql(u8, args.output, prior.output)) return error.DuplicateParentBatchOutput;
        }
    }
    return .{ .parsed = parsed };
}
pub const Report = struct {
    allocator: std.mem.Allocator,
    reports: []producer.CandidateReportV1,
    plan_builds: usize,
    pcs_plan_builds: usize,
    pcs_plan_hits: usize,
    pcs_plan_retained_bytes: usize,
    requests: usize,
    retained_scratch_bytes: usize,
    elapsed_ns: u64,
    pub fn deinit(self: *Report) void {
        self.allocator.free(self.reports);
    }
};
pub fn run(comptime Engine: type, allocator: std.mem.Allocator, input: *const Admitted) !Report {
    var timer = try std.time.Timer.start();
    var workspace = producer.WorkspaceFor(Engine).init(allocator, input.parsed.value.session_byte_budget, input.parsed.value.retained_scratch_byte_limit);
    defer workspace.deinit();
    workspace.pcs_plans.byte_budget = input.parsed.value.pcs_plan_byte_budget;
    const reports = try allocator.alloc(producer.CandidateReportV1, input.parsed.value.requests.len);
    errdefer allocator.free(reports);
    for (input.parsed.value.requests, reports) |request, *report| {
        report.* = try producer.runWithWorkspace(Engine, allocator, try producer.parseArguments(request), &workspace);
    }
    return .{ .allocator = allocator, .reports = reports, .plan_builds = workspace.plan_builds, .pcs_plan_builds = workspace.pcs_plans.builds, .pcs_plan_hits = workspace.pcs_plans.hits, .pcs_plan_retained_bytes = workspace.pcs_plans.retained_bytes, .requests = workspace.requests, .retained_scratch_bytes = workspace.scratch.queryCapacity(), .elapsed_ns = timer.read() };
}
