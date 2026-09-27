//! Durable PUBLIC proposal transport. Admission always requires independent
//! expected job fields; file hashes, JSON metadata and window sums are not proof.
const std = @import("std");
const Job = @import("../recursion/block_v5_global_expected_public_job_v1.zig");
const Windows = @import("block_v5_register_windows_v1.zig");
const Export = @import("../recursion/block_v5_global_public_export_policy_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const FILE = "block-v5-global-expected-public-v1.json";
pub const Limits = struct { job: Job.Limits = .{}, max_file_bytes: usize = 128 << 20, max_owned_bytes: usize = 256 << 20 };
pub const Pin = struct { byte_len: u64, sha256: [32]u8 };
pub const Wire = struct {
    format: []const u8 = "B5EP/public/v1",
    version: u32 = Job.VERSION,
    coverage_digest: [32]u8,
    seal_digest: [32]u8,
    recipe: u32,
    input_words: []const u32,
    windows: []const Job.Window,
    register_version: u32,
    initial_registers: [32]u32,
    final_registers: [32]u32,
    pub fn fromExpected(expected: Job.Expected) Wire {
        return .{ .coverage_digest = expected.coverage_digest, .seal_digest = expected.seal_digest, .recipe = expected.recipe, .input_words = expected.input_words, .windows = expected.windows, .register_version = expected.register_plan.version, .initial_registers = expected.register_plan.initial_registers, .final_registers = expected.register_plan.final_registers };
    }
};
pub const Owned = struct {
    parent: std.mem.Allocator,
    parent_owner: ?*Budget = null,
    budget: *Budget,
    parsed: std.json.Parsed(Wire),
    windows: []Windows.Window,
    pin: Pin,
    limits: Limits,
    references: std.atomic.Value(usize) = .init(1),
    pub const complete_block_authority = false;
    pub fn deinit(self: *Owned) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        self.budget.allocator().free(self.windows);
        self.parsed.deinit();
        const parent = self.parent;
        const budget = self.budget;
        const parent_owner = self.parent_owner;
        self.* = undefined;
        parent.destroy(self);
        budget.destroy();
        if (parent_owner) |owner| owner.destroy();
    }
    /// Caller already holds a live reference. Every successful retain requires
    /// one release; this is an explicit contract, not language move checking.
    pub fn retain(self: *Owned) !*Owned {
        var previous = self.references.load(.acquire);
        while (true) {
            if (previous == 0 or previous == std.math.maxInt(usize)) return error.ExpectedPublicOwnerReferenceLimit;
            if (self.references.cmpxchgWeak(previous, previous + 1, .acq_rel, .acquire)) |observed| previous = observed else return self;
        }
    }
    pub fn expected(self: *const Owned) Job.Expected {
        const wire = self.parsed.value;
        return .{ .coverage_digest = wire.coverage_digest, .seal_digest = wire.seal_digest, .recipe = wire.recipe, .input_words = wire.input_words, .windows = wire.windows, .register_plan = .{ .version = wire.register_version, .initial_registers = wire.initial_registers, .final_registers = wire.final_registers, .windows = self.windows } };
    }
    pub fn validate(self: *const Owned, independently_expected: Job.Expected) !void {
        if (!std.mem.eql(u8, self.parsed.value.format, "B5EP/public/v1") or self.parsed.value.version != Job.VERSION) return error.InvalidExpectedPublicFormat;
        try self.expected().requireEqual(independently_expected, self.limits.job);
    }
    pub fn bind(self: *const Owned, original: Export.Policy) !Export.Policy {
        if (!std.mem.eql(u8, self.parsed.value.format, "B5EP/public/v1") or self.parsed.value.version != Job.VERSION) return error.InvalidExpectedPublicFormat;
        return self.expected().bind(original, self.limits.job);
    }
};
/// Count before allocating. The immutable input vector occurs exactly once in
/// the wire; windows contain only headers/registers/roots/output/public spans.
pub fn encode(a: std.mem.Allocator, expected: Job.Expected, limits: Limits) ![]u8 {
    try expected.validate(limits.job);
    if (limits.max_file_bytes == 0 or limits.max_owned_bytes == 0) return error.ExpectedPublicJobResourceLimit;
    const wire = Wire.fromExpected(expected);
    var count = @import("block_v5_cpu_counting_writer_v1.zig").Counting.init(limits.max_file_bytes);
    std.json.Stringify.value(wire, .{}, &count.writer) catch |failure| {
        if (count.exceeded) return error.ExpectedPublicJobResourceLimit;
        return failure;
    };
    const raw = try a.alloc(u8, count.count);
    errdefer a.free(raw);
    var writer = std.Io.Writer.fixed(raw);
    try std.json.Stringify.value(wire, .{}, &writer);
    if (writer.buffered().len != count.count) return error.ChangedExpectedPublicSerialization;
    return raw;
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, expected: Job.Expected, limits: Limits) !Pin {
    const raw = try encode(a, expected, limits);
    defer a.free(raw);
    try Files.publish(dir, FILE, raw);
    return .{ .byte_len = raw.len, .sha256 = Files.hash(raw) };
}
/// The Pin validates storage only. ALL independently expected public data is
/// checked before a decoded owner can be used to rebuild verifier admission.
pub fn decode(a: std.mem.Allocator, raw: []const u8, pin: Pin, independently_expected: Job.Expected, limits: Limits) !*Owned {
    try independently_expected.validate(limits.job);
    if (limits.max_file_bytes == 0 or limits.max_owned_bytes == 0 or raw.len == 0 or raw.len > limits.max_file_bytes) return error.ExpectedPublicJobResourceLimit;
    if (raw.len != pin.byte_len or !std.meta.eql(Files.hash(raw), pin.sha256)) return error.TamperedExpectedPublicFile;
    const parent_owner = Budget.fromAllocator(a);
    if (parent_owner) |owner| _ = owner.retain();
    errdefer if (parent_owner) |owner| owner.destroy();
    const budget = try Budget.create(a, limits.max_owned_bytes);
    errdefer budget.destroy();
    const bounded = budget.allocator();
    var parsed = try std.json.parseFromSlice(Wire, bounded, raw, .{ .allocate = .alloc_always, .ignore_unknown_fields = false, .max_value_len = limits.max_file_bytes });
    errdefer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.format, "B5EP/public/v1") or parsed.value.version != Job.VERSION) return error.InvalidExpectedPublicFormat;
    if (parsed.value.windows.len == 0 or parsed.value.windows.len > limits.job.max_windows or parsed.value.input_words.len > limits.job.max_input_words) return error.ExpectedPublicJobResourceLimit;
    const windows = try bounded.alloc(Windows.Window, parsed.value.windows.len);
    errdefer bounded.free(windows);
    for (windows, parsed.value.windows, 0..) |*window, stored, index| {
        var data = stored.data.publicData(parsed.value.input_words);
        window.* = Windows.Window.fromPublic(@intCast(index), stored.first_cycle, &data);
    }
    const owner = try a.create(Owned);
    errdefer a.destroy(owner);
    owner.* = .{ .parent = a, .parent_owner = parent_owner, .budget = budget, .parsed = parsed, .windows = windows, .pin = pin, .limits = limits };
    try owner.validate(independently_expected);
    return owner;
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, pin: Pin, independently_expected: Job.Expected, limits: Limits) !*Owned {
    const raw = try Files.readPinned(a, dir, FILE, pin.byte_len, pin.sha256, limits.max_file_bytes);
    defer a.free(raw);
    return decode(a, raw, pin, independently_expected, limits);
}
