//! Inactive typed coverage planner. This is NOT physical bus closure or a proof
//! verifier. Current per-batch FS challenges cannot be mixed across contexts.
//! A new protocol must seal the complete two-phase participant commitment
//! manifest, draw shared typed challenges, namespace RAM/clocks by owner, and
//! authenticate every counter/claim before this metadata can route real proofs.
const std = @import("std");
const C = @import("rv64_ethereum_chip_plan.zig");
const core = @import("stwo_core");
const Digest = @import("stwo_riscv_frontend").rv64_air.memory.values.Digest;
pub const State = struct { pc: u64, registers: [32]u64, ram: Digest };
pub const Namespace = struct { profile: [32]u8, epoch: u64 };
pub const CpuIdentity = struct { namespace: Namespace, index: u32 };
pub const ChipIdentity = struct { profile: [32]u8, chip: C.Chip, log: u5 };
pub const ClaimTag = struct { namespace: Namespace, key: ChipIdentity, instance: u32 };
pub const Context = struct {
    id: CpuIdentity,
    first_step: u64,
    steps: u32,
    initial: State,
    final: State,
    counts: C.Counts,
    first_ids: C.FirstIds,
};
pub const Expected = struct {
    epoch: u64,
    first_cpu_index: u32,
    first_step: u64,
    instructions: u64,
    initial: State,
    final: State,
    first_ids: C.FirstIds,
};
pub const RequestFamily = enum { division_operands, multiplication_operands, load_store, keccak_call, secp_add_call, secp_double_call, alu_word16, binary_word16, shift_word16 };
pub const RequestNamespace = struct { scope: Namespace, family: RequestFamily };
pub const Link = struct { owner: CpuIdentity, request: RequestNamespace, provider: u32, tag: ClaimTag, first_id: u32, requests: u32 };
fn family(chip: C.Chip) RequestFamily {
    return switch (chip) {
        .alu => .alu_word16,
        .binary => .binary_word16,
        .shift => .shift_word16,
        .division => .division_operands,
        .multiplication => .multiplication_operands,
        .load_store => .load_store,
        .keccak, .keccak_bridge => .keccak_call,
        .add_product, .add_linear, .add_bridge => .secp_add_call,
        .double_product, .double_linear, .double_bridge => .secp_double_call,
    };
}
pub const MAX_LINKS = 2 * C.MAX_INSTANCES * C.CHIP_COUNT;
pub const Coverage = struct {
    allocator: std.mem.Allocator,
    // Aggregate sparse provider packing only. Actual CPU spans are contexts,
    // which can contain partial interiors; do not dispatch packing.cpu().
    packing: C.Plan,
    expected: Expected,
    contexts: []Context,
    links: []Link,
    pub const physical_bus_closed = false;
    pub fn init(a: std.mem.Allocator, profile: C.Profile, semantics: [32]u8, expected: Expected, contexts: []const Context) !Coverage {
        const identity = try profile.identity(semantics);
        const counts = try validateContexts(profile, identity, expected, contexts);
        var packing = try C.Plan.init(a, profile, semantics, expected.first_step, expected.instructions, counts, expected.first_ids);
        errdefer packing.deinit();
        if (contexts.len + packing.instances.len > C.MAX_INSTANCES) return error.ChipInstanceLimit;
        const owned = try a.dupe(Context, contexts);
        errdefer a.free(owned);
        var out = Coverage{ .allocator = a, .packing = packing, .expected = expected, .contexts = owned, .links = &.{} };
        var list: std.ArrayList(Link) = .empty;
        defer list.deinit(a);
        var sink = LinkSink{ .allocator = a, .output = &list };
        try out.walkLinks(&sink);
        out.links = try list.toOwnedSlice(a);
        return out;
    }
    pub fn deinit(self: *Coverage) void {
        self.allocator.free(self.links);
        self.allocator.free(self.contexts);
        self.packing.deinit();
        self.* = undefined;
    }
    pub fn namespace(self: *const Coverage) Namespace {
        return .{ .profile = self.packing.profile_identity, .epoch = self.expected.epoch };
    }
    pub fn providerTag(self: *const Coverage, index: usize) !ClaimTag {
        if (index >= self.packing.instances.len) return error.InvalidChipClaimTag;
        const v = self.packing.instances[index];
        return .{ .namespace = self.namespace(), .key = .{ .profile = self.packing.profile_identity, .chip = v.chip, .log = v.log }, .instance = v.index };
    }
    /// Framing only. It rejects cross-epoch/profile/role/instance claim labels;
    /// it does not accept a field value, verify a proof or derive FS challenges.
    pub fn checkProviderClaimTag(self: *const Coverage, index: usize, actual: ClaimTag) !void {
        if (!std.meta.eql(try self.providerTag(index), actual)) return error.InvalidChipClaimTag;
    }
    /// Use actual fixed CPU contexts, including partial interior instances;
    /// packing.cpu_instances is only the aggregate lower-bound row model.
    pub fn cpuDomainRows(self: *const Coverage) !u64 {
        try self.validate();
        return std.math.mul(u64, self.contexts.len, @as(u64, 1) << self.packing.profile.cpu_log);
    }
    /// The row query count comes from the independently expected immutable
    /// opcode/state/control Plan, never from a producer's free mass claim.
    pub fn admitMass(self: *const Coverage, expected_cpu_queries_per_row: u32, other_byte_queries: u64) !u64 {
        const cpu_queries = try std.math.mul(u64, try self.cpuDomainRows(), expected_cpu_queries_per_row);
        return self.packing.admitMass(try std.math.add(u64, cpu_queries, other_byte_queries));
    }
    pub fn validate(self: *const Coverage) !void {
        try self.packing.validate();
        const actual = try validateContexts(self.packing.profile, self.packing.profile_identity, self.expected, self.contexts);
        if (!std.meta.eql(actual, self.packing.counts) or !std.meta.eql(self.expected.first_ids, self.packing.first_ids) or self.expected.first_step != self.packing.first_step or self.expected.instructions != self.packing.instructions or self.contexts.len + self.packing.instances.len > C.MAX_INSTANCES or self.links.len > MAX_LINKS) return error.InvalidChipCoverage;
        var sink = LinkSink{ .expected = self.links };
        try self.walkLinks(&sink);
        if (sink.index != self.links.len) return error.InvalidChipCoverage;
    }
    /// Receiver/controller supplies expected identity/endpoints separately.
    /// Self-consistent producer metadata alone is not an expected continuation.
    pub fn validateAgainst(self: *const Coverage, profile: C.Profile, semantics: [32]u8, expected: Expected) !void {
        if (!std.meta.eql(self.packing.profile, profile) or !std.mem.eql(u8, &self.packing.semantic_identity, &semantics) or !std.meta.eql(self.expected, expected)) return error.InvalidChipCoverage;
        try self.validate();
    }
    fn walkLinks(self: *const Coverage, sink: *LinkSink) !void {
        var provider: usize = 0;
        for (0..C.CHIP_COUNT) |kind| {
            const chip: C.Chip = @enumFromInt(kind);
            for (self.contexts) |context| {
                var left = C.countFor(context.counts, chip);
                var next = C.firstFor(context.first_ids, chip);
                while (left != 0) {
                    if (provider >= self.packing.instances.len) return error.InvalidChipCoverage;
                    const instance = self.packing.instances[provider];
                    if (instance.chip != chip or next < instance.first_id or @as(u64, next) >= @as(u64, instance.first_id) + instance.requests) return error.InvalidChipCoverage;
                    const take = @min(left, instance.first_id + instance.requests - next);
                    try sink.emit(.{ .owner = context.id, .request = .{ .scope = self.namespace(), .family = family(chip) }, .provider = @intCast(provider), .tag = try self.providerTag(provider), .first_id = next, .requests = take });
                    next += take;
                    left -= take;
                    if (next == instance.first_id + instance.requests) provider += 1;
                }
            }
            if (provider < self.packing.instances.len and self.packing.instances[provider].chip == chip) return error.InvalidChipCoverage;
        }
        if (provider != self.packing.instances.len) return error.InvalidChipCoverage;
    }
};
const LinkSink = struct {
    allocator: ?std.mem.Allocator = null,
    output: ?*std.ArrayList(Link) = null,
    expected: []const Link = &.{},
    index: usize = 0,
    fn emit(self: *LinkSink, value: Link) !void {
        if (value.requests == 0 or self.index >= MAX_LINKS) return error.InvalidChipCoverage;
        if (self.output) |list| try list.append(self.allocator.?, value) else if (self.index >= self.expected.len or !std.meta.eql(self.expected[self.index], value)) return error.InvalidChipCoverage;
        self.index += 1;
    }
};
fn validateState(state: State) !void {
    if (state.pc & 3 != 0 or state.registers[0] != 0) return error.InvalidChipCoverage;
    for (state.ram) |limb| if (limb >= core.fields.m31.Modulus) return error.InvalidChipCoverage;
}
fn validateContexts(profile: C.Profile, identity: [32]u8, expected: Expected, contexts: []const Context) !C.Counts {
    if (contexts.len == 0 or contexts.len > C.MAX_INSTANCES or expected.instructions == 0 or expected.first_step > std.math.maxInt(u64) - expected.instructions or expected.first_cpu_index >= core.fields.m31.Modulus or contexts.len - 1 >= core.fields.m31.Modulus - expected.first_cpu_index) return error.InvalidChipCoverage;
    try validateState(expected.initial);
    try validateState(expected.final);
    var first = expected.first_step;
    var state = expected.initial;
    var ids = expected.first_ids;
    var total = C.Counts{};
    for (contexts, 0..) |context, index| {
        if (!std.mem.eql(u8, &context.id.namespace.profile, &identity)) return error.InvalidChipProfile;
        if (context.id.namespace.epoch != expected.epoch or context.id.index != expected.first_cpu_index + index or context.first_step != first or context.steps == 0 or context.steps > try profile.cpuCapacity() or first > std.math.maxInt(u64) - @as(u64, context.steps) or !std.meta.eql(context.initial, state) or C.requestCount(context.counts) > context.steps or !std.meta.eql(context.first_ids, ids)) return error.InvalidChipCoverage;
        try validateState(context.final);
        inline for (.{ "division", "multiplication", "load_store", "keccak", "add", "double", "alu", "binary", "shift" }) |field| {
            const count = @field(context.counts, field);
            try C.validateSpan(@field(ids, field), count);
            @field(total, field) = try std.math.add(u32, @field(total, field), count);
            @field(ids, field) += count;
        }
        first += context.steps;
        state = context.final;
    }
    if (first != expected.first_step + expected.instructions or !std.meta.eql(state, expected.final)) return error.InvalidChipCoverage;
    return total;
}
