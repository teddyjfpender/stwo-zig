//! Owned explicit immutable policy for physical collection and late admission.
//! All values are proposals; only genuine source/classification verifiers close.
const std = @import("std");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Proposal = @import("block_v5_readonly_input_proposal_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Caller = @import("block_v5_caller_readonly_protocol_v1.zig");
const Sources = @import("block_v5_initial_sources_v1.zig");
const Counters = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Staging = @import("block_v5_readonly_input_counter_staging_v2.zig");
pub const Options = struct { selection: Selection.Pins, native: Proposal.Limits = .{}, caller: Caller.Limits = .{}, counter_groups: ?Counters.Options = null, shared_provider_staging: ?Staging.Limits = null };
pub const Owned = struct {
    a: std.mem.Allocator,
    selection: Selection.Owned,
    input: []u8,
    native: []Proposal.Proposal,
    native_count: usize = 0,
    native_limits: Proposal.Limits,
    caller_limits: Caller.Limits,
    plan: ?Plan.Owned = null,
    source: ?Sources.Pins = null,
    readonly_roster_digest: [32]u8 = @splat(0),
    counter_groups: ?Counters.Owned = null,
    counter_staging: ?*Staging.Writer = null,
    /// Stable heap ownership keeps the group sink valid while this value moves
    /// into the original Collected owner. The directory remains caller-owned.
    pub fn initWithStaging(a: std.mem.Allocator, options: Options, input: []const u8, segments: usize, max_metadata_bytes: usize, dir: std.fs.Dir) !Owned {
        const staging_limits = options.shared_provider_staging orelse return init(a, options, input, segments, max_metadata_bytes);
        if (options.counter_groups != null) return error.ConflictingReadonlyCounterCollectors;
        const groups = try std.math.mul(usize, segments, 2);
        const bytes = try Staging.metadataBytes(groups);
        if (bytes > max_metadata_bytes) return error.ReadonlyInputCollectionResourceLimit;
        const writer = try a.create(Staging.Writer);
        errdefer a.destroy(writer);
        writer.* = try Staging.Writer.init(a, dir, options.selection.expected_digest, groups, staging_limits);
        errdefer writer.deinit();
        var internal = options;
        internal.shared_provider_staging = null;
        internal.counter_groups = .{ .limits = staging_limits.counters, .sink = writer.sink() };
        var result = try init(a, internal, input, segments, max_metadata_bytes - bytes);
        result.counter_staging = writer;
        return result;
    }
    pub fn init(a: std.mem.Allocator, options: Options, input: []const u8, segments: usize, max_metadata_bytes: usize) !Owned {
        if (options.shared_provider_staging != null) return error.MissingReadonlyCounterStagingDirectory;
        var metadata = try std.math.add(usize, @sizeOf(Owned), try std.math.add(usize, input.len, try std.math.add(usize, try std.math.mul(usize, segments, @sizeOf(Proposal.Proposal)), try std.math.add(usize, try std.math.mul(usize, options.selection.addresses.len, @sizeOf(u32)), try std.math.mul(usize, try std.math.add(usize, try std.math.mul(usize, options.selection.addresses.len, 2), 1), 2 * @sizeOf(Plan.Interval))))));
        if (options.counter_groups) |groups| metadata = try std.math.add(usize, metadata, try Counters.metadataBytes(try std.math.add(usize, try std.math.mul(usize, options.selection.addresses.len, 2), 1), segments, groups.limits));
        if (segments == 0 or metadata > max_metadata_bytes) return error.ReadonlyInputCollectionResourceLimit;
        var selection = try Selection.admit(a, options.selection, input);
        errdefer selection.deinit();
        const bytes = try a.dupe(u8, input);
        errdefer a.free(bytes);
        const native = try a.alloc(Proposal.Proposal, segments);
        errdefer a.free(native);
        const groups = if (options.counter_groups) |options_groups| try Counters.Owned.init(a, selection.digest, selection.intervals, segments, options_groups) else null;
        return .{ .a = a, .selection = selection, .input = bytes, .native = native, .native_limits = options.native, .caller_limits = options.caller, .counter_groups = groups };
    }
    pub fn deinit(self: *Owned) void {
        if (self.plan) |*plan| plan.deinit();
        if (self.counter_groups) |*groups| groups.deinit();
        if (self.counter_staging) |writer| {
            writer.deinit();
            self.a.destroy(writer);
        }
        self.a.free(self.native);
        self.a.free(self.input);
        self.selection.deinit();
        self.* = undefined;
    }
    pub fn selectionPins(self: *const Owned) Selection.Pins {
        return .{ .authority = self.selection.authority, .addresses = self.selection.addresses, .expected_digest = self.selection.digest, .limits = self.selection.limits };
    }
    pub fn append(self: *Owned, proposal: Proposal.Proposal) !void {
        if (self.plan != null or self.native_count >= self.native.len or proposal.expected.source.index != self.native_count or proposal.expected.source.kind != .native or !std.meta.eql(proposal.expected.selection_digest, self.selection.digest) or !std.meta.eql(proposal.expected.limits, self.native_limits)) return error.StaleReadonlyInputCollection;
        try proposal.require(proposal.expected);
        self.native[self.native_count] = proposal;
        self.native_count += 1;
    }
    pub fn bind(self: *Owned, actual: Sources.Pins) !void {
        if (self.plan != null or self.native_count != self.native.len) return error.IncompleteReadonlyInputCollection;
        try self.selection.authority.requireSource(actual);
        try self.selection.require(self.selectionPins(), self.input);
        var plan = try Plan.derive(self.a, actual, self.input, self.selection.addresses, self.selection.limits);
        errdefer plan.deinit();
        if (plan.intervals.len != self.selection.intervals.len) return error.StaleReadonlyInputSelection;
        for (plan.intervals, self.selection.intervals) |late, early| if (!std.meta.eql(late, early)) return error.StaleReadonlyInputSelection;
        if (self.counter_groups) |*groups| try groups.requirePlan(self.selection.digest, &plan);
        self.plan = plan;
        self.source = actual;
    }
    pub fn authority(self: *const Owned) !Caller.Authority {
        const plan = self.plan orelse return error.IncompleteReadonlyInputCollection;
        return .{ .selection = self.selectionPins(), .plan = .{ .source = self.source orelse return error.IncompleteReadonlyInputCollection, .addresses = self.selection.addresses, .expected_digest = plan.digest, .limits = self.selection.limits }, .input = self.input, .limits = self.caller_limits };
    }
    /// Record the exact independently constructed prechallenge roster.
    pub fn bindRoster(self: *Owned, digest: [32]u8) !void {
        if (self.plan == null or std.mem.allEqual(u8, &digest, 0) or (!std.mem.allEqual(u8, &self.readonly_roster_digest, 0) and !std.meta.eql(self.readonly_roster_digest, digest))) return error.StaleReadonlyInputRoster;
        self.readonly_roster_digest = digest;
    }
    /// Immutable borrowed admission; this owner alone releases the Plan.
    pub fn nativeBinding(self: *const Owned, index: u32) !Proposal.Binding {
        if (index >= self.native_count) return error.StaleReadonlyInputCollection;
        return .{ .plan = if (self.plan) |*plan| plan else return error.IncompleteReadonlyInputCollection, .source_plan_digest = try (self.source orelse return error.IncompleteReadonlyInputCollection).digest(), .expected = self.native[index].expected, .readonly_roster_digest = self.readonly_roster_digest };
    }
};
