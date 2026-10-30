//! Independently reconstructed policy for the experimental one-cohort B8
//! original proof. No source-provided key, digest or successful host admission
//! confers proof authority. Every component and physical claim must be checked.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v7_execution_receiver_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v7_program_image_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Descriptor = @import("block_v8_endpoint_source_descriptor_v1.zig").Descriptor;
const Native = @import("block_v8_native_endpoint_closure_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
const MemoryLayout = @import("block_v7_window_memory_joint_layout_v1.zig").Layout;
const Memory = @import("block_v7_window_memory_joint_protocol_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const LookupLayout = @import("block_v7_lookup_compact_layout_v1.zig").Layout;
const LookupPlan = @import("block_v5_native_lookup_plan_v1.zig");
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Input = struct {
    shape: *const @import("../air/statement.zig").Blake3ExecutionStatement,
    frame: @import("../air/block/memory_event.zig").Frame,
    endpoint_count: u32,
    native_roots: [4][32]u8,
    program_plan: @import("block_v5_program_table_v1.zig").Plan,
    program_roots: [2][32]u8,
    lookup_plan: LookupPlan.Plan,
    lookup_layout: LookupLayout,
    lookup_roots: [2][32]u8,
    memory_geometry: []const Geometry.Claim,
    memory_roots: [2][32]u8,
    memory_interval_log: u32,
};
pub const Limits = struct {
    initial: Initial.Limits = .{},
    max_endpoints: u32 = 1 << 24,
    memory_layout: @import("block_v7_window_memory_joint_layout_v1.zig").Limits = .{},
};
/// Shape, source metadata, snapshots and their owned arrays must outlive this
/// scope. The receiver supplies canonical independently decoded metadata, not
/// any producer-side admission object. Initialization/image are owned here.
pub const Owned = struct {
    allocator: std.mem.Allocator,
    initialized: Initial.Owned,
    image: Image.Owned,
    policy: Policy.Policy,
    descriptor: Descriptor,
    memory_layout: MemoryLayout,
    entries: [4]Epoch.Entry,
    epoch: Epoch.Epoch,
    pub fn init(a: std.mem.Allocator, trusted: Original.Trusted, input: Input, limits: Limits) !*Owned {
        if (trusted.window == null) return error.UnsupportedEndpointTerminalContinuation;
        if (input.endpoint_count == 0) return error.UnsupportedEmptyEndpointCohort;
        if (input.endpoint_count > limits.max_endpoints) return error.EndpointWholeResourceLimit;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.allocator = a;
        self.initialized = try Original.deriveInitialization(a, trusted, limits.initial);
        errdefer self.initialized.deinit();
        self.image = try Image.Owned.init(a, trusted.elf, &self.initialized, limits.initial);
        errdefer self.image.deinit();
        self.policy = .{ .initialized = &self.initialized, .program_root = self.image.root.bytes, .terminal = trusted.terminal, .config = trusted.config, .window = trusted.window };
        const native_policy = @import("block_v8_ram_endpoint_kernel_v1.zig").Policy{
            .source_ordinal = 0,
            .max_local_clock = try Native.maxLocalClock(input.shape.public_data.clock),
        };
        self.descriptor = try Descriptor.deriveWithHalt(a, input.shape, trusted.profile, input.frame, native_policy, input.endpoint_count, input.native_roots, .{ .halt_address = self.initialized.info.halt_flag });
        try self.policy.validateWindows(&.{.{ .shape = input.shape, .frame = input.frame, .external_retirements = 0 }});
        if (!std.meta.eql(input.shape.public_data.program_root, self.image.root)) return error.UntrustedEndpointNativeProgram;
        // Geometry census is compressed endpoint events, never logical native
        // RAM traffic. The local native/endpoint relation proves the latter.
        try Geometry.admitSequence(input.memory_geometry, input.endpoint_count);
        const coarse = try native_policy.globalClock();
        for (input.memory_geometry) |part| {
            if (part.first.clock != coarse or part.last.clock != coarse or
                (if (part.preceding) |prior| prior.clock != coarse else false))
                return error.UntrustedEndpointCoarseClock;
        }
        self.memory_layout = try MemoryLayout.init(a, input.memory_geometry, input.memory_interval_log, limits.memory_layout);
        errdefer self.memory_layout.deinit();
        if (!std.meta.eql(input.program_plan.program_root, self.image.root) or input.program_plan.leaves.len != self.image.leaves.len)
            return error.UntrustedEndpointProgramImage;
        for (input.program_plan.leaves, self.image.leaves) |got, expected| if (!std.meta.eql(got, expected))
            return error.UntrustedEndpointProgramImage;
        var demand = try LookupPlan.nativeDemand(input.shape, 0);
        const byte_pairs = try std.math.mul(u64, input.endpoint_count, 4);
        demand[@intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8)] =
            try std.math.add(u64, demand[@intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8)], byte_pairs);
        const expected_lookup = LookupPlan.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        if (!std.meta.eql(expected_lookup, input.lookup_plan)) return error.UntrustedEndpointLookupDemand;
        self.entries = .{
            try self.descriptor.entry(),                                                       try ROM.firstEntry(input.program_plan, input.program_roots),
            try Lookup.firstEntry(input.lookup_plan, input.lookup_layout, input.lookup_roots), try Memory.entry(self.policy, &self.memory_layout, input.memory_roots),
        };
        var counts: Epoch.Counts = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family)] += 1;
        self.epoch = try Epoch.Epoch.init(try self.policy.digest(), trusted.config, counts, &self.entries, self.entries.len);
        try self.epoch.requireCompleteFamilies();
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.memory_layout.deinit();
        self.image.deinit();
        self.initialized.deinit();
        a.destroy(self);
    }
    pub fn programPolicy(self: *const Owned, input: Input) ROM.Policy {
        return .{ .plan = input.program_plan, .expected_program_root = self.image.root, .roots = input.program_roots, .epoch = self.epoch, .entries = &self.entries };
    }
    pub fn lookupPolicy(self: *const Owned, input: Input) Lookup.Policy {
        return .{ .plan = input.lookup_plan, .layout = input.lookup_layout, .roots = input.lookup_roots, .epoch = self.epoch, .entries = &self.entries };
    }
    /// New proof transcript boundary, deliberately separate from old union
    /// framing even though original provider equations/draw order are reused.
    pub fn beginProofChannel(self: *const Owned, drawn: Epoch.Drawn) core.proof_suites.Blake3.Channel {
        var channel = drawn.channel;
        self.recordAfterDraws(&channel);
        return channel;
    }
    /// One framing authority for original verification and symbolic recursive
    /// transcript recording. The epoch channel continues; it is NOT reset.
    pub fn recordAfterDraws(self: *const Owned, channel: anytype) void {
        channel.mixU32s(&.{ 0x42384557, 1, 13 });
        channel.mixRoot(self.epoch.digest);
        channel.mixRoot(self.descriptor.scope.native_identity);
    }
};
