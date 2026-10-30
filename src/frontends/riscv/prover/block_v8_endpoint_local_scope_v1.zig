//! A source-local execution theorem, deliberately without global RAM admission.
//! The receiver pins ELF/security/total cohorts. CPU boundaries are public
//! claims; a later global coordinator must link them and close RAM endpoints.
const std = @import("std");
const core = @import("stwo_core");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Descriptor = @import("block_v8_endpoint_source_descriptor_v1.zig").Descriptor;
const Kernel = @import("block_v8_ram_endpoint_kernel_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Sparse = @import("block_v8_sparse_rom_v1.zig");
const SparseROM = @import("block_v8_sparse_rom_provider_v1.zig");
pub const RomFlavor = enum { legacy_complete, sparse_elf };
pub const SPARSE_TAG: u32 = 0x42385343;
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42384c43;
pub const production_active = false;
pub const Trusted = struct {
    elf: []const u8,
    elf_sha256: [32]u8,
    profile: @import("../runner/elf_loader.zig").ExecutionProfile,
    config: core.pcs.PcsConfig,
    cohort_count: u32,
    terminal_cycle: ?u32 = null,
    boundary_policy_id: [32]u8 = @splat(0),
};
pub const Input = struct {
    rom_flavor: RomFlavor = .legacy_complete,
    native_profile: @import("block_v8_native_endpoint_profile_v1.zig").Profile = .endpoint_v2,
    sparse_support: []const Sparse.Entry = &.{},
    shape: *const @import("../air/statement.zig").Blake3ExecutionStatement,
    frame: @import("../air/block/memory_event.zig").Frame,
    cohort_ordinal: u32,
    endpoint_count: u32,
    native_roots: [4][32]u8,
    program_plan: @import("block_v5_program_table_v1.zig").Plan,
    program_roots: [2][32]u8,
    lookup_plan: LP.Plan,
    lookup_layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout,
    lookup_roots: [2][32]u8,
};
/// Public identifiers after a fresh local original verifies. This plain value
/// is NOT a receipt capability and must not substitute for original checking.
/// The late bridge uses the SAME endpoint main root under a new global draw;
/// its result must still close against independently proved global memory.
pub const Source = struct {
    local_epoch: [32]u8,
    local_identity: [32]u8,
    endpoint_root: [32]u8,
    endpoint_count: u32,
    policy: Kernel.Policy,
    frame: @FieldType(Input, "frame"),
};
pub const Limits = struct { initial: Initial.Limits = .{}, max_endpoints: u32 = 1 << 24, max_cohorts: u32 = 1 << 20 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    image: Image.Owned,
    owns_image: bool,
    descriptor: Descriptor,
    entries: [3]Epoch.Entry,
    epoch: Epoch.Epoch,
    cohort_count: u32,
    rom_flavor: RomFlavor,
    native_profile: @import("block_v8_native_endpoint_profile_v1.zig").Profile,
    sparse_rom: ?Sparse.Owned,
    pub fn init(a: std.mem.Allocator, trusted: Trusted, input: Input, limits: Limits) !*Owned {
        var image = try Image.Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.initial);
        errdefer image.deinit();
        const self = try initWithProgram(a, trusted, input, &image, limits);
        self.owns_image = true;
        return self;
    }
    /// Prover-local immutable reuse only. Fresh receivers always call init,
    /// rebuilding the program from their own independently pinned ELF bytes.
    /// The supplied owner must outlive this borrowed scope.
    pub fn initWithProgram(a: std.mem.Allocator, trusted: Trusted, input: Input, image: *const Image.Owned, limits: Limits) !*Owned {
        if (trusted.config.lifting_log_size != null) return error.UnsupportedEndpointLocalLifting;
        if (!std.meta.eql(image.elf_sha256, trusted.elf_sha256) or image.info.execution_profile != trusted.profile) return error.UntrustedEndpointLocalProgram;
        if (trusted.cohort_count == 0 or trusted.cohort_count > @min(limits.max_cohorts, 1 << 20) or input.cohort_ordinal >= trusted.cohort_count or input.endpoint_count == 0 or input.endpoint_count > limits.max_endpoints)
            return error.InvalidEndpointLocalCohort;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.allocator = a;
        self.rom_flavor = input.rom_flavor;
        self.native_profile = input.native_profile;
        self.sparse_rom = null;
        errdefer if (self.sparse_rom) |*plan| plan.deinit();
        self.cohort_count = trusted.cohort_count;
        self.image = image.*;
        self.owns_image = false;
        const data = &input.shape.public_data;
        try input.shape.validateBlake3ExecutionWithExternal(0);
        if (input.shape.localZeroCustody() or data.initial_rw_root != null or data.final_rw_root != null or data.io_entries.input_len != 0 or data.io_entries.input_words.len != 0 or data.io_entries.output_len != 0 or data.io_entries.output_words.len != 0)
            return error.UnsupportedEndpointLocalBoundary;
        const completion = data.completion orelse return error.MissingCompletion;
        const halt = try haltFor(trusted, input.shape, input.frame, self.image.info.halt_flag);
        _ = completion;
        const root = data.program_root orelse return error.MissingProgramRoot;
        if (!std.meta.eql(root, self.image.root)) return error.UntrustedEndpointLocalProgram;
        const Windows = @import("block_v5_register_windows_v1.zig");
        const window = Windows.Window.fromPublic(0, 1, data.*);
        try (Windows.Plan{ .initial_registers = data.initial_regs, .final_registers = data.final_regs, .windows = &.{window} }).validate();
        const policy = Kernel.Policy{ .source_ordinal = input.cohort_ordinal, .max_local_clock = try @import("block_v8_native_endpoint_closure_v1.zig").maxLocalClock(data.clock) };
        if (try policy.globalClock() > 4 * @as(u64, trusted.cohort_count) - 1) return error.InvalidEndpointLocalCohort;
        self.descriptor = try Descriptor.deriveWithNativeProfile(a, input.shape, trusted.profile, input.frame, policy, input.endpoint_count, input.native_roots, halt, input.native_profile);
        if (input.rom_flavor == .legacy_complete) {
            if (input.sparse_support.len != 0 or !std.meta.eql(input.program_plan.program_root, self.image.root) or input.program_plan.leaves.len != self.image.leaves.len) return error.UntrustedEndpointLocalProgram;
            for (input.program_plan.leaves, self.image.leaves) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedEndpointLocalProgram;
        } else {
            if (input.program_plan.leaves.len != 0 or input.program_plan.multiplicities.len != 0 or !std.meta.eql(input.program_plan.program_root, self.image.root)) return error.UntrustedSparseLocalDescriptor;
            self.sparse_rom = try Sparse.Owned.fromImage(a, .{ .elf = trusted.elf, .elf_sha256 = trusted.elf_sha256, .profile = trusted.profile, .program_root = self.image.root, .expected_fetches = input.program_plan.expected_fetches }, input.sparse_support, image, .{ .initial = limits.initial });
            if (input.program_plan.log_size != self.sparse_rom.?.log_size) return error.UntrustedSparseLocalDescriptor;
        }
        var demand = try @import("block_v8_native_endpoint_profile_v1.zig").nativeDemand(input.shape, input.native_profile);
        const byte_index = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8);
        demand[byte_index] = try std.math.add(u64, demand[byte_index], try std.math.mul(u64, input.endpoint_count, 4));
        if (demand[byte_index] >= core.fields.m31.Modulus) return error.EndpointLocalLookupOverflow;
        const expected = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        if (!std.meta.eql(expected, input.lookup_plan)) return error.UntrustedEndpointLocalLookup;
        self.entries = .{
            // Epoch slots are local (one native entry). The descriptor identity
            // independently binds the actual global cohort ordinal and clock.
            try Epoch.Entry.init(.native, 0, self.descriptor.scope.native_identity, &input.native_roots),
            if (input.rom_flavor == .legacy_complete) try ROM.firstEntry(input.program_plan, input.program_roots) else try SparseROM.firstEntry(&self.sparse_rom.?, input.program_roots),
            try Lookup.firstEntry(input.lookup_plan, input.lookup_layout, input.lookup_roots),
        };
        var statement = core.proof_suites.Blake3.Channel{};
        statement.mixU32s(&.{ if (input.rom_flavor == .legacy_complete) TAG else SPARSE_TAG, VERSION, 11, trusted.cohort_count, input.cohort_ordinal, @intFromEnum(trusted.profile) });
        if (input.native_profile.isDirect()) statement.mixU32s(&.{ 0x52434c33, @intFromEnum(input.native_profile) });
        statement.mixRoot(trusted.elf_sha256);
        statement.mixRoot(self.descriptor.scope.native_identity);
        trusted.config.mixInto(&statement);
        var counts: Epoch.Counts = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family)] += 1;
        self.epoch = try Epoch.Epoch.init(statement.digestBytes(), trusted.config, counts, &self.entries, 3);
        // Intentionally do NOT requireCompleteFamilies: this is a new local
        // theorem with deferred RAM, never a disguised complete V7 original.
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        if (self.sparse_rom) |*plan| plan.deinit();
        if (self.owns_image) self.image.deinit();
        a.destroy(self);
    }
    pub fn source(self: *const Owned) Source {
        return .{ .local_epoch = self.epoch.digest, .local_identity = self.descriptor.scope.native_identity, .endpoint_root = self.descriptor.roots[2], .endpoint_count = self.descriptor.scope.endpoint_count, .policy = self.descriptor.scope.policy, .frame = self.descriptor.frame };
    }
    pub fn programPolicy(self: *const Owned, input: Input) ROM.Policy {
        return .{ .plan = input.program_plan, .expected_program_root = self.image.root, .roots = input.program_roots, .epoch = self.epoch, .entries = &self.entries };
    }
    pub fn sparseProgramPolicy(self: *const Owned, input: Input) SparseROM.Policy {
        return .{ .plan = &self.sparse_rom.?, .roots = input.program_roots, .epoch = self.epoch, .entries = &self.entries };
    }
    pub fn lookupPolicy(self: *const Owned, input: Input) Lookup.Policy {
        return .{ .plan = input.lookup_plan, .layout = input.lookup_layout, .roots = input.lookup_roots, .epoch = self.epoch, .entries = &self.entries };
    }
    pub fn recordAfterDraws(self: *const Owned, ch: anytype) void {
        ch.mixU32s(&.{ if (self.rom_flavor == .legacy_complete) TAG else SPARSE_TAG, VERSION, 11, self.cohort_count });
        if (self.native_profile.isDirect()) ch.mixU32s(&.{ 0x52434c33, @intFromEnum(self.native_profile) });
        ch.mixRoot(self.epoch.digest);
        ch.mixRoot(self.descriptor.scope.native_identity);
    }
    pub fn beginProofChannel(self: *const Owned, drawn: Epoch.Drawn) core.proof_suites.Blake3.Channel {
        var channel = drawn.channel;
        self.recordAfterDraws(&channel);
        return channel;
    }
};

/// Native-only first-halt permission. A terminal public shape is admitted only
/// at the final instruction of the independently selected window boundary.
pub fn haltFor(trusted: Trusted, shape: *const @import("../air/statement.zig").Blake3ExecutionStatement, frame: @import("../air/block/memory_event.zig").Frame, halt_address: u32) !@import("block_v8_native_halt_policy_v1.zig").Policy {
    if (shape.public_data.clock == 0 or frame.global_first_cycle == 0) return error.UntrustedTerminalSourceBoundary;
    const completion = shape.public_data.completion orelse return error.MissingCompletion;
    const end = try std.math.add(u64, frame.global_first_cycle, shape.public_data.clock - 1);
    var result = @import("block_v8_native_halt_policy_v1.zig").Policy{ .halt_address = halt_address };
    if (trusted.terminal_cycle) |last| {
        if (last == 0 or std.mem.allEqual(u8, &trusted.boundary_policy_id, 0) or end > last) return error.UntrustedTerminalSourceBoundary;
        if (end == last) {
            if (completion.kind != .halt_flag or completion.address != halt_address or completion.value != 1 or completion.clock != @import("../access_clock.zig").maximum(shape.public_data.clock)) return error.UntrustedTerminalSourceCompletion;
            result.permitted_final_instruction_cycle = shape.public_data.clock;
        } else if (completion.kind != .unretired_program_fetch) return error.UntrustedTerminalSourceCompletion;
    } else if (completion.kind != .unretired_program_fetch) return error.UnsupportedEndpointLocalTerminal;
    try result.validate();
    return result;
}
