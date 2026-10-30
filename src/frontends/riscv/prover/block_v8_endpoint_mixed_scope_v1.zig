//! Explicit native/caller source identity, with one shared original STARK.
//! Global RAM remains open until the same endpoint root is rebound and closed.
const std = @import("std");
const core = @import("stwo_core");
const Local = @import("block_v8_endpoint_local_scope_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Caller = @import("block_v8_endpoint_caller_plan_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const Kernel = @import("block_v8_ram_endpoint_kernel_v1.zig");
const Native = @import("block_v8_native_endpoint_closure_v1.zig");
const Mixed = @import("block_v8_native_mixed_layout_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Sparse = @import("block_v8_sparse_rom_v1.zig");
const SparseROM = @import("block_v8_sparse_rom_provider_v1.zig");
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
pub const production_active = false;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42384d53;
pub const Trusted = Local.Trusted;
pub const RomFlavor = Local.RomFlavor;
pub const Input = struct {
    rom_flavor: Local.RomFlavor = .legacy_complete,
    sparse_support: []const Sparse.Entry = &.{},
    shape: *const @import("../air/statement.zig").Blake3ExecutionStatement,
    caller_statement: *const P.admission.Statement,
    frame: @import("../air/block/memory_event.zig").Frame,
    cohort_ordinal: u32,
    endpoint_count: u32,
    native_roots: [4][32]u8,
    caller_roots: [2][32]u8,
    program_plan: @import("block_v5_program_table_v1.zig").Plan,
    program_roots: [2][32]u8,
    lookup_plan: LP.Plan,
    lookup_layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout,
    lookup_roots: [2][32]u8,
};
pub const Limits = struct { local: Local.Limits = .{}, caller: Caller.Limits = .{} };
pub const Descriptor = struct { scope: Native.Scope, frame: @FieldType(Input, "frame"), layout: [32]u8, roots: [4][32]u8 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    image: Image.Owned,
    owns_image: bool,
    caller_plan: Caller.Owned,
    layout: @import("block_v8_native_endpoint_layout_v1.zig").Layout,
    descriptor: Descriptor,
    identity: [32]u8,
    external: u32,
    halt: @import("block_v8_native_halt_policy_v1.zig").Policy,
    endpoint_policy: Kernel.Policy,
    epoch: Epoch.Epoch,
    entries: [4]Epoch.Entry,
    cohort_count: u32,
    rom_flavor: Local.RomFlavor,
    sparse_rom: ?Sparse.Owned,
    pub fn callerHalt(self: *const Owned) @import("block_v8_native_halt_policy_v1.zig").Policy {
        return .{ .halt_address = self.halt.halt_address };
    }
    pub fn init(a: std.mem.Allocator, trusted: Trusted, input: Input, limits: Limits) !*Owned {
        var image = try Image.Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.local.initial);
        errdefer image.deinit();
        const self = try initWithProgram(a, trusted, input, &image, limits);
        self.owns_image = true;
        return self;
    }
    pub fn initWithProgram(a: std.mem.Allocator, trusted: Trusted, input: Input, image: *const Image.Owned, limits: Limits) !*Owned {
        if (trusted.config.lifting_log_size != null) return error.UnsupportedEndpointMixedLifting;
        if (!std.meta.eql(image.elf_sha256, trusted.elf_sha256) or image.info.execution_profile != trusted.profile) return error.UntrustedEndpointMixedProgram;
        if (trusted.cohort_count == 0 or trusted.cohort_count > @min(limits.local.max_cohorts, 1 << 20) or input.cohort_ordinal >= trusted.cohort_count or input.endpoint_count == 0 or input.endpoint_count > limits.local.max_endpoints) return error.InvalidEndpointMixedCohort;
        const external = P.externalCount(input.caller_statement);
        if (external == 0) return error.EmptyMixedCallerInventory;
        const data = &input.shape.public_data;
        try input.shape.validateBlake3ExecutionWithExternal(external);
        if (input.shape.localZeroCustody() or input.caller_statement.ethereum.localZeroCustody() or data.initial_rw_root != null or data.final_rw_root != null or data.io_entries.input_len != 0 or data.io_entries.input_words.len != 0 or data.io_entries.output_len != 0 or data.io_entries.output_words.len != 0) return error.UnsupportedEndpointMixedBoundary;
        if (input.frame.clock_frame != .leaf_local or input.frame.global_first_cycle == 0 or input.frame.cycle_count != data.clock) return error.InvalidEndpointMixedFrame;
        const completion = data.completion orelse return error.MissingCompletion;
        _ = completion;
        if (!std.meta.eql(data.program_root orelse return error.MissingProgramRoot, image.root)) return error.UntrustedEndpointMixedProgram;
        const Windows = @import("block_v5_register_windows_v1.zig");
        const window = Windows.Window.fromPublic(0, 1, data.*);
        try (Windows.Plan{ .initial_registers = data.initial_regs, .final_registers = data.final_regs, .windows = &.{window} }).validate();
        var caller = try Caller.Owned.init(a, input.caller_statement, data.clock, input.frame, limits.caller);
        errdefer caller.deinit();
        var layout = try Mixed.init(a, input.shape, external);
        errdefer layout.deinit();
        var accesses = caller.ram.logical_ram_accesses;
        for (input.shape.component_descs[0..input.shape.n_components]) |desc| if (desc.family == .load_store) {
            accesses = try std.math.add(u64, accesses, desc.n_rows);
        };
        if (input.endpoint_count > accesses) return error.InvalidEndpointMixedCensus;
        const halt = try Local.haltFor(trusted, input.shape, input.frame, image.info.halt_flag);
        const policy = Kernel.Policy{ .source_ordinal = input.cohort_ordinal, .max_local_clock = try Native.maxLocalClock(data.clock) };
        try policy.validate();
        if (try policy.globalClock() > 4 * @as(u64, trusted.cohort_count) - 1) return error.InvalidEndpointMixedCohort;
        for (input.native_roots ++ input.caller_roots ++ input.program_roots ++ input.lookup_roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidEndpointMixedRoots;
        if (!std.meta.eql(input.native_roots[0], input.caller_roots[0])) return error.EndpointMixedFixedRootMismatch;
        var sparse: ?Sparse.Owned = null;
        errdefer if (sparse) |*plan| plan.deinit();
        if (input.rom_flavor == .legacy_complete) {
            if (input.sparse_support.len != 0 or !std.meta.eql(input.program_plan.program_root, image.root) or input.program_plan.leaves.len != image.leaves.len) return error.UntrustedEndpointMixedProgram;
            for (input.program_plan.leaves, image.leaves) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedEndpointMixedProgram;
        } else {
            if (input.program_plan.leaves.len != 0 or input.program_plan.multiplicities.len != 0 or !std.meta.eql(input.program_plan.program_root, image.root)) return error.UntrustedSparseMixedDescriptor;
            sparse = try Sparse.Owned.fromImage(a, .{ .elf = trusted.elf, .elf_sha256 = trusted.elf_sha256, .profile = trusted.profile, .program_root = image.root, .expected_fetches = input.program_plan.expected_fetches }, input.sparse_support, image, .{ .initial = limits.local.initial });
            if (input.program_plan.log_size != sparse.?.log_size) return error.UntrustedSparseMixedDescriptor;
        }
        var demand = try LP.nativeDemand(input.shape, external);
        try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demand, input.caller_statement, data.clock, trusted.config);
        const byte_index = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8);
        demand[byte_index] = try std.math.add(u64, demand[byte_index], try std.math.mul(u64, input.endpoint_count, 4));
        const lookup = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        try lookup.validate();
        if (!std.meta.eql(lookup, input.lookup_plan)) return error.UntrustedEndpointMixedLookup;
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ TAG, VERSION, 14, trusted.cohort_count, input.cohort_ordinal, @intFromEnum(trusted.profile), @intFromEnum(input.rom_flavor), external, halt.halt_address, policy.max_local_clock, input.endpoint_count });
        if (trusted.terminal_cycle) |cycle| {
            ch.mixU32s(&.{ 0x42385453, 1, cycle, halt.permitted_final_instruction_cycle orelse 0 });
            ch.mixRoot(trusted.boundary_policy_id);
        }
        ch.mixRoot(trusted.elf_sha256);
        trusted.config.mixInto(&ch);
        ch.mixRoot(layout.digest);
        ch.mixRoot(caller.digest);
        ch.mixRoot(try @import("block_v5_precompile_protocol_v1.zig").keyId(input.caller_statement, data.clock, trusted.config, input.caller_roots[0]));
        data.mixInto(&ch);
        input.shape.mixShardManifest(&ch);
        ch.mixU64(input.frame.global_first_cycle);
        ch.mixU32s(&.{input.frame.cycle_count});
        for (input.native_roots ++ input.caller_roots) |root| ch.mixRoot(root);
        const identity = ch.digestBytes();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .image = image.*, .owns_image = false, .caller_plan = caller, .layout = layout, .descriptor = .{ .scope = .{ .native_index = input.cohort_ordinal, .execution_profile = trusted.profile, .native_identity = identity, .endpoint_count = input.endpoint_count, .policy = policy, .halt = halt }, .frame = input.frame, .layout = layout.digest, .roots = input.native_roots }, .identity = identity, .external = external, .halt = halt, .endpoint_policy = policy, .cohort_count = trusted.cohort_count, .rom_flavor = input.rom_flavor, .sparse_rom = sparse, .entries = undefined, .epoch = undefined };
        self.entries = .{ try Epoch.Entry.init(.native, 0, identity, &input.native_roots), try Epoch.Entry.init(.caller_fused, 0, identity, &input.caller_roots), if (input.rom_flavor == .legacy_complete) try ROM.firstEntry(input.program_plan, input.program_roots) else try SparseROM.firstEntry(&self.sparse_rom.?, input.program_roots), try Lookup.firstEntry(input.lookup_plan, input.lookup_layout, input.lookup_roots) };
        var counts: Epoch.Counts = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family)] += 1;
        self.epoch = try Epoch.Epoch.init(identity, trusted.config, counts, &self.entries, self.entries.len);
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.caller_plan.deinit();
        self.layout.deinit();
        if (self.sparse_rom) |*plan| plan.deinit();
        if (self.owns_image) self.image.deinit();
        a.destroy(self);
    }
    pub fn source(self: *const Owned) Local.Source {
        return .{ .local_epoch = self.epoch.digest, .local_identity = self.identity, .endpoint_root = self.descriptor.roots[2], .endpoint_count = self.descriptor.scope.endpoint_count, .policy = self.endpoint_policy, .frame = self.descriptor.frame };
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
        ch.mixU32s(&.{ TAG, VERSION, 14, self.cohort_count, self.external });
        ch.mixRoot(self.epoch.digest);
        ch.mixRoot(self.identity);
    }
    pub fn beginProofChannel(self: *const Owned, drawn: Epoch.Drawn) core.proof_suites.Blake3.Channel {
        var ch = drawn.channel;
        self.recordAfterDraws(&ch);
        return ch;
    }
};
