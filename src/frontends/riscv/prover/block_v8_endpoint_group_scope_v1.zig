//! Finite GROUP original domain. Every member's CPU/RAM closure remains
//! separate; only positive bounded ROM/table/range providers are shared.
//! All ordered frames, global ordinals and first roots precede one epoch draw.
const std = @import("std");
const core = @import("stwo_core");
const Local = @import("block_v8_endpoint_local_scope_v1.zig");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Native = @import("block_v8_native_endpoint_layout_v1.zig");
const Mixed = @import("block_v8_native_mixed_layout_v1.zig");
const Caller = @import("block_v8_endpoint_caller_plan_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const K = @import("block_v8_ram_endpoint_kernel_v1.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Sparse = @import("block_v8_sparse_rom_v1.zig");
const SparseROM = @import("block_v8_sparse_rom_provider_v1.zig");
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const Digest = [32]u8;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42384753;
pub const MAX_MEMBERS: usize = 8;
const GroupLayout = @import("block_v8_endpoint_group_layout_v1.zig");
pub const Profile = GroupLayout.Profile;
pub const production_active = false;
pub const Trusted = Local.Trusted;
pub const CallerInput = struct { statement: *const P.admission.Statement, main_root: Digest };
pub const MemberInput = struct {
    shape: *const @import("../air/statement.zig").Blake3ExecutionStatement,
    frame: @import("../air/block/memory_event.zig").Frame,
    cohort_ordinal: u32,
    endpoint_count: u32,
    native_main_root: Digest,
    endpoint_main_root: Digest,
    caller: ?CallerInput = null,
};
pub const Input = struct {
    profile: Profile = .compact_v1,
    members: []const MemberInput,
    fixed_root: Digest,
    range_main_root: Digest,
    rom_flavor: Local.RomFlavor = .legacy_complete,
    sparse_support: []const Sparse.Entry = &.{},
    program_plan: @import("block_v5_program_table_v1.zig").Plan,
    program_roots: [2]Digest,
    lookup_plan: LP.Plan,
    lookup_layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout,
    lookup_roots: [2]Digest,
};
pub const Limits = struct { local: Local.Limits = .{}, caller: Caller.Limits = .{}, max_members: usize = GroupLayout.MAX_NATIVE_WIDE_MEMBERS };
pub const OwnedMember = struct {
    layout: Native.Layout,
    layout_identity: Digest,
    caller_plan: ?Caller.Owned,
    external: u32,
    endpoint_policy: K.Policy,
    identity: Digest,
    caller_index: ?usize,
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    image: Image.Owned,
    owns_image: bool,
    epoch: Epoch.Epoch,
    entries: []Epoch.Entry,
    member: []OwnedMember,
    sources: []Local.Source,
    halt: @import("block_v8_native_halt_policy_v1.zig").Policy,
    cohort_count: u32,
    endpoint_count_total: u32,
    rom_flavor: Local.RomFlavor,
    profile: Profile,
    sparse_rom: ?Sparse.Owned,
    identity: Digest,
    cycles: u64,
    external: u64,
    caller_count: usize,
    pub fn init(a: std.mem.Allocator, trusted: Trusted, input: Input, limits: Limits) !*Owned {
        var image = try Image.Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.local.initial);
        errdefer image.deinit();
        const self = try initWithProgram(a, trusted, input, &image, limits);
        self.owns_image = true;
        return self;
    }
    pub fn initWithProgram(a: std.mem.Allocator, trusted: Trusted, input: Input, image: *const Image.Owned, limits: Limits) !*Owned {
        if (trusted.config.lifting_log_size != null) return error.UnsupportedEndpointGroupLifting;
        if (input.members.len == 0 or input.members.len > @min(GroupLayout.maxMembers(input.profile), limits.max_members) or trusted.cohort_count == 0 or trusted.cohort_count > @min(limits.local.max_cohorts, 1 << 20)) return error.InvalidEndpointGroupInventory;
        if (input.profile == .native_wide_v2) for (input.members) |m| if (m.caller != null) return error.UnsupportedEndpointNativeWideCaller;
        if (!std.meta.eql(image.elf_sha256, trusted.elf_sha256) or image.info.execution_profile != trusted.profile) return error.UntrustedEndpointGroupProgram;
        try input.lookup_layout.validate();
        for (input.program_roots ++ input.lookup_roots ++ [2]Digest{ input.fixed_root, input.range_main_root }) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidEndpointGroupRoots;
        const halt = @import("block_v8_native_halt_policy_v1.zig").Policy{ .halt_address = image.info.halt_flag };
        try halt.validate();
        try @import("block_v8_caller_halt_policy_v1.zig").validate(halt);
        const members = try a.alloc(OwnedMember, input.members.len);
        errdefer a.free(members);
        var ready: usize = 0;
        errdefer for (members[0..ready]) |*m| {
            if (m.caller_plan) |*p| p.deinit();
            m.layout.deinit();
        };
        var demand: [@import("../air/lookups/tables/schema.zig").KIND_COUNT]u64 = @splat(0);
        var endpoint_total: u64 = 0;
        var fetches: u64 = 0;
        var cycles: u64 = 0;
        var external_total: u64 = 0;
        var caller_count: usize = 0;
        for (input.members, members, 0..) |m, *owned, index| {
            const data = &m.shape.public_data;
            const external = if (m.caller) |c| P.externalCount(c.statement) else 0;
            try m.shape.validateBlake3ExecutionWithExternal(external);
            if (data.clock == 0 or m.shape.localZeroCustody() or @import("block_v5_native_frame_v1.zig").required(m.shape) or data.initial_rw_root != null or data.final_rw_root != null or data.io_entries.input_len != 0 or data.io_entries.input_words.len != 0 or data.io_entries.output_len != 0 or data.io_entries.output_words.len != 0) return error.UnsupportedEndpointGroupBoundary;
            if ((data.completion orelse return error.MissingCompletion).kind != .unretired_program_fetch) return error.UnsupportedEndpointGroupTerminal;
            if (!std.meta.eql(data.program_root orelse return error.MissingProgramRoot, image.root)) return error.UntrustedEndpointGroupProgram;
            if (m.cohort_ordinal >= trusted.cohort_count or m.endpoint_count == 0 or m.endpoint_count > limits.local.max_endpoints or m.frame.clock_frame != .leaf_local or m.frame.global_first_cycle == 0 or m.frame.cycle_count != data.clock) return error.InvalidEndpointGroupMember;
            if (std.mem.allEqual(u8, &m.native_main_root, 0) or std.mem.allEqual(u8, &m.endpoint_main_root, 0)) return error.InvalidEndpointGroupRoots;
            if (index > 0) {
                const prior = input.members[index - 1];
                if (m.cohort_ordinal != try std.math.add(u32, prior.cohort_ordinal, 1) or m.frame.global_first_cycle != try std.math.add(u64, prior.frame.global_first_cycle, prior.frame.cycle_count) or data.initial_pc != prior.shape.public_data.final_pc or !std.meta.eql(data.initial_regs, prior.shape.public_data.final_regs)) return error.UntrustedEndpointGroupCpuChain;
            }
            const Windows = @import("block_v5_register_windows_v1.zig");
            const window = Windows.Window.fromPublic(0, 1, data.*);
            try (Windows.Plan{ .initial_registers = data.initial_regs, .final_registers = data.final_regs, .windows = &.{window} }).validate();
            var caller: ?Caller.Owned = null;
            var layout: ?Native.Layout = null;
            errdefer if (caller) |*v| v.deinit();
            errdefer if (layout) |*v| v.deinit();
            if (m.caller) |c| {
                if (external == 0 or c.statement.ethereum.localZeroCustody() or std.mem.allEqual(u8, &c.main_root, 0)) return error.InvalidEndpointGroupCaller;
                caller = try Caller.Owned.init(a, c.statement, data.clock, m.frame, limits.caller);
                layout = try Mixed.init(a, m.shape, external);
            } else layout = try Native.Layout.init(a, m.shape, 0);
            var accesses: u64 = if (caller) |c| c.ram.logical_ram_accesses else 0;
            for (m.shape.component_descs[0..m.shape.n_components]) |desc| if (desc.family == .load_store) {
                accesses = try std.math.add(u64, accesses, desc.n_rows);
            };
            if (m.endpoint_count > accesses) return error.InvalidEndpointGroupEndpointCensus;
            _ = try m.frame.globalClock(@intCast(@import("../access_clock.zig").maximum(data.clock)));
            const endpoint_policy = K.Policy{ .source_ordinal = m.cohort_ordinal, .max_local_clock = try @import("block_v8_native_endpoint_closure_v1.zig").maxLocalClock(data.clock) };
            try endpoint_policy.validate();
            if (try endpoint_policy.globalClock() > 4 * @as(u64, trusted.cohort_count) - 1) return error.InvalidEndpointGroupMember;
            var layout_channel = core.proof_suites.Blake3.Channel{};
            GroupLayout.domain(&layout_channel, input.profile);
            layout_channel.mixU32s(&.{ TAG, VERSION, 0x4c41594f, @intCast(index), m.cohort_ordinal, external, @intFromBool(m.caller != null) });
            layout_channel.mixRoot(layout.?.digest);
            const local_demand = try LP.nativeDemand(m.shape, external);
            for (&demand, local_demand) |*sum, value| sum.* = try std.math.add(u64, sum.*, value);
            if (m.caller) |c| try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demand, c.statement, data.clock, trusted.config);
            endpoint_total = try std.math.add(u64, endpoint_total, m.endpoint_count);
            fetches = try std.math.add(u64, fetches, try std.math.add(u64, data.clock, 1));
            cycles = try std.math.add(u64, cycles, data.clock);
            external_total = try std.math.add(u64, external_total, external);
            owned.* = .{ .layout = layout.?, .layout_identity = layout_channel.digestBytes(), .caller_plan = caller, .external = external, .endpoint_policy = endpoint_policy, .identity = undefined, .caller_index = if (m.caller != null) caller_count else null };
            ready += 1;
            if (m.caller != null) caller_count += 1;
            caller = null;
            layout = null;
        }
        const range_counts = try @import("block_v8_endpoint_range_provider_v1.zig").requests(endpoint_total);
        const byte_index = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8);
        demand[byte_index] = try std.math.add(u64, demand[byte_index], range_counts.byte_pairs);
        const lookup = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = @intCast(input.members.len), .max_requests = demand };
        try lookup.validate();
        if (!std.meta.eql(lookup, input.lookup_plan)) return error.UntrustedEndpointGroupLookup;
        if (fetches >= core.fields.m31.Modulus or input.program_plan.expected_fetches != fetches) return error.InvalidEndpointGroupProgramCensus;
        var sparse: ?Sparse.Owned = null;
        errdefer if (sparse) |*p| p.deinit();
        var program_digest: Digest = undefined;
        if (input.rom_flavor == .legacy_complete) {
            if (input.sparse_support.len != 0 or !std.meta.eql(input.program_plan.program_root, image.root) or input.program_plan.leaves.len != image.leaves.len) return error.UntrustedEndpointGroupProgram;
            for (input.program_plan.leaves, image.leaves) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedEndpointGroupProgram;
            program_digest = try input.program_plan.digest();
        } else {
            if (input.program_plan.leaves.len != 0 or input.program_plan.multiplicities.len != 0 or !std.meta.eql(input.program_plan.program_root, image.root)) return error.UntrustedSparseGroupDescriptor;
            sparse = try Sparse.Owned.fromImage(a, .{ .elf = trusted.elf, .elf_sha256 = trusted.elf_sha256, .profile = trusted.profile, .program_root = image.root, .expected_fetches = fetches }, input.sparse_support, image, .{ .initial = limits.local.initial });
            if (sparse.?.log_size != input.program_plan.log_size) return error.UntrustedSparseGroupDescriptor;
            program_digest = sparse.?.digest;
        }
        var group = core.proof_suites.Blake3.Channel{};
        GroupLayout.domain(&group, input.profile);
        group.mixU32s(&.{ TAG, VERSION, @intCast(input.members.len), @intCast(caller_count), trusted.cohort_count, @intFromEnum(trusted.profile), @intFromEnum(input.rom_flavor), range_counts.endpoints, range_counts.range16 });
        trusted.config.mixInto(&group);
        group.mixRoot(trusted.elf_sha256);
        group.mixRoot(image.root.bytes);
        for ([2]Digest{ input.fixed_root, input.range_main_root } ++ input.program_roots ++ input.lookup_roots) |root| group.mixRoot(root);
        group.mixRoot(program_digest);
        group.mixRoot(try lookup.identity());
        group.mixRoot(input.lookup_layout.digest);
        for (input.members, members, 0..) |m, owned, index| {
            group.mixU32s(&.{ @intCast(index), m.cohort_ordinal, m.endpoint_count, owned.external, @intFromEnum(m.frame.clock_frame), m.frame.cycle_count });
            group.mixU64(m.frame.global_first_cycle);
            m.shape.public_data.mixInto(&group);
            m.shape.mixShardManifest(&group);
            group.mixRoot(owned.layout_identity);
            group.mixRoot(m.native_main_root);
            group.mixRoot(m.endpoint_main_root);
            group.mixU32s(&.{@intFromBool(m.caller != null)});
            if (m.caller) |c| {
                group.mixRoot(c.main_root);
                group.mixRoot(owned.caller_plan.?.digest);
                group.mixRoot(try @import("block_v5_precompile_protocol_v1.zig").keyId(c.statement, m.shape.public_data.clock, trusted.config, input.fixed_root));
            }
        }
        const identity = group.digestBytes();
        const entries = try a.alloc(Epoch.Entry, input.members.len + caller_count + 2);
        errdefer a.free(entries);
        var at: usize = 0;
        for (input.members, members, 0..) |m, *owned, index| {
            var ch = core.proof_suites.Blake3.Channel{};
            GroupLayout.domain(&ch, input.profile);
            ch.mixU32s(&.{ TAG, VERSION, 0x4d454d42, @intCast(index), m.cohort_ordinal });
            ch.mixRoot(identity);
            ch.mixRoot(owned.layout_identity);
            owned.identity = ch.digestBytes();
            entries[at] = try Epoch.Entry.init(.native, @intCast(index), owned.identity, &.{ input.fixed_root, m.native_main_root, m.endpoint_main_root, input.range_main_root });
            at += 1;
        }
        for (input.members, members) |m, owned| if (m.caller) |c| {
            entries[at] = try Epoch.Entry.init(.caller_fused, @intCast(owned.caller_index.?), owned.identity, &.{ input.fixed_root, c.main_root });
            at += 1;
        };
        entries[at] = if (input.rom_flavor == .legacy_complete) try ROM.firstEntry(input.program_plan, input.program_roots) else try SparseROM.firstEntry(&sparse.?, input.program_roots);
        at += 1;
        entries[at] = try Lookup.firstEntry(input.lookup_plan, input.lookup_layout, input.lookup_roots);
        at += 1;
        var counts: Epoch.Counts = @splat(0);
        for (entries) |e| counts[@intFromEnum(e.family)] += 1;
        const epoch = try Epoch.Epoch.init(identity, trusted.config, counts, entries, at);
        const sources = try a.alloc(Local.Source, input.members.len);
        errdefer a.free(sources);
        for (sources, input.members, members) |*exported_source, m, owned| exported_source.* = .{ .local_epoch = epoch.digest, .local_identity = owned.identity, .endpoint_root = m.endpoint_main_root, .endpoint_count = m.endpoint_count, .policy = owned.endpoint_policy, .frame = m.frame };
        const self = try a.create(Owned);
        self.* = .{ .allocator = a, .image = image.*, .owns_image = false, .epoch = epoch, .entries = entries, .member = members, .sources = sources, .halt = halt, .cohort_count = trusted.cohort_count, .endpoint_count_total = range_counts.endpoints, .rom_flavor = input.rom_flavor, .profile = input.profile, .sparse_rom = sparse, .identity = identity, .cycles = cycles, .external = external_total, .caller_count = caller_count };
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        for (self.member) |*m| {
            if (m.caller_plan) |*c| c.deinit();
            m.layout.deinit();
        }
        a.free(self.member);
        a.free(self.sources);
        a.free(self.entries);
        if (self.sparse_rom) |*p| p.deinit();
        if (self.owns_image) self.image.deinit();
        a.destroy(self);
    }
    pub fn source(self: *const Owned, index: usize) Local.Source {
        return self.sources[index];
    }
    pub fn programPolicy(self: *const Owned, input: Input) ROM.Policy {
        return .{ .plan = input.program_plan, .expected_program_root = self.image.root, .roots = input.program_roots, .epoch = self.epoch, .entries = self.entries };
    }
    pub fn sparseProgramPolicy(self: *const Owned, input: Input) SparseROM.Policy {
        return .{ .plan = &self.sparse_rom.?, .roots = input.program_roots, .epoch = self.epoch, .entries = self.entries };
    }
    pub fn lookupPolicy(self: *const Owned, input: Input) Lookup.Policy {
        return .{ .plan = input.lookup_plan, .layout = input.lookup_layout, .roots = input.lookup_roots, .epoch = self.epoch, .entries = self.entries };
    }
    pub fn beginProofChannel(self: *const Owned, drawn: Epoch.Drawn) core.proof_suites.Blake3.Channel {
        var ch = drawn.channel;
        self.recordAfterDraws(&ch);
        return ch;
    }
    /// Same authority for original and recursive transcript framing.
    pub fn recordAfterDraws(self: *const Owned, ch: anytype) void {
        GroupLayout.recordDomain(ch, self.profile);
        ch.mixU32s(&.{ TAG, VERSION, @intCast(self.member.len), @intCast(self.caller_count), self.cohort_count, self.endpoint_count_total });
        ch.mixRoot(self.identity);
        ch.mixRoot(self.epoch.digest);
    }
};
