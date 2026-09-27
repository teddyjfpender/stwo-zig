//! Actual CPU publication -> independently admitted heterogeneous job roster.
//! Only source-bound in-process template callbacks can provide producer keys.
//! Metadata claims remain proposals; every fold freshly verifies the original
//! recursive proof before using its cells. This grants no source/global token.
const std = @import("std");
const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(true);
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(true);
const Full = @import("../recursion/block_v5_heterogeneous_policy_v1.zig");
const Frames = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
const Parts = @import("block_v5_recursive_leaf_envelope_parts_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Providers = @import("block_v5_recursive_provider_store_v1.zig");
const Executions = @import("block_v5_recursive_execution_leaf_store_v1.zig");
const Forest = @import("block_v5_capacity_open_forest_stage_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Limits = struct {
    max_owned_bytes: usize = 1 << 30,
    max_proof_bytes: usize = 512 << 20,
    max_source_cells: usize = 1 << 26,
    coverage: Coverage.Limits = .{},
};
pub const File = struct { path: []const u8, byte_len: u64, sha256: [32]u8 };
pub const Owner = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    coverage: Coverage.Plan,
    expected: []Full.Expected,
    children: []Frames.Child,
    files: []File,
    initialized: usize = 0,
    limits: Limits,
    /// Borrowed immutable original admissions and bound callback schedules.
    publication: *Publication.Session,
    pub const complete_block_authority = false;
    pub const source_authority = false;
    pub fn deinit(self: *Owner) void {
        for (self.children[0..self.initialized]) |*child| child.deinit();
        self.coverage.deinit();
        self.arena.deinit();
        const budget = self.budget;
        budget.allocator().destroy(self);
        budget.destroy();
    }
    pub fn policy(self: *const Owner) Full.Policy {
        return .{ .plan = &self.coverage, .children = self.children, .expected = self.expected };
    }
    pub fn readLeaf(self: *const Owner, a: std.mem.Allocator, ordinal: u32) ![]u8 {
        if (ordinal >= self.files.len) return error.UnadmittedCpuScopedLeaf;
        const file = self.files[ordinal];
        // The inventory is transport custody only. Actual Expected.verify is
        // mandatory in the fold. No artifact-provided key selects admission.
        if (self.coverage.meta.physical[ordinal].kind == .native_arithmetic)
            return Files.readPinned(a, self.publication.base.dir, file.path, file.byte_len, file.sha256, self.limits.max_proof_bytes);
        return readEnvelopeProof(self, a, ordinal);
    }
};
/// TemplatePolicy is independently derived: producer Stage.on_template OR
/// the standalone Receive reconstruction from original durable base proofs.
/// Transport proposals cannot construct either admitted source path.
/// Session, Assembly and Native.Prepared owners outlive this source owner.
pub fn create(a: std.mem.Allocator, assembly: *const Assembly.Assembly, publication: *Publication.Session, native: []const Forest.LeafFile, limits: Limits) !*Owner {
    if (limits.max_owned_bytes == 0 or limits.max_proof_bytes == 0 or limits.max_source_cells == 0)
        return error.CpuScopedSourceResourceLimit;
    try publication.options.validate();
    try publication.sources.require();
    const sealed = try assembly.global_pins.validate();
    if (!std.meta.eql(sealed.digest, publication.sources.roster.sealed.digest) or
        !std.meta.eql(assembly.seal_pins, publication.sources.roster.pins) or
        native.len != publication.sources.selection.?.natives.len)
        return error.UntrustedCpuScopedSourceRoster;
    const budget = try Budget.create(a, limits.max_owned_bytes);
    errdefer budget.destroy();
    const self = try budget.allocator().create(Owner);
    errdefer budget.allocator().destroy(self);
    self.arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer self.arena.deinit();
    const owned = self.arena.allocator();
    self.budget = budget;
    self.publication = publication;
    self.limits = limits;
    self.initialized = 0;
    self.coverage = try Coverage.ForStack(Stack).prepare(owned, assembly.global_pins, .{ .base = assembly.seal_pins.config, .recursive = publication.profile.config() }, .quartet, limits.coverage);
    errdefer self.coverage.deinit();
    self.expected = try owned.alloc(Full.Expected, self.coverage.meta.physical.len);
    self.children = try owned.alloc(Frames.Child, self.expected.len);
    self.files = try owned.alloc(File, self.expected.len);
    const assigned = try owned.alloc(bool, self.expected.len);
    @memset(assigned, false);
    for (native, 0..) |leaf, index| {
        if (leaf.policy.native != publication.sources.selection.?.natives[index] or leaf.policy.native.index != index)
            return error.UntrustedCpuScopedNativeSource;
        var buffer: [128]u8 = undefined;
        const path = try Forest.leafPath(@intCast(index), &buffer);
        const expected = Full.Expected{ .capacity_v1 = .{
            .admitted = leaf.policy.native,
            .proposal = leaf.policy.exported,
            .key = leaf.policy.recursive_key,
            .key_id = leaf.policy.recursive_key_id,
            .wires = leaf.policy.recursive_schedule,
        } };
        try assign(self, assigned, .native_arithmetic, @intCast(index), expected, .{ .path = try owned.dupe(u8, path), .byte_len = leaf.file.byte_len, .sha256 = leaf.file.sha256 });
    }
    inline for (.{ .range16, .ram_lanes, .program_table, .native_lookup }) |family| try addProviders(family, self, assigned);
    inline for (.{ .caller_arithmetic, .caller_fused, .native_capacity_fused }) |family| try addExecutions(family, self, assigned);
    for (assigned) |present| if (!present) return error.IncompleteCpuScopedSources;
    var cells: usize = 0;
    errdefer for (self.children[0..self.initialized]) |*child| child.deinit();
    for (self.expected, self.children, 0..) |expected, *child, ordinal| {
        child.* = try expected.normalize(owned, &self.coverage, @intCast(ordinal));
        self.initialized += 1;
        cells = try std.math.add(usize, cells, child.cells.len);
        if (cells > limits.max_source_cells) return error.CpuScopedSourceResourceLimit;
    }
    try self.policy().validate();
    return self;
}
pub fn physicalOrdinal(plan: *const Coverage.Plan, kind: Coverage.Kind, index: u32) !u32 {
    var found: ?u32 = null;
    for (plan.meta.physical, 0..) |physical, ordinal| if (physical.kind == kind and physical.index == index) {
        if (found != null) return error.DuplicateCpuScopedSource;
        found = @intCast(ordinal);
    };
    return found orelse error.UnadmittedCpuScopedLeaf;
}
fn assign(self: *Owner, assigned: []bool, kind: Coverage.Kind, index: u32, expected: Full.Expected, file: File) !void {
    const ordinal = try physicalOrdinal(&self.coverage, kind, index);
    if (assigned[ordinal] or std.meta.activeTag(expected) != self.coverage.meta.physical[ordinal].subtype) return error.DuplicateCpuScopedSource;
    if (file.byte_len == 0 or file.byte_len > self.limits.max_proof_bytes) return error.CpuScopedSourceResourceLimit;
    self.expected[ordinal] = expected;
    self.files[ordinal] = file;
    assigned[ordinal] = true;
}
fn cloneProposal(comptime T: type, a: std.mem.Allocator, value: T) !T {
    // Bounded outer arena owns every proposed slice. No typed Prepared pointer
    // is encoded here; only original claim DTOs use this clone.
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    return std.json.parseFromSliceLeaky(T, a, raw, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
}
fn addProviders(comptime family: Providers.Family, self: *Owner, assigned: []bool) !void {
    const M = Providers.ForFamily(family);
    const D = @import("block_v5_recursive_provider_definition_v1.zig").ForFamily(family);
    const field = switch (family) {
        .range16 => "ranges",
        .ram_lanes => "lanes",
        .program_table => "program",
        .native_lookup => "lookups",
    };
    const kind: Coverage.Kind = switch (family) {
        .range16 => .range16,
        .ram_lanes => .ram_lanes,
        .program_table => .rom,
        .native_lookup => .native_lookup,
    };
    const subtype: Coverage.Subtype = switch (family) {
        .range16 => .range16_v1,
        .ram_lanes => .ram_lanes_v1,
        .program_table => .rom_v1,
        .native_lookup => .six_table_lookup_v1,
    };
    const writer = &@field(self.publication, field).?;
    const a = self.arena.allocator();
    const policies = try writer.store.publishedPolicies(a);
    const pins = try writer.store.sourceFilePins(a);
    if (policies.len != pins.len) return error.IncompleteCpuScopedSources;
    for (policies, pins) |policy, pin| {
        var buffer: [128]u8 = undefined;
        const path = try M.fileName(&buffer, pin.index);
        var parts = try Parts.readPinned(M.Codec, self.budget.allocator(), writer.store.dir, path, pin.byte_len, pin.sha256, policy, writer.store.limits.codec);
        defer parts.deinit();
        var view = try M.Codec.decodeMetadataParts(self.budget.allocator(), &parts.header, parts.metadata, parts.proof, policy, writer.store.limits.codec);
        defer view.deinit();
        const proposed = try cloneProposal(D.Open, a, view.open);
        const expected = @unionInit(Full.Expected, @tagName(subtype), .{ .admitted = policy.prepared, .proposal = proposed, .key = policy.template.key, .key_id = policy.template.key_id, .wires = policy.template.schedule });
        try assign(self, assigned, kind, pin.index, expected, .{ .path = try a.dupe(u8, path), .byte_len = pin.byte_len, .sha256 = pin.sha256 });
    }
}
fn addExecutions(comptime family: Executions.Family, self: *Owner, assigned: []bool) !void {
    const M = Executions.ForFamily(family);
    const C = @import("block_v5_recursive_execution_leaf_files_v1.zig").ForFamily(family);
    const field = switch (family) {
        .caller_arithmetic => "caller_arithmetic",
        .caller_fused => "caller_fused",
        .native_capacity_fused => "native_fused",
    };
    const kind: Coverage.Kind = switch (family) {
        .caller_arithmetic => .caller_arithmetic,
        .caller_fused => .caller_fused,
        .native_capacity_fused => .native_fused,
    };
    const subtype: Coverage.Subtype = switch (family) {
        .caller_arithmetic => .caller_family11_v1,
        .caller_fused => .caller_fused_v1,
        .native_capacity_fused => .capacity_fused_v1,
    };
    const writer = &@field(self.publication, field).?;
    const a = self.arena.allocator();
    const policies = try writer.store.publishedPolicies(a);
    const pins = try writer.store.sourceFilePins(a);
    if (policies.len != pins.len) return error.IncompleteCpuScopedSources;
    for (policies, pins) |policy, pin| {
        var buffer: [128]u8 = undefined;
        const path = try M.fileName(&buffer, pin.index);
        var parts = try Parts.readPinned(C, self.budget.allocator(), writer.store.dir, path, pin.byte_len, pin.sha256, policy, writer.store.limits.codec);
        defer parts.deinit();
        var view = try C.decodeMetadataParts(self.budget.allocator(), &parts.header, parts.metadata, parts.proof, policy, writer.store.limits.codec);
        defer view.deinit();
        const claims = try cloneProposal(C.Claims, a, view.parsed.value.claims);
        const proposal: @import("../recursion/block_v5_heterogeneous_leaf_definition_v1.zig").ForSubtype(subtype).Open = switch (family) {
            .caller_arithmetic => .{ .receipt = @import("block_v5_precompile_family_proof_v1.zig").OpenReceipt{ .binding = policy.prepared.binding, .open_sum = claims.componentSum() }, .claims = claims },
            .caller_fused => claims,
            .native_capacity_fused => .{ .projections = claims.projection, .memory = claims.memory },
        };
        const expected = @unionInit(Full.Expected, @tagName(subtype), .{ .admitted = policy.prepared, .proposal = proposal, .key = policy.template.key, .key_id = policy.template.key_id, .wires = policy.template.schedule });
        try assign(self, assigned, kind, pin.index, expected, .{ .path = try a.dupe(u8, path), .byte_len = pin.byte_len, .sha256 = pin.sha256 });
    }
}
fn readEnvelopeProof(self: *const Owner, a: std.mem.Allocator, ordinal: u32) ![]u8 {
    const physical = self.coverage.meta.physical[ordinal];
    const file = self.files[ordinal];
    inline for ([_]Providers.Family{ .range16, .ram_lanes, .program_table, .native_lookup }) |family| {
        const kind: Coverage.Kind = switch (family) {
            .range16 => .range16,
            .ram_lanes => .ram_lanes,
            .program_table => .rom,
            .native_lookup => .native_lookup,
        };
        if (physical.kind == kind) return proofFromWriter(&@field(self.publication, switch (family) {
            .range16 => "ranges",
            .ram_lanes => "lanes",
            .program_table => "program",
            .native_lookup => "lookups",
        }).?.store, a, physical.index, file);
    }
    inline for ([_]Executions.Family{ .caller_arithmetic, .caller_fused, .native_capacity_fused }) |family| {
        const kind: Coverage.Kind = switch (family) {
            .caller_arithmetic => .caller_arithmetic,
            .caller_fused => .caller_fused,
            .native_capacity_fused => .native_fused,
        };
        if (physical.kind == kind) return proofFromWriter(&@field(self.publication, switch (family) {
            .caller_arithmetic => "caller_arithmetic",
            .caller_fused => "caller_fused",
            .native_capacity_fused => "native_fused",
        }).?.store, a, physical.index, file);
    }
    return error.UnadmittedCpuScopedLeaf;
}
fn proofFromWriter(store: anytype, a: std.mem.Allocator, index: u32, expected: File) ![]u8 {
    const pins = try store.sourceFilePins(a);
    defer a.free(pins);
    var found = false;
    for (pins) |pin| if (pin.index == index) {
        if (found or pin.byte_len != expected.byte_len or !std.meta.eql(pin.sha256, expected.sha256)) return error.ChangedCpuScopedFile;
        found = true;
    };
    if (!found) return error.UnadmittedCpuScopedLeaf;
    return store.proofBytes(a, index);
}
