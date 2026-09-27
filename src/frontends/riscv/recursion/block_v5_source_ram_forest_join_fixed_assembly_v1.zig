//! Independent V20 expected-key factory. Both original forests and typed
//! direct leaf factories are reconstructed internally; no captures or received
//! keys/fixed rows nominate setup. Transition/global block authority stays OPEN.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Page = @import("block_v5_memory_source_page_forest_fixed_assembly_v1.zig");
const Memory = @import("block_v5_ram_range_forest_fixed_assembly_v1.zig");
const PageBus = @import("block_v5_memory_source_page_forest_summary_bus_v1.zig");
const MemoryBus = @import("block_v5_ram_range_forest_summary_bus_v1.zig");
const Public = @import("block_v5_source_ram_forest_join_fixed_public_v1.zig");
const Context = @import("block_v5_source_ram_forest_join_fixed_context_v1.zig");
const OriginalProtocol = @import("block_v5_source_ram_forest_join_protocol_v1.zig");
const Protocol = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(Public, OriginalProtocol);
const Graph = @import("air/block_v5_source_ram_forest_join_graph_v1.zig").ForPublic(Public);
const FixedGraph = @import("air/block_v5_recursive_fixed_graph_attach_v1.zig");
const Identifiers = @import("air/block_v5_requester_public_fixed_identifier_ports_v1.zig");
const Child = @import("air/block_v5_compact_recursive_fixed_child_v1.zig");
const Attach = @import("block_v5_recursive_fixed_attachments_v1.zig").Scoped;
const Storage = @import("air/blake3_parent_row_storage.zig");
const Join = @import("air/block_v5_requester_public_fixed_join_v1.zig");
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Compare = @import("air/block_v5_recursive_statement_compare_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub const PUBLIC_CIRCUIT = @import("block_v5_source_ram_forest_join_source_v1.zig").PUBLIC_CIRCUIT;
pub const Limits = struct {
    max_metadata_bytes: usize = 1 << 30,
    max_live_bytes: usize = 8 << 30,
    max_rows_per_cohort: usize = 1 << 24,
    page: Page.Limits = .{},
    memory: Memory.Limits = .{},
    pieces: @import("block_v5_recursive_parent_fixed_pieces_v1.zig").Limits = .{},
    public: Public.Limits = .{},
    public_supply: @import("air/block_v5_closed_public_supply_v1.zig").Limits = .{},
    frame: Compare.Limits = .{ .max_words = 1024, .max_felts = 4, .max_steps = 128 },
    pub fn validate(self: Limits, capacity: u32) !void {
        if (capacity == 0 or self.max_metadata_bytes == 0 or self.max_live_bytes == 0 or self.max_rows_per_cohort == 0 or self.max_rows_per_cohort > 1 << 24 or self.frame.max_words == 0 or self.frame.max_felts == 0 or self.frame.max_steps == 0) return error.SourceRamFixedResourceLimit;
        try self.page.validate(capacity);
        try self.memory.validate(capacity);
    }
};
/// Stable heap owner: summary policies borrow independently derived catalogue
/// specs; Sources borrow those exact owners. Original Plan/Context and native
/// admissions remain borrowed, and must outlive this entire object.
const CatalogueCustody = enum { owned, borrowed };
pub const Owned = struct {
    backing: std.mem.Allocator,
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed_budget: ?*Budget,
    page: Page.Catalogue,
    memory: Memory.Catalogue,
    catalogue_custody: CatalogueCustody,
    page_expected_catalogue: [32]u8,
    memory_expected_catalogue: [32]u8,
    page_public: PageBus.Owner,
    memory_public: ?MemoryBus.Owner,
    page_source: Public.Page.Source,
    memory_source: ?Public.Memory.Source,
    public: Public.Owner,
    fixed: Storage.FixedTuple(false),
    context: Base.Context,
    key: OriginalProtocol.Key,
    expected_id: [32]u8,
    expected_children: [2]?[32]u8,
    closure: [32]u8,
    frame: Frames.Statement,
    terms: []Term,
    capacity: u32,
    profile: Base.Profile,
    limits: Limits,
    pub const complete_block_authority = false;
    pub const fixed_setup_only = true;
    pub const reusable_across_instances = false;
    pub fn validate(self: *const Owned) !void {
        try requireCatalogueControls(&self.page, &self.memory, self.capacity, self.profile, self.limits);
        try self.page.require(self.page_expected_catalogue);
        try self.memory.require(self.memory_expected_catalogue);
        const page_policy = try self.page.policy(self.page.forest.geometry.root orelse return error.MissingPageForestFixedRoot, self.page_expected_catalogue);
        if (!std.meta.eql(page_policy, self.page_public.policy) or !std.meta.eql(self.expected_children[0], page_policy.specs[page_policy.index].expected_id)) return error.UntrustedSourceRamFixedSetup;
        if (self.memory.forest.geometry.root) |root| {
            const memory_policy = try self.memory.policy(root, self.memory_expected_catalogue);
            if (self.memory_public == null or self.memory_source == null or !std.meta.eql(memory_policy, self.memory_public.?.policy) or !std.meta.eql(self.expected_children[1], memory_policy.specs[root].expected_id)) return error.UntrustedSourceRamFixedSetup;
        } else if (self.memory_public != null or self.memory_source != null or self.expected_children[1] != null) return error.UntrustedSourceRamFixedSetup;
        if (self.public.policy.source != &self.page_source or self.page_source.public != &self.page_public or self.public.policy.memory != self.memory.forest or !std.meta.eql(self.public.policy.expected_memory_plan, self.memory.expected_plan) or self.public.policy.aggregate != (if (self.memory_source) |*source| source else null)) return error.UntrustedSourceRamFixedSetup;
        if (self.memory_source) |*source| if (source.public != &self.memory_public.?) return error.UntrustedSourceRamFixedSetup;
        const authority = try Protocol.Admission.init(try Protocol.Key.fromGeometry(.{ .profile = self.key.profile, .config = self.key.config, .context = self.key.context, .log_sizes = self.key.log_sizes, .preprocessed_root = self.key.preprocessed_root }, &.{}), self.expected_id, &.{}, .{ .public = &self.public });
        try Compare.compareFirst(&self.frame, self.limits.frame, .{ .sealed_offset = 0, .roots_offset = @splat(0) }, authority);
        if (!std.meta.eql(self.key.context, self.context) or self.key.profile != self.profile or self.terms.len != 0) return error.UntrustedSourceRamFixedSetup;
    }
    /// Match the independently derived setup to the genuine original source.
    /// Original Fresh verification/value checks are mandatory and unchanged.
    /// A received key never nominates any catalogue or expected fixed rows.
    pub fn validateAgainstSource(self: *const Owned, source: *const @import("block_v5_source_ram_forest_join_source_v1.zig").Source, capacity: u32, profile: Base.Profile, limits: Limits) !void {
        if (self.capacity != capacity or self.profile != profile or !std.meta.eql(self.limits, limits)) return error.UnpairedSourceRamFixedCatalogues;
        try self.validate();
        try source.validate();
        const actual = source.fresh.public.policy;
        const page_policy = actual.source.fresh.public.policy;
        const page_root = self.page.forest.geometry.root orelse return error.MissingPageForestFixedRoot;
        if (page_policy.forest != self.page.forest or page_policy.index != page_root or !std.meta.eql(page_policy.expected_plan, self.page.expected_plan) or !std.meta.eql(page_policy.specs[page_root].geometry, self.page.specs[page_root].geometry) or !std.meta.eql(page_policy.specs[page_root].expected_id, self.page.specs[page_root].expected_id) or page_policy.specs[page_root].schedule.len != 0 or actual.memory != self.memory.forest or !std.meta.eql(actual.expected_memory_plan, self.memory.expected_plan)) return error.UnpairedSourceRamFixedCatalogues;
        if (self.memory.forest.geometry.root) |root| {
            const memory_source = actual.aggregate orelse return error.UnpairedSourceRamFixedCatalogues;
            const selected = memory_source.fresh.public.policy;
            if (selected.forest != self.memory.forest or selected.index != root or !std.meta.eql(selected.expected_plan, self.memory.expected_plan) or !std.meta.eql(selected.specs[root], self.memory.specs[root])) return error.UnpairedSourceRamFixedCatalogues;
        } else if (actual.aggregate != null) return error.UnpairedSourceRamFixedCatalogues;
        if (!std.meta.eql(self.key, source.fresh.policy.key) or !std.meta.eql(self.expected_id, source.fresh.policy.expected_id)) return error.UnpairedSourceRamFixedCatalogues;
        const authority = try source.fresh.authority();
        try Compare.compareFirst(&self.frame, self.limits.frame, .{ .sealed_offset = 0, .roots_offset = @splat(0) }, authority);
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v5_source_ram_forest_join_preparation_v1.zig").Prepared) !void {
        try self.validate();
        if (self.fixed_budget == null) return error.ReleasedSourceRamFixedRows;
        try live.recursive.rows.partitionHashRows();
        if (live.wires.len != 0 or !std.meta.eql(self.context, live.recursive.context)) return error.UntrustedSourceRamFixedSetup;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedSourceRamFixedSetup;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedSourceRamFixedSetup;
        }
    }
    /// Key derivation is complete. Keep only stable independently derived
    /// compact policy/frame custody for an upper fixed verifier compiler.
    pub fn releaseFixedRows(self: *Owned) !void {
        try self.validate();
        if (self.fixed_budget) |live| {
            Join.deinit(live.allocator(), &self.fixed);
            self.fixed = Join.empty();
            self.fixed_budget = null;
            live.destroy();
        }
    }
    pub fn replayPublic(self: *const Owned, recorder: anytype) void {
        self.frame.recordAt(recorder, self.frame.first, PUBLIC_CIRCUIT) catch |failure| {
            recorder.failure = failure;
        };
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        a.free(self.terms);
        self.frame.deinit();
        if (self.fixed_budget) |live| {
            Join.deinit(live.allocator(), &self.fixed);
            live.destroy();
        }
        self.public.deinit();
        if (self.memory_source) |*source| source.deinit();
        self.page_source.deinit();
        if (self.memory_public) |*public| public.deinit();
        self.page_public.deinit();
        if (self.catalogue_custody == .owned) {
            self.memory.deinit();
            self.page.deinit();
        }
        a.destroy(self);
        budget.destroy();
    }
};
pub const Admission = struct {
    pub const fixed_setup_only = true;
    source: *const Owned,
    key: Base.Key,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Owned) !Admission {
        try source.validate();
        const k = source.key;
        return .{ .source = source, .key = .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root } };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        const original = try init(self.source);
        if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, original.key)) return error.UntrustedSourceRamFixedSetup;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
};
/// Controls are constructor-owned setup constraints, never artifact fields.
/// Check them before reading the borrowed immutable recipe/Scope providers.
fn requireCatalogueControls(page: *const Page.Catalogue, memory: *const Memory.Catalogue, capacity: u32, profile: Base.Profile, limits: Limits) !void {
    try limits.validate(capacity);
    if (page.capacity != capacity or memory.capacity != capacity or page.profile != profile or memory.profile != profile or !std.meta.eql(page.limits, limits.page) or !std.meta.eql(memory.limits, limits.memory)) return error.UnpairedSourceRamFixedCatalogues;
    if (page.leaf_catalogue == null) return error.MissingIndependentPageSemanticClaims;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Family = @This();
        fn deriveAdmitted(backing: std.mem.Allocator, page_forest: *const @import("block_v5_memory_source_page_forest_plan_v1.zig").Owned, page_expected: [32]u8, memory_forest: *const @import("block_v5_ram_range_forest_authority_v1.zig").Owned, memory_expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits, catalogue: ?*@import("../prover/block_v5_memory_source_page_leaf_catalogue_v1.zig").Catalogue) !*Owned {
            @setEvalBranchQuota(30_000);
            try limits.validate(capacity);
            try page_forest.require(page_expected);
            try memory_forest.require(memory_expected);
            if (page_forest.geometry.root == null) return error.MissingPageForestFixedRoot;
            var page = if (catalogue) |owner| try Page.ForBackend(Backend).deriveWithCatalogue(backing, page_forest, page_expected, capacity, profile, limits.page, owner) else try Page.ForBackend(Backend).derive(backing, page_forest, page_expected, capacity, profile, limits.page);
            errdefer page.deinit();
            var memory = try Memory.ForBackend(Backend).derive(backing, memory_forest, memory_expected, capacity, profile, limits.memory);
            errdefer memory.deinit();
            // Transfer only after the shared kernel succeeds. Failure leaves
            // both locally constructed catalogues under these errdefers.
            return Family.deriveCatalogues(.owned, backing, &page, page.independently_expected, &memory, memory.independently_expected, capacity, profile, limits);
        }
        fn deriveCatalogues(comptime custody: CatalogueCustody, backing: std.mem.Allocator, page: *const Page.Catalogue, page_expected: [32]u8, memory: *const Memory.Catalogue, memory_expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !*Owned {
            @setEvalBranchQuota(30_000);
            try requireCatalogueControls(page, memory, capacity, profile, limits);
            try page.require(page_expected);
            try memory.require(memory_expected);
            const page_forest = page.forest;
            const memory_forest = memory.forest;
            if (page_forest.geometry.root == null) return error.MissingPageForestFixedRoot;
            try page.requireSelected(page_forest.geometry.root.?, page_expected);
            if (memory_forest.geometry.root) |root| try memory.requireSelected(root, memory_expected);
            const budget = try Budget.createRetainingParent(backing, limits.max_metadata_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            const self = try a.create(Owned);
            errdefer a.destroy(self);
            // These copies preserve the original pinned arrays and scope/plan
            // provenance. Borrowed catalogue storage is never freed here.
            self.page = page.*;
            self.memory = memory.*;
            self.catalogue_custody = custody;
            self.page_expected_catalogue = page_expected;
            self.memory_expected_catalogue = memory_expected;
            self.page_public = try PageBus.Owner.init(a, try self.page.policy(page_forest.geometry.root.?, page_expected), limits.page.public);
            errdefer self.page_public.deinit();
            self.memory_public = null;
            errdefer if (self.memory_public) |*public| public.deinit();
            if (memory_forest.geometry.root) |root| self.memory_public = try MemoryBus.Owner.init(a, try self.memory.policy(root, memory_expected), limits.memory.public);
            self.page_source = try Public.Page.Source.init(a, &self.page_public);
            errdefer self.page_source.deinit();
            self.memory_source = null;
            errdefer if (self.memory_source) |*source| source.deinit();
            if (self.memory_public) |*public| self.memory_source = try Public.Memory.Source.init(a, public);
            self.public = try Public.Owner.init(a, .{ .source = &self.page_source, .memory = memory_forest, .expected_memory_plan = memory.expected_plan, .aggregate = if (self.memory_source) |*source| source else null }, limits.public);
            errdefer self.public.deinit();
            const fixed_budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
            errdefer fixed_budget.destroy();
            const scratch = fixed_budget.allocator();
            var builder = try Attach.init(scratch, .{ .max_children = 2, .max_rows = limits.max_rows_per_cohort });
            defer builder.deinit();
            var ids = Context.Owned.init(1 + @as(u32, @intFromBool(self.memory_source != null)), OriginalProtocol.sourceAuthority(), memory_forest.memory.seal.memory_plan_digest, memory_forest.sealed.digest);
            const page_id = self.page.specs[page_forest.geometry.root.?].expected_id;
            const child = try Child.append(scratch, &builder, try Public.Page.Admission.init(&self.page_source), 0, Public.Page.PUBLIC_CIRCUIT, capacity, limits.pieces);
            ids.child(page_id, child.namespace, child.context);
            var memory_id: ?[32]u8 = null;
            if (self.memory_source) |*source| {
                memory_id = self.memory.specs[memory_forest.geometry.root.?].expected_id;
                const lower = try Child.append(scratch, &builder, try Public.Memory.Admission.init(source), 1, Public.Memory.PUBLIC_CIRCUIT, capacity, limits.pieces);
                ids.child(memory_id.?, lower.namespace, lower.context);
            }
            var graph = try Graph.prepare(scratch, &self.public);
            defer graph.deinit();
            var fixed_graph = try FixedGraph.Owned.derive(scratch, &graph.circuit, graph.sources);
            defer fixed_graph.deinit();
            var identifiers = try Identifiers.Owned.init(scratch, &.{graph.circuit.graph()}, &.{FixedGraph.CIRCUIT});
            defer identifiers.deinit();
            try builder.appendGraphWithArithmetic(fixed_graph.fixed, fixed_graph.wires, fixed_graph.identity, try identifiers.port());
            ids.attachment(builder.attachments.items[builder.attachments.items.len - 1]);
            if (builder.main_identifier_rows != 0 or builder.child_count != 1 + @as(usize, @intFromBool(memory_id != null))) return error.MissingRecursiveFixedMainIdentifierPort;
            const closure = try builder.closePublicSupply(Public.Values{ .public = &self.public }, limits.public_supply);
            ids.attachment(closure);
            var fixed = Join.empty();
            errdefer Join.deinit(scratch, &fixed);
            inline for (0..Storage.Airs.len) |i| fixed[i] = try builder.fixed[i].toOwnedSlice(scratch);
            try Join.partition(scratch, &fixed);
            const context = ids.finish(memory_forest.memory.seal.config);
            const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(scratch, fixed, context, profile);
            const key = try OriginalProtocol.Key.fromGeometry(geometry, &.{});
            const expected_id = try key.identity();
            const authority = try Protocol.Admission.init(try Protocol.Key.fromGeometry(geometry, &.{}), expected_id, &.{}, .{ .public = &self.public });
            var frames = Frames.Builder{ .allocator = a, .max_words = limits.frame.max_words, .max_felts = limits.frame.max_felts };
            defer frames.deinit();
            try authority.mix(&frames);
            try frames.check();
            if (frames.steps.items.len > limits.frame.max_steps) return error.SourceRamFixedResourceLimit;
            const words = try frames.data.toOwnedSlice(a);
            errdefer a.free(words);
            const felts = try frames.fields.toOwnedSlice(a);
            errdefer a.free(felts);
            const steps = try frames.steps.toOwnedSlice(a);
            errdefer a.free(steps);
            const claims = try a.alloc(Frames.Step, 0);
            errdefer a.free(claims);
            const terms = try a.alloc(Term, 0);
            errdefer a.free(terms);
            self.backing = backing;
            self.allocator = a;
            self.budget = budget;
            self.fixed_budget = fixed_budget;
            self.fixed = fixed;
            self.context = context;
            self.key = key;
            self.expected_id = expected_id;
            self.expected_children = .{ page_id, memory_id };
            self.closure = closure;
            self.frame = .{ .allocator = a, .words = words, .felts = felts, .first = steps, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) };
            self.terms = terms;
            self.capacity = capacity;
            self.profile = profile;
            self.limits = limits;
            try self.validate();
            return self;
        }
        /// Reuse only genuinely derived typed catalogues. Expected catalogue
        /// IDs come from independent construction, never transported manifests.
        /// Both catalogue owners, original Plans/Context and Scope provider must
        /// remain alive through this owner and every borrowed upper admission.
        /// Failure leaves the caller's catalogue ownership unchanged.
        pub fn deriveFromCatalogues(backing: std.mem.Allocator, page: *const Page.Catalogue, page_expected: [32]u8, memory: *const Memory.Catalogue, memory_expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !*Owned {
            return Family.deriveCatalogues(.borrowed, backing, page, page_expected, memory, memory_expected, capacity, profile, limits);
        }
        pub fn derive(backing: std.mem.Allocator, page_forest: *const @import("block_v5_memory_source_page_forest_plan_v1.zig").Owned, page_expected: [32]u8, memory_forest: *const @import("block_v5_ram_range_forest_authority_v1.zig").Owned, memory_expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !*Owned {
            return Family.deriveAdmitted(backing, page_forest, page_expected, memory_forest, memory_expected, capacity, profile, limits, null);
        }
        pub fn deriveWithCatalogue(backing: std.mem.Allocator, page_forest: *const @import("block_v5_memory_source_page_forest_plan_v1.zig").Owned, page_expected: [32]u8, memory_forest: *const @import("block_v5_ram_range_forest_authority_v1.zig").Owned, memory_expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits, catalogue: *@import("../prover/block_v5_memory_source_page_leaf_catalogue_v1.zig").Catalogue) !*Owned {
            return Family.deriveAdmitted(backing, page_forest, page_expected, memory_forest, memory_expected, capacity, profile, limits, catalogue);
        }
    };
}
