//! Complete FINAL22 fixed assembly. PUBLIC21 expected setup is capture-free;
//! V20 expectation uses either original genuine lower preparation or the
//! distinct authenticated capture-free catalogue factory; neither is proof authority.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("block_v5_requester_memory_public_v1.zig");
const Protocol = @import("block_v5_requester_memory_protocol_v1.zig");
const Context = @import("block_v5_requester_memory_fixed_context_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const PublicFixed = @import("block_v5_requester_public_fixed_assembly_v1.zig");
const PublicShape = @import("block_v5_requester_public_recursive_shape_admission_v1.zig");
const MemoryShape = @import("block_v5_source_ram_forest_join_recursive_shape_admission_v1.zig");
const MemoryPreparation = @import("block_v5_source_ram_forest_join_preparation_v1.zig");
const MemoryProducer = @import("block_v5_source_ram_forest_join_producer_v1.zig");
const IndependentMemory = @import("block_v5_source_ram_forest_join_fixed_assembly_v1.zig");
const PageCatalogue = @import("../prover/block_v5_memory_source_page_leaf_catalogue_v1.zig");
const MemorySetup = enum { original_captures, independent_fixed, authenticated_fixed };
const PiecesModule = @import("block_v5_recursive_parent_fixed_pieces_v1.zig");
const RosterModule = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
const PiecesLimits = @import("block_v5_recursive_parent_fixed_pieces_v1.zig").Limits;
const FixedAttach = @import("block_v5_recursive_fixed_attachments_v1.zig").Scoped;
const Storage = @import("air/blake3_parent_row_storage.zig");
const Identifiers = @import("air/block_v5_requester_public_fixed_identifier_ports_v1.zig");
const Suppliers = @import("air/block_v5_recursive_fixed_child_suppliers_v1.zig");
const Graph = @import("air/block_v5_requester_memory_graph_v1.zig");
const FixedGraph = @import("air/block_v5_recursive_fixed_graph_attach_v1.zig");
const Circuit = @import("air/composition_circuit.zig").CircuitGraph;
const FixedJoin = @import("air/block_v5_requester_public_fixed_join_v1.zig");
const ScopedBus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Limits = struct {
    max_owned_bytes: usize = 8 << 30,
    max_setup_bytes: usize = 16 << 30,
    max_rows_per_cohort: usize = 1 << 24,
    public_setup: PublicFixed.Limits = .{},
    memory_setup: MemoryPreparation.Limits = .{},
    independent_memory_setup: IndependentMemory.Limits = .{},
    pieces: PiecesLimits = .{},
    public_source: PublicShape.Limits = .{},
    public_supply: @import("air/block_v5_closed_public_supply_v1.zig").Limits = .{},
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    backing: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    context: Base.Context,
    wires: []Public.Wire,
    expected_children: [2][32]u8,
    public_identity: [32]u8,
    closure: [32]u8,
    retry_capacity: u32,
    profile: Protocol.Profile,
    limits: Limits,
    pub const complete_block_authority = false;
    /// Legacy Owned does not prove which lower setup path constructed it.
    /// Use the distinct IndependentOwned constructor for capture-free setup.
    pub fn requireCaptureFreeMemorySetup(_: *const Owned) error{MissingIndependentMemoryRootFixedSetup}!void {
        return error.MissingIndependentMemoryRootFixedSetup;
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v5_requester_memory_preparation_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != 0 or live.wires.len != 0) return error.UntrustedRequesterMemoryFixedAssembly;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedRequesterMemoryFixedAssembly;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedRequesterMemoryFixedAssembly;
        }
    }
    pub fn deinit(self: *Owned) void {
        const budget = self.budget;
        self.allocator.free(self.wires);
        FixedJoin.deinit(self.allocator, &self.fixed);
        self.* = undefined;
        budget.destroy();
    }
};
/// Distinct host setup type, returned only after the actual independent V20
/// forest factories complete. It carries no successful proof/block authority.
pub const IndependentOwned = struct {
    owned: Owned,
    pub const complete_block_authority = false;
    pub fn validateLive(self: *const IndependentOwned, live: *@import("block_v5_requester_memory_preparation_v1.zig").Prepared) !void {
        try self.owned.validateLive(live);
    }
    pub fn deinit(self: *IndependentOwned) void {
        self.owned.deinit();
        self.* = undefined;
    }
};
fn appendChild(a: std.mem.Allocator, builder: *FixedAttach, ids: *Context.Owned, admission: anytype, expected: [32]u8, child: u32, comptime public_circuit: u32, capacity: u32, limits: PiecesLimits) !void {
    const Admission = @TypeOf(admission);
    const Pieces = PiecesModule.ForAdmission(Admission);
    const Roster = RosterModule.ForPackedAdmission(Admission);
    const pieces = try Pieces.Owned.init(a, &admission, capacity, limits);
    defer pieces.deinit();
    const rows = try Roster.Owned.init(a, pieces, &admission);
    defer rows.deinit();
    const wires = try Suppliers.collect(a, pieces.transcript.fixed.fixed, &pieces.composition, admission.source.terms.len, child, public_circuit);
    defer a.free(wires);
    const graphs = [3]Circuit{ pieces.composition.circuit.graph(), pieces.arithmetic.deep_graph.graph(), pieces.arithmetic.fri_graph.graph() };
    var identifiers = try Identifiers.Owned.init(a, &graphs, &.{ 1500, 1502, 1504 });
    defer identifiers.deinit();
    try builder.appendChildWithArithmetic(rows.fixed, wires, try identifiers.port());
    ids.child(expected, builder.attachments.items[builder.attachments.items.len - 1], .{ .child_key_id = expected, .child_config = admission.key.config, .graph_ids = rows.graph_ids, .transcript_plan_id = rows.transcript_id });
}
pub const KeyAndSchedule = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    key: Protocol.Key,
    wires: []Public.Wire,
    pub fn deinit(self: *KeyAndSchedule) void {
        const lease = self.lease;
        self.allocator.free(self.wires);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Family = @This();
        /// Independently derive BOTH expectations before comparing any received
        /// root policies. V20 original preparation consumes genuine lower PAGE
        /// and RAM-root captures; no externally supplied rows/key factory exists.
        fn initKernel(comptime memory_setup: MemorySetup, backing: std.mem.Allocator, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, catalogue: ?*PageCatalogue.Catalogue, authenticated_memory: ?*const IndependentMemory.Owned) !Owned {
            @setEvalBranchQuota(30_000);
            if (capacity == 0 or limits.max_owned_bytes == 0 or limits.max_setup_bytes == 0 or limits.max_rows_per_cohort == 0 or limits.max_rows_per_cohort > 1 << 24) return error.RequesterMemoryFixedResourceLimit;
            try public.validate();
            if (!std.meta.eql(profile.config(), public.policy.expected_requester.coverage.meta.security.recursive)) return error.RequesterMemorySecurityMismatch;
            const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            const requester_public = public.policy.requester.fresh.policy.public;
            const public_expected = expected: {
                const setup_budget = try Budget.createRetainingParent(backing, limits.max_setup_bytes);
                defer setup_budget.destroy();
                var expected = try PublicFixed.ForBackend(Backend).deriveKeyAndScheduleForPolicy(setup_budget.allocator(), requester_public, capacity, profile, limits.public_setup);
                defer expected.deinit();
                const key = expected.key;
                const wires = try a.dupe(@import("block_v5_requester_public_bus_v1.zig").Wire, expected.wires);
                break :expected .{ .key = key, .id = try key.identity(), .wires = wires };
            };
            defer a.free(public_expected.wires);
            const original_requester = public.policy.requester;
            if (!std.meta.eql(public_expected.key, original_requester.fresh.policy.key) or !std.meta.eql(public_expected.id, original_requester.fresh.policy.expected_id) or public_expected.wires.len != original_requester.fresh.policy.wires.len) return error.UnpairedRequesterRootExpectedSetup;
            for (public_expected.wires, original_requester.fresh.policy.wires) |expected, received| if (!std.meta.eql(expected, received)) return error.UnpairedRequesterRootExpectedSetup;
            var independent_memory: ?*IndependentMemory.Owned = null;
            defer if (independent_memory) |owned| owned.deinit();
            var memory_setup_source: ?*const IndependentMemory.Owned = null;
            const memory_expected = expected: {
                const setup_budget = try Budget.createRetainingParent(backing, limits.max_setup_bytes);
                defer setup_budget.destroy();
                const original_public = &public.policy.memory.fresh.public;
                if (comptime memory_setup == .authenticated_fixed) {
                    const expected = authenticated_memory orelse return error.MissingIndependentMemoryRootFixedSetup;
                    try expected.validateAgainstSource(public.policy.memory, capacity, profile, limits.independent_memory_setup);
                    memory_setup_source = expected;
                    break :expected expected.key;
                } else if (comptime memory_setup == .independent_fixed) {
                    const provider = catalogue orelse return error.MissingIndependentPageSemanticClaims;
                    const page_policy = original_public.policy.source.fresh.public.policy;
                    independent_memory = try IndependentMemory.ForBackend(Backend).deriveWithCatalogue(setup_budget.allocator(), page_policy.forest, page_policy.expected_plan, original_public.policy.memory, original_public.policy.expected_memory_plan, capacity, profile, limits.independent_memory_setup, provider);
                    // Release lower fixed setup before compiling upper rows.
                    // Stable policy/frame and independent key custody survives.
                    try independent_memory.?.releaseFixedRows();
                    memory_setup_source = independent_memory.?;
                    try memory_setup_source.?.validateAgainstSource(public.policy.memory, capacity, profile, limits.independent_memory_setup);
                    break :expected independent_memory.?.key;
                } else {
                    var prepared = try MemoryPreparation.prepare(setup_budget.allocator(), original_public, capacity, limits.memory_setup);
                    defer prepared.deinit();
                    break :expected try MemoryProducer.ForBackend(Backend).deriveKey(setup_budget.allocator(), &prepared, original_public, profile);
                }
            };
            const memory_id = try memory_expected.identity();
            if (!std.meta.eql(memory_expected, public.policy.memory.fresh.policy.key) or !std.meta.eql(memory_id, public.policy.memory.fresh.policy.expected_id)) return error.UnpairedMemoryRootExpectedSetup;
            var public_source = try PublicShape.Source.init(a, requester_public, public_expected.key, public_expected.id, public_expected.wires, limits.public_source);
            defer public_source.deinit();
            var memory_source: ?MemoryShape.Source = null;
            defer if (memory_source) |*source| source.deinit();
            if (comptime memory_setup == .original_captures) memory_source = try MemoryShape.Source.init(a, public.policy.memory, memory_expected, memory_id);
            var builder = try FixedAttach.init(a, .{ .max_children = 2, .max_rows = limits.max_rows_per_cohort });
            defer builder.deinit();
            var ids = Context.Owned.init(Protocol.sourceAuthority(), public.policy.memory.fresh.public.policy.memory.memory.seal.memory_plan_digest, public.policy.expected_requester.pins.source);
            try appendChild(a, &builder, &ids, try PublicShape.Admission.init(&public_source), public_expected.id, 0, PublicShape.PUBLIC_CIRCUIT, capacity, limits.pieces);
            if (comptime memory_setup != .original_captures) {
                try appendChild(a, &builder, &ids, try IndependentMemory.Admission.init(memory_setup_source.?), memory_id, 1, IndependentMemory.PUBLIC_CIRCUIT, capacity, limits.pieces);
            } else {
                try appendChild(a, &builder, &ids, try MemoryShape.Admission.init(&memory_source.?), memory_id, 1, MemoryShape.PUBLIC_CIRCUIT, capacity, limits.pieces);
            }
            var graph = try Graph.prepare(a, public);
            defer graph.deinit();
            var fixed_graph = try FixedGraph.Owned.derive(a, &graph.circuit, graph.sources);
            defer fixed_graph.deinit();
            var graph_identifiers = try Identifiers.Owned.init(a, &.{graph.circuit.graph()}, &.{FixedGraph.CIRCUIT});
            defer graph_identifiers.deinit();
            try builder.appendGraphWithArithmetic(fixed_graph.fixed, fixed_graph.wires, fixed_graph.identity, try graph_identifiers.port());
            ids.attachment(builder.attachments.items[builder.attachments.items.len - 1]);
            if (builder.child_count != 2 or builder.main_identifier_rows != 0) return error.MissingRecursiveFixedMainIdentifierPort;
            const closure = try builder.closePublicSupply(Public.Values{ .public = public }, limits.public_supply);
            ids.attachment(closure);
            if (builder.wires.items.len != 0) return error.ClosedRequesterMemoryHasNoPublicTerms;
            var fixed = FixedJoin.empty();
            errdefer FixedJoin.deinit(a, &fixed);
            inline for (0..Storage.Airs.len) |slot| fixed[slot] = try builder.fixed[slot].toOwnedSlice(a);
            // Original final key partitions only after both children, graph
            // and all constrained Boundary suppliers have been joined.
            try FixedJoin.partition(a, &fixed);
            const context = ids.finish(public.policy.expected_requester.coverage.meta.security.recursive);
            const original_authority = try original_requester.fresh.authority();
            try public.validate();
            try public_source.validate();
            if (memory_source) |*source| try source.validate();
            if (memory_setup_source) |owned| try owned.validateAgainstSource(public.policy.memory, capacity, profile, limits.independent_memory_setup);
            _ = try Public.scheduleDigest(&.{});
            return .{ .allocator = a, .backing = backing, .budget = budget, .fixed = fixed, .context = context, .wires = try a.alloc(Public.Wire, 0), .expected_children = .{ public_expected.id, memory_id }, .public_identity = try original_authority.publicInputIdentity(), .closure = closure, .retry_capacity = capacity, .profile = profile, .limits = limits };
        }
        pub fn initViaOriginalMemory(backing: std.mem.Allocator, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits) !Owned {
            return Family.initKernel(.original_captures, backing, public, capacity, profile, limits, null, null);
        }
        /// Typed provider owns independent pre-prove semantic claims; missing
        /// v2 pins fail closed. Original genuine public/Fresh validation remains.
        pub fn initViaIndependentMemory(backing: std.mem.Allocator, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, catalogue: *PageCatalogue.Catalogue) !IndependentOwned {
            return .{ .owned = try Family.initKernel(.independent_fixed, backing, public, capacity, profile, limits, catalogue, null) };
        }
        /// Borrow a genuinely derived V20 setup. Full original Fresh/value
        /// admission, selected catalogue membership and exact original public
        /// framing remain mandatory; no child key or fixed rows are parameters.
        pub fn initViaAuthenticatedMemorySetup(backing: std.mem.Allocator, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, memory: *const IndependentMemory.Owned) !IndependentOwned {
            return .{ .owned = try Family.initKernel(.authenticated_fixed, backing, public, capacity, profile, limits, null, memory) };
        }
        pub fn validateAgainstViaAuthenticatedMemorySetup(self: *const IndependentOwned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, memory: *const IndependentMemory.Owned) !void {
            if (self.owned.retry_capacity != capacity or self.owned.profile != profile or !std.meta.eql(self.owned.limits, limits) or self.owned.wires.len != 0) return error.UntrustedRequesterMemoryFixedAssembly;
            var expected = try Family.initViaAuthenticatedMemorySetup(self.owned.backing, public, capacity, profile, limits, memory);
            defer expected.deinit();
            if (!std.meta.eql(self.owned.context, expected.owned.context) or !std.meta.eql(self.owned.expected_children, expected.owned.expected_children) or !std.meta.eql(self.owned.public_identity, expected.owned.public_identity) or !std.meta.eql(self.owned.closure, expected.owned.closure)) return error.UntrustedRequesterMemoryFixedAssembly;
            inline for (0..Storage.Airs.len) |i| {
                if (self.owned.fixed[i].len != expected.owned.fixed[i].len) return error.UntrustedRequesterMemoryFixedAssembly;
                for (self.owned.fixed[i], expected.owned.fixed[i]) |actual, independent| if (!std.meta.eql(actual, independent)) return error.UntrustedRequesterMemoryFixedAssembly;
            }
        }
        /// Direct canonical factory: own assembly internally, commit the single
        /// original fixed root once, retain only the exact empty schedule.
        pub fn deriveKeyAndScheduleForAuthenticatedMemory(a: std.mem.Allocator, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, memory: *const IndependentMemory.Owned) !KeyAndSchedule {
            var owned = try Family.initViaAuthenticatedMemorySetup(a, public, capacity, profile, limits, memory);
            defer owned.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.owned.fixed, owned.owned.context, profile);
            const key = try Protocol.Key.fromGeometry(geometry, owned.owned.wires);
            _ = try Protocol.Admission.init(key, try key.identity(), owned.owned.wires, .{ .public = public });
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            return .{ .allocator = a, .lease = lease, .key = key, .wires = try a.dupe(Public.Wire, owned.owned.wires) };
        }
        pub fn deriveKeyViaAuthenticatedMemorySetup(a: std.mem.Allocator, self: *const IndependentOwned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, memory: *const IndependentMemory.Owned) !Protocol.Key {
            try Family.validateAgainstViaAuthenticatedMemorySetup(self, public, capacity, profile, limits, memory);
            const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, self.owned.fixed, self.owned.context, profile);
            const key = try Protocol.Key.fromGeometry(geometry, self.owned.wires);
            _ = try Protocol.Admission.init(key, try key.identity(), self.owned.wires, .{ .public = public });
            return key;
        }
        pub fn validateAgainstViaIndependentMemory(self: *const IndependentOwned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, catalogue: *PageCatalogue.Catalogue) !void {
            if (self.owned.retry_capacity != capacity or self.owned.profile != profile or !std.meta.eql(self.owned.limits, limits) or self.owned.wires.len != 0) return error.UntrustedRequesterMemoryFixedAssembly;
            var expected = try Family.initViaIndependentMemory(self.owned.backing, public, capacity, profile, limits, catalogue);
            defer expected.deinit();
            if (!std.meta.eql(self.owned.context, expected.owned.context) or !std.meta.eql(self.owned.expected_children, expected.owned.expected_children) or !std.meta.eql(self.owned.public_identity, expected.owned.public_identity) or !std.meta.eql(self.owned.closure, expected.owned.closure)) return error.UntrustedRequesterMemoryFixedAssembly;
            inline for (0..Storage.Airs.len) |i| {
                if (self.owned.fixed[i].len != expected.owned.fixed[i].len) return error.UntrustedRequesterMemoryFixedAssembly;
                for (self.owned.fixed[i], expected.owned.fixed[i]) |actual, independent| if (!std.meta.eql(actual, independent)) return error.UntrustedRequesterMemoryFixedAssembly;
            }
        }
        pub fn deriveKeyViaIndependentMemory(a: std.mem.Allocator, self: *const IndependentOwned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits, catalogue: *PageCatalogue.Catalogue) !Protocol.Key {
            try Family.validateAgainstViaIndependentMemory(self, public, capacity, profile, limits, catalogue);
            const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, self.owned.fixed, self.owned.context, profile);
            const key = try Protocol.Key.fromGeometry(geometry, self.owned.wires);
            _ = try Protocol.Admission.init(key, try key.identity(), self.owned.wires, .{ .public = public });
            return key;
        }
        pub fn validateAgainstViaOriginalMemory(self: *const Owned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits) !void {
            if (self.retry_capacity != capacity or self.profile != profile or !std.meta.eql(self.limits, limits) or self.wires.len != 0) return error.UntrustedRequesterMemoryFixedAssembly;
            // Independent backing lane avoids charging scratch against retained
            // output metadata; the caller retains the whole aggregate budget.
            var expected = try Family.initViaOriginalMemory(self.backing, public, capacity, profile, limits);
            defer expected.deinit();
            if (!std.meta.eql(self.context, expected.context) or !std.meta.eql(self.expected_children, expected.expected_children) or !std.meta.eql(self.public_identity, expected.public_identity) or !std.meta.eql(self.closure, expected.closure)) return error.UntrustedRequesterMemoryFixedAssembly;
            inline for (0..Storage.Airs.len) |i| {
                if (self.fixed[i].len != expected.fixed[i].len) return error.UntrustedRequesterMemoryFixedAssembly;
                for (self.fixed[i], expected.fixed[i]) |actual, independent| if (!std.meta.eql(actual, independent)) return error.UntrustedRequesterMemoryFixedAssembly;
            }
        }
        pub fn deriveKeyViaOriginalMemory(a: std.mem.Allocator, self: *const Owned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits) !Protocol.Key {
            try Family.validateAgainstViaOriginalMemory(self, public, capacity, profile, limits);
            const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, self.fixed, self.context, profile);
            const key = try Protocol.Key.fromGeometry(geometry, self.wires);
            _ = try Protocol.Admission.init(key, try key.identity(), self.wires, .{ .public = public });
            return key;
        }
    };
}
