//! Independently reconstructed PUBLIC21 fixed family assembly. The original
//! requester verifier, tuple/B5SS rows, namespaces, join and context are used.
//! This derives expected setup; only the original Fresh receiver accepts proof.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("block_v5_requester_public_compensation_v1.zig");
const Protocol = @import("block_v5_requester_public_protocol_v1.zig");
const Bus = @import("block_v5_requester_public_bus_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Requester = @import("block_v5_requester_recursive_shape_admission_v1.zig");
const Pieces = @import("block_v5_recursive_parent_fixed_pieces_v1.zig").ForAdmission(Requester.Admission);
const Roster = @import("block_v5_recursive_parent_fixed_roster_v1.zig").ForPackedAdmission(Requester.Admission);
const Tuple = @import("air/block_v5_requester_public_fixed_rows_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Suppliers = @import("air/block_v5_recursive_fixed_child_suppliers_v1.zig");
const Identifiers = @import("air/block_v5_requester_public_fixed_identifier_ports_v1.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Graph = @import("air/composition_circuit.zig").CircuitGraph;
const Join = @import("air/block_v5_requester_public_fixed_join_v1.zig");
const Ports = @import("block_v5_requester_public_assembly_ports_v1.zig");
const TupleKernel = @import("air/block_v5_global_public_export_rows_v1.zig");
pub const Limits = struct {
    max_bytes: usize = 8 << 30,
    max_rows_per_cohort: usize = 1 << 24,
    pieces: Pieces.Limits = .{},
    tuples: Tuple.Limits = .{},
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Bus.Wire,
    context: Base.Context,
    profile: Protocol.Profile,
    retry_capacity: u32,
    limits: Limits,
    public_identity: [32]u8,
    requester_expected: [32]u8,
    pub const complete_block_authority = false;
    pub const reusable_across_instances = false;
    /// Independent Public.Owner/Scoped catalogue must stay immutable through
    /// expected-key reconstruction and all original producer/receiver policies.
    pub fn init(backing: std.mem.Allocator, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits) !Owned {
        @setEvalBranchQuota(20_000);
        if (capacity == 0 or limits.max_bytes == 0 or limits.max_rows_per_cohort == 0 or limits.max_rows_per_cohort > 1 << 24) return error.RequesterPublicFixedResourceLimit;
        try public.validate();
        if (!std.meta.eql(profile.config(), public.requester.coverage.meta.security.recursive)) return error.UntrustedRequesterPublicSecurity;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var source = try Requester.Source.init(public.requester);
        defer source.deinit();
        if (!std.meta.eql(public.compact.seal, source.compact.seal) or !std.meta.eql(public.compact.ref, source.compact.ref)) return error.UnpairedRequesterPublicSource;
        const admission = try Requester.Admission.init(&source);
        const pieces = try Pieces.Owned.init(a, &admission, capacity, limits.pieces);
        defer pieces.deinit();
        const child = try Roster.Owned.init(a, pieces, &admission);
        defer child.deinit();
        const child_wires = try Suppliers.collect(a, pieces.transcript.fixed.fixed, &pieces.composition, source.terms.len, 0, Requester.PUBLIC_CIRCUIT);
        defer a.free(child_wires);
        const graphs = [3]Graph{ pieces.composition.circuit.graph(), pieces.arithmetic.deep_graph.graph(), pieces.arithmetic.fri_graph.graph() };
        var child_identifiers = try Identifiers.Owned.init(a, &graphs, &.{ 1500, 1502, 1504 });
        defer child_identifiers.deinit();
        var child_namespace = try Namespace.prepareForArithmetic(a, child.fixed, 1, try child_identifiers.port());
        defer child_namespace.deinit();
        try child_namespace.requireIndependentMainPort();
        const child_end = try child_namespace.end();
        const child_namespace_id = try child_namespace.identity();
        for (child_wires) |*wire| wire.circuit = child_namespace.original.map(wire.circuit) orelse return error.MissingRequesterPublicNamespace;
        try Namespace.apply(&child.fixed, &child_namespace, child_namespace_id);
        var tuple = try Tuple.Owned.init(a, public, capacity, limits.tuples);
        defer tuple.deinit();
        var tuple_view: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| tuple_view[i] = tuple.fixed.rows.rows[i];
        const tuple_graph = [_]Graph{tuple.graph.circuit.graph()};
        var tuple_identifiers = try Identifiers.Owned.init(a, &tuple_graph, &.{TupleKernel.GRAPH});
        defer tuple_identifiers.deinit();
        var tuple_namespace = try Namespace.prepareForArithmetic(a, tuple_view, child_end, try tuple_identifiers.port());
        defer tuple_namespace.deinit();
        try tuple_namespace.requireIndependentMainPort();
        const tuple_namespace_id = try tuple_namespace.identity();
        for (tuple.fixed.wires) |*wire| wire.circuit = tuple_namespace.original.map(wire.circuit) orelse return error.MissingRequesterPublicNamespace;
        try Namespace.apply(&tuple_view, &tuple_namespace, tuple_namespace_id);
        var wires: std.ArrayList(Bus.Wire) = .empty;
        errdefer wires.deinit(a);
        for (child_wires) |wire| try wires.append(a, try Ports.childWire(wire));
        try wires.appendSlice(a, tuple.fixed.wires);
        try Ports.sortAndRequire(wires.items);
        var fixed = try Join.join(a, child.fixed, tuple_view, limits.max_rows_per_cohort);
        errdefer Join.deinit(a, &fixed);
        const context = Ports.context(.{
            .source_authority = Protocol.sourceAuthority(),
            .public_identity = public.identity,
            .requester_expected = source.compact.expected_id,
            .tuple_identity = tuple.fixed.identity,
            .child_namespace = child_namespace_id,
            .tuple_namespace = tuple_namespace_id,
            .child = .{ .child_key_id = source.compact.expected_id, .child_config = admission.key.config, .graph_ids = child.graph_ids, .transcript_plan_id = child.transcript_id },
        });
        try public.validate();
        try admission.validate();
        return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = try wires.toOwnedSlice(a), .context = context, .profile = profile, .retry_capacity = capacity, .limits = limits, .public_identity = public.identity, .requester_expected = source.compact.expected_id };
    }
    /// Caller supplies original independently chosen parameters. Resealing a
    /// proposal cannot select another family recipe, capacity or public source.
    pub fn validateAgainst(self: *const Owned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits) !void {
        if (self.retry_capacity != capacity or self.profile != profile or !std.meta.eql(self.limits, limits)) return error.UntrustedRequesterPublicFixedAssembly;
        var expected = try Owned.init(self.allocator, public, capacity, profile, limits);
        defer expected.deinit();
        if (!std.meta.eql(self.context, expected.context) or !std.meta.eql(self.public_identity, expected.public_identity) or !std.meta.eql(self.requester_expected, expected.requester_expected) or self.wires.len != expected.wires.len) return error.UntrustedRequesterPublicFixedAssembly;
        for (self.wires, expected.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedRequesterPublicFixedAssembly;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != expected.fixed[i].len) return error.UntrustedRequesterPublicFixedAssembly;
            for (self.fixed[i], expected.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedRequesterPublicFixedAssembly;
        }
    }
    /// Actual old live compiler parity, provided only by a genuinely prepared
    /// caller. This routine never constructs/accepts a Fresh or MAIN witness.
    pub fn validateLive(self: *const Owned, live: *@import("block_v5_requester_public_preparation_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedRequesterPublicFixedAssembly;
        for (self.wires, live.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedRequesterPublicFixedAssembly;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedRequesterPublicFixedAssembly;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedRequesterPublicFixedAssembly;
        }
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        a.free(self.wires);
        Join.deinit(a, &self.fixed);
        self.* = undefined;
        budget.destroy();
    }
};
/// Owned schedule metadata from an internally constructed family setup.
/// Deinitialization releases only this copied schedule, never Public.Owner.
pub const KeyAndSchedule = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    key: Protocol.Key,
    wires: []Bus.Wire,
    pub fn deinit(self: *KeyAndSchedule) void {
        const lease = self.lease;
        self.allocator.free(self.wires);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Canonical constructor owns the entire independent fixed setup;
        /// commit its original fixed columns once, then release all rows.
        pub fn deriveKeyAndScheduleForPolicy(a: std.mem.Allocator, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits) !KeyAndSchedule {
            var owned = try Owned.init(a, public, capacity, profile, limits);
            defer owned.deinit();
            const base = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, profile);
            const key = try Protocol.Key.fromGeometry(base, owned.wires);
            _ = try Protocol.Admission.init(key, try key.identity(), owned.wires, .{ .public = public });
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            return .{ .allocator = a, .lease = lease, .key = key, .wires = try a.dupe(Bus.Wire, owned.wires) };
        }
        /// Fixed PCS commitment is the original single root-only body. The
        /// resulting key is expected setup, not a proof-acceptance receipt.
        pub fn deriveKey(a: std.mem.Allocator, owned: *const Owned, public: *const Public.Owner, capacity: u32, profile: Protocol.Profile, limits: Limits) !Protocol.Key {
            try owned.validateAgainst(public, capacity, profile, limits);
            const base = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, profile);
            const key = try Protocol.Key.fromGeometry(base, owned.wires);
            _ = try Protocol.Admission.init(key, try key.identity(), owned.wires, .{ .public = public });
            return key;
        }
    };
}
