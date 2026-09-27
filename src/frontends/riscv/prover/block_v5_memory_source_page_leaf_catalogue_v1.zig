//! Durable independent PAGE setup with bounded transient descriptor custody.
//! Stable slots preserve original pin/template/census metadata. Idle slots have
//! a zero capture allowance and cannot pass the original strict admission.
//! A scope must outlive every original capture, leaf Fresh and source reader
//! borrowing its Prepared. This owner grants no proof or aggregate receipt.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const PolicyFile = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Admission = @import("block_v5_memory_source_page_recursive_admission_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Inventory = @import("block_v5_memory_source_fold_inventory_owner_v1.zig");
const Durable = @import("block_v5_memory_source_page_durable_loader_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig");
const RawSetup = Components.ForKind(.raw).CoreColumns.Setup;
const FoldSetup = Components.ForKind(.fold).CoreColumns.Setup;
pub const Limits = struct {
    policy: PolicyFile.Limits = .{},
    recursive: Admission.Limits = .{},
    max_owned_bytes: usize = 1 << 30,
    max_scope_bytes: usize = 128 << 20,
    max_slots: usize = 524288,
    pub fn validate(self: Limits) !void {
        try self.policy.validate();
        if (self.max_owned_bytes == 0 or self.max_scope_bytes == 0 or self.max_slots == 0 or
            self.recursive.max_capture_bytes == 0 or self.recursive.max_preparation_bytes == 0 or
            self.recursive.max_public_wires == 0 or !std.meta.eql(self.policy.pages, self.recursive.page)) return error.InvalidPageLeafCatalogueLimits;
    }
};
/// Pure coordinator state. Only a live single coordinator may acquire/release;
/// no concurrent mutation or source borrower may race the final release.
pub const Occupancy = struct {
    count: u32 = 0,
    serial: u64 = 0,
    pub fn begin(self: *Occupancy) !u64 {
        if (self.count >= 4) return error.PageLeafCatalogueBackpressure;
        const next = try std.math.add(u64, self.serial, 1);
        self.serial = next;
        self.count += 1;
        return next;
    }
    pub fn end(self: *Occupancy) void {
        std.debug.assert(self.count != 0);
        self.count -= 1;
    }
};
const State = struct { ticket: u64 = 0 };
pub const Catalogue = struct {
    budget: *Budget,
    dir: std.fs.Dir,
    policy: *PolicyFile.Owned,
    raw_setup: *const RawSetup,
    fold_setup: *const FoldSetup,
    arithmetic_setup: *const Components.ArithmeticSetup,
    raw: []Admission.ForKind(.raw).Prepared,
    fold: []Admission.ForKind(.fold).Prepared,
    raw_states: []State,
    fold_states: []State,
    occupancy: Occupancy = .{},
    limits: Limits,
    pub const complete_source_authority = false;
    pub fn allocator(self: *Catalogue) std.mem.Allocator {
        return self.budget.allocator();
    }
    pub fn context(self: *const Catalogue) *const Page.Context {
        return &self.policy.context;
    }
    pub fn create(backing: std.mem.Allocator, dir: std.fs.Dir, pin: PolicyFile.Pin, globals: Global.Pins, limits: Limits) !*Catalogue {
        try limits.validate();
        const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Catalogue);
        errdefer a.destroy(self);
        var owned_dir = std.fs.Dir{ .fd = try std.posix.dup(dir.fd) };
        errdefer owned_dir.close();
        const policy = try PolicyFile.read(a, owned_dir, pin, globals, limits.policy);
        errdefer policy.deinit();
        const count = try std.math.add(usize, policy.context.raw.len, policy.context.fold.len);
        if (count > limits.max_slots) return error.PageLeafCatalogueResourceLimit;
        const raw_setup = try RawSetup.create(a);
        errdefer raw_setup.release();
        const fold_setup = try FoldSetup.create(a);
        errdefer fold_setup.release();
        const arithmetic_setup = try Components.ArithmeticSetup.create(a);
        errdefer arithmetic_setup.release();
        const raw = try a.alloc(Admission.ForKind(.raw).Prepared, policy.context.raw.len);
        errdefer a.free(raw);
        const fold = try a.alloc(Admission.ForKind(.fold).Prepared, policy.context.fold.len);
        errdefer a.free(fold);
        const raw_states = try a.alloc(State, raw.len);
        errdefer a.free(raw_states);
        const fold_states = try a.alloc(State, fold.len);
        errdefer a.free(fold_states);
        @memset(raw_states, .{});
        @memset(fold_states, .{});
        self.* = .{ .budget = budget, .dir = owned_dir, .policy = policy, .raw_setup = raw_setup, .fold_setup = fold_setup, .arithmetic_setup = arithmetic_setup, .raw = raw, .fold = fold, .raw_states = raw_states, .fold_states = fold_states, .limits = limits };
        for (raw, policy.context.raw) |*slot, original| {
            slot.* = try Admission.ForKind(.raw).Prepared.init(a, &policy.context, original, &.{}, raw_setup, arithmetic_setup, limits.recursive);
            slot.limits.max_capture_bytes = 0;
        }
        // Sequential exact inventory admission: one metadata page resident,
        // never a whole-job recipe/descriptor array. Original identity is kept.
        for (fold, policy.context.fold, 0..) |*slot, original, i| {
            var path: [96]u8 = undefined;
            const scope_budget = try Budget.createRetainingParent(a, limits.max_scope_bytes);
            defer scope_budget.destroy();
            var inventory = try Inventory.load(scope_budget.allocator(), owned_dir, try Durable.name(&path, .fold, @intCast(i), false), original, policy.parsed.value.fold[i].operands, limits.policy.pages.fold);
            defer inventory.deinit();
            slot.* = try Admission.ForKind(.fold).Prepared.init(a, &policy.context, original, inventory.rows, fold_setup, arithmetic_setup, limits.recursive);
            slot.fold_rows = &.{};
            slot.limits.max_capture_bytes = 0;
        }
        return self;
    }
    pub fn deinit(self: *Catalogue) void {
        // A caller must destroy nested Fresh/capture/Source readers before the
        // scope, and every scope before this owner. Never silently invalidate.
        std.debug.assert(self.occupancy.count == 0);
        const budget = self.budget;
        const a = budget.allocator();
        a.free(self.raw_states);
        a.free(self.fold_states);
        a.free(self.raw);
        a.free(self.fold);
        self.arithmetic_setup.release();
        self.fold_setup.release();
        self.raw_setup.release();
        self.policy.deinit();
        self.dir.close();
        a.destroy(self);
        budget.destroy();
    }
    /// Metadata provenance check independent of transient descriptor activation.
    /// The exact original Prepared.validate remains mandatory for acceptance.
    pub fn requireCompact(self: *const Catalogue, comptime kind: Semantic.Kind, index: u32) !void {
        const slots = if (kind == .raw) self.raw else self.fold;
        const pins = if (kind == .raw) self.policy.context.raw else self.policy.context.fold;
        if (index >= slots.len or slots.len != pins.len) return error.UntrustedPageLeafCatalogueSlot;
        const slot = &slots[index];
        if (slot.context != &self.policy.context or !std.meta.eql(slot.pin, pins[index]) or
            slot.core_setup != (if (kind == .raw) self.raw_setup else self.fold_setup) or slot.arithmetic_setup != self.arithmetic_setup or
            !std.meta.eql(slot.config, self.policy.context.fold_plan.config) or !std.meta.eql(slot.limits.page, self.limits.recursive.page) or
            slot.limits.max_preparation_bytes != self.limits.recursive.max_preparation_bytes or slot.limits.max_public_wires != self.limits.recursive.max_public_wires) return error.UntrustedPageLeafCatalogueSlot;
    }
    /// Used only by the independently reconstructed forest setup constructor.
    /// A temporary real inventory scope runs the unchanged strict Policy check.
    pub fn validateLeaf(self: *Catalogue, comptime kind: Semantic.Kind, index: u32, policy: @import("../recursion/block_v5_memory_source_page_forest_leaf_v1.zig").ForKind(kind).Policy) !void {
        var scope = try self.acquire(kind, index);
        defer scope.deinit();
        if (policy.admitted != try scope.prepared()) return error.UntrustedPageLeafCatalogueSlot;
        try policy.validate();
    }
    pub fn acquire(self: *Catalogue, comptime kind: Semantic.Kind, index: u32) !Scope(kind) {
        try self.requireCompact(kind, index);
        const states = if (kind == .raw) self.raw_states else self.fold_states;
        const slots = if (kind == .raw) self.raw else self.fold;
        if (states[index].ticket != 0 or slots[index].limits.max_capture_bytes != 0 or slots[index].fold_rows.len != 0) return error.PageLeafCatalogueAlreadyLeased;
        const ticket = try self.occupancy.begin();
        errdefer self.occupancy.end();
        const budget = try Budget.createRetainingParent(self.allocator(), self.limits.max_scope_bytes);
        errdefer budget.destroy();
        var inventory: ?Inventory.Owner = null;
        errdefer if (inventory) |*owner| owner.deinit();
        if (kind == .fold) {
            var path: [96]u8 = undefined;
            inventory = try Inventory.load(budget.allocator(), self.dir, try Durable.name(&path, .fold, index, false), self.policy.context.fold[index], self.policy.parsed.value.fold[index].operands, self.limits.policy.pages.fold);
        }
        const core_setup = if (kind == .raw) self.raw_setup else self.fold_setup;
        const active = try Admission.ForKind(kind).Prepared.init(budget.allocator(), self.context(), slots[index].pin, if (inventory) |owner| owner.rows else &.{}, core_setup, self.arithmetic_setup, self.limits.recursive);
        if (!std.meta.eql(active.template_id, slots[index].template_id)) return error.UntrustedPageLeafCatalogueSlot;
        slots[index] = active;
        states[index].ticket = ticket;
        return .{ .catalogue = self, .budget = budget, .index = index, .ticket = ticket, .inventory = inventory };
    }
};
pub fn Scope(comptime kind: Semantic.Kind) type {
    return struct {
        catalogue: *Catalogue,
        budget: *Budget,
        index: u32,
        ticket: u64,
        inventory: ?Inventory.Owner,
        pub fn prepared(self: *const @This()) !*const Admission.ForKind(kind).Prepared {
            try self.catalogue.requireCompact(kind, self.index);
            const states = if (kind == .raw) self.catalogue.raw_states else self.catalogue.fold_states;
            const slots = if (kind == .raw) self.catalogue.raw else self.catalogue.fold;
            if (self.ticket == 0 or states[self.index].ticket != self.ticket) return error.ReleasedPageLeafCatalogueScope;
            const slot = &slots[self.index];
            if (slot.limits.max_capture_bytes != self.catalogue.limits.recursive.max_capture_bytes or slot.fold_rows.len != (if (self.inventory) |owner| owner.rows.len else 0)) return error.UntrustedPageLeafCatalogueSlot;
            if (self.inventory) |owner| if (slot.fold_rows.ptr != owner.rows.ptr) return error.UntrustedPageLeafCatalogueSlot;
            try slot.validate(slot.template_id);
            return slot;
        }
        /// The independently pinned version-2 pre-proof proposal. No native
        /// file is opened and no verified capture supplies these constants.
        pub fn expectedClaims(self: *const @This()) !Semantic.Claims {
            _ = try self.prepared();
            if (self.catalogue.policy.parsed.value.version != PolicyFile.VERSION) return error.MissingIndependentPageSemanticClaims;
            const records = if (kind == .raw) self.catalogue.policy.parsed.value.raw else self.catalogue.policy.parsed.value.fold;
            return PolicyFile.expectedClaims(kind, records[self.index].expected_claims);
        }
        pub fn decodeOriginal(self: *const @This(), a: std.mem.Allocator) !Page.ForKind(kind).Proof {
            const admitted = try self.prepared();
            const records = if (kind == .raw) self.catalogue.policy.parsed.value.raw else self.catalogue.policy.parsed.value.fold;
            const pin = records[self.index].artifact;
            var path: [96]u8 = undefined;
            const bytes = try Files.readPinned(a, self.catalogue.dir, try Durable.name(&path, kind, self.index, true), pin.byte_len, pin.sha256, self.catalogue.limits.policy.codec.max_artifact_bytes);
            defer a.free(bytes);
            return Codec.ForKind(kind).decodeProposal(a, bytes, admitted.context, admitted.pin, admitted.fold_rows, admitted.limits.page, self.catalogue.limits.policy.codec);
        }
        pub fn deinit(self: *@This()) void {
            const states = if (kind == .raw) self.catalogue.raw_states else self.catalogue.fold_states;
            const slots = if (kind == .raw) self.catalogue.raw else self.catalogue.fold;
            std.debug.assert(self.ticket != 0 and states[self.index].ticket == self.ticket);
            states[self.index].ticket = 0;
            slots[self.index].fold_rows = &.{};
            slots[self.index].limits.max_capture_bytes = 0;
            slots[self.index].allocator = self.catalogue.allocator();
            self.catalogue.occupancy.end();
            if (self.inventory) |*owner| owner.deinit();
            self.budget.destroy();
            self.* = undefined;
        }
    };
}
pub const AnyScope = union(enum) { raw: Scope(.raw), fold: Scope(.fold) };
pub const Group = struct {
    slots: [4]AnyScope = undefined,
    count: usize = 0,
    /// Acquire only direct original leaves; compact lower parents use no leaf
    /// descriptor leases. Every caller destroys readers before Group.deinit.
    pub fn acquire(catalogue: *Catalogue, refs: []const @import("../recursion/block_v5_memory_source_page_forest_plan_v1.zig").Ref) !Group {
        if (refs.len > 4) return error.PageLeafCatalogueBackpressure;
        var self = Group{};
        errdefer self.deinit();
        for (refs) |ref| if (ref == .leaf) {
            self.slots[self.count] = if (ref.leaf < catalogue.raw.len) .{ .raw = try catalogue.acquire(.raw, ref.leaf) } else .{ .fold = try catalogue.acquire(.fold, ref.leaf - @as(u32, @intCast(catalogue.raw.len))) };
            self.count += 1;
        };
        return self;
    }
    pub fn deinit(self: *Group) void {
        while (self.count != 0) {
            self.count -= 1;
            switch (self.slots[self.count]) {
                .raw => |*scope| scope.deinit(),
                .fold => |*scope| scope.deinit(),
            }
        }
    }
};
