//! Shared typed compact-range prover/verifier component owner.
//! Its placement must be supplied by the complete admitted execution statement.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const geometry = @import("../recursion/air/compact_range_geometry.zig");
const roster_mod = @import("../recursion/air/compact_range_roster.zig");
const roster = roster_mod.Roster;
const interaction = @import("../recursion/air/compact_range_interaction.zig");
const Universal = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
const Prepared = std.meta.Tuple(&.{ *interaction.Prepared(.range_check_20), *interaction.Prepared(.range_check_8_11), *interaction.Prepared(.range_check_8_8_4) });
const Q = core.fields.qm31.QM31;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    manifest: roster.Manifest,
    prepared: Prepared = undefined,
    initialized: usize = 0,
    components: roster.Tuple(.component) = undefined,
    relations: Universal = undefined,
    proving: bool,
    bound: bool = false,
    pub fn init(a: std.mem.Allocator, plan: geometry.Plan, expected: [32]u8, origin: roster.Origin, proving: bool) !*Owner {
        const manifest = try roster_mod.admittedManifest(plan, expected, origin);
        const self = try a.create(Owner);
        self.* = .{ .allocator = a, .manifest = manifest, .proving = proving };
        errdefer self.deinit();
        inline for (geometry.kinds, 0..) |kind, i| {
            const P = interaction.Prepared(kind);
            self.prepared[i] = if (proving) try P.init(a, plan, expected) else try P.initVerifier(a, plan, expected);
            self.initialized += 1;
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        inline for (0..geometry.kinds.len) |i| {
            if (i < self.initialized) self.prepared[i].deinit();
        }
        a.destroy(self);
    }
    /// Rebind challenges/claims while keeping authenticated definitions and
    /// inversion buffers. Invalidate handles before any fallible construction.
    pub fn bind(self: *Owner, relations: Universal, claims: [3]Q) !void {
        self.bound = false;
        self.relations = relations;
        inline for (roster.Airs, 0..) |Air, i| {
            const prepared = self.prepared[i];
            self.components[i] = try roster.Component(Air).init(&prepared.definition, prepared.plan, &self.manifest, @enumFromInt(i), prepared.shape.log_size, .{}, &self.relations, claims[i]);
        }
        self.bound = true;
    }
    /// End placement for the following component group (normally BLAKE3).
    pub fn endOrigin(self: *const Owner) !roster.Origin {
        const last = try self.manifest.placement(@enumFromInt(2));
        const Air = roster.Airs[2];
        return .{
            .columns = .{
                try std.math.add(u32, last.preprocessed_offset, Air.PREPROCESSED_COLUMN_COUNT),
                try std.math.add(u32, last.main_offset, Air.PHYSICAL_MAIN_COLUMN_COUNT),
                try std.math.add(u32, last.interaction_offset, Air.INTERACTION_COLUMN_COUNT),
                try std.math.add(u32, last.constraint_offset, Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT),
            },
            .claimed_sum_index = try std.math.add(u32, last.claimed_sum_index, 1),
        };
    }
    /// All validation precedes the first destination write. The table remains
    /// unchanged when unbound, misordered or full; handles borrow this owner.
    pub fn appendProvers(self: *Owner, table: anytype) !void {
        const handles = try self.provers();
        try self.validateAppend(table);
        for (handles) |handle| table.push(handle);
    }
    pub fn appendVerifiers(self: *Owner, table: anytype) !void {
        const handles = try self.verifiers();
        try self.validateAppend(table);
        for (handles) |handle| table.push(handle);
    }
    fn validateAppend(self: *const Owner, table: anytype) !void {
        if (table.n_handles != self.manifest.origin.claimed_sum_index) return error.CompactRangeComponentOrderMismatch;
        if (table.n_handles > table.handles.len or table.handles.len - table.n_handles < 3) return error.CompactRangeComponentCapacityExceeded;
        _ = try self.endOrigin();
    }
    pub fn provers(self: *Owner) ![3]engine.air.component_prover.ComponentProver {
        if (!self.bound) return error.CompactRangeComponentsNotBound;
        if (!self.proving) return error.VerifierOnlyCompactRangePreparation;
        var result: [3]engine.air.component_prover.ComponentProver = undefined;
        inline for (0..3) |i| result[i] = self.components[i].asProverComponent();
        return result;
    }
    pub fn verifiers(self: *Owner) ![3]core.air.components.Component {
        if (!self.bound) return error.CompactRangeComponentsNotBound;
        var result: [3]core.air.components.Component = undefined;
        inline for (0..3) |i| result[i] = self.components[i].asVerifierComponent();
        return result;
    }
};
