//! Exact original namespace metadata, without pretending that fixed rows are a
//! MAIN witness. The two legacy arithmetic schedules need a live parity check
//! until their MAIN identifier emission has an independently factored port.
const std = @import("std");
const core = @import("stwo_core");
const Storage = @import("blake3_parent_row_storage.zig");
const Original = @import("blake3_parent_rebase.zig");
const Namespace = @import("blake3_parent_namespace.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Fusion = @import("arithmetic_fusion_rows.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
pub const ArithmeticPort = struct { plan: *const Lower.Plan, reference: Lower.Reference, kind: Lower.ProofKind };
const Masks = blk: {
    var types: [Storage.Airs.len]type = undefined;
    for (Storage.Airs, &types) |Air, *T| T.* = [Air.LOGICAL_INPUT_COUNT]bool;
    break :blk std.meta.Tuple(&types);
};
pub const Plan = struct {
    original: Original.Plan,
    main_identifier_rows: usize,
    lease: ?*Budget,
    pub fn end(self: *const Plan) !u32 {
        return self.original.end();
    }
    pub fn identity(self: *const Plan) ![32]u8 {
        return self.original.identity();
    }
    pub fn deinit(self: *Plan) void {
        const lease = self.lease;
        self.original.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    /// Independent live compiler comparison, never a received namespace token.
    /// This cannot be substituted by comparing a resealed fixed-only output.
    pub fn validateLive(self: *const Plan, parent: anytype) !void {
        var expected = try Original.prepare(self.original.allocator, parent, self.original.first);
        defer expected.deinit();
        if (!std.mem.eql(u32, self.original.old, expected.old) or !std.meta.eql(try self.identity(), try expected.identity())) return error.UntrustedRecursiveFixedNamespace;
    }
    pub fn requireIndependentMainPort(self: *const Plan) !void {
        if (self.main_identifier_rows != 0) return error.MissingRecursiveFixedMainIdentifierPort;
    }
};
pub fn prepare(a: std.mem.Allocator, fixed: Storage.FixedTuple(false), first: u32) !Plan {
    return prepareImpl(a, fixed, first, null);
}
/// Reconstruct actual MAIN identifier emission from the ORIGINAL immutable
/// arithmetic plan. A proposed identifier array is deliberately not accepted.
pub fn prepareForArithmetic(a: std.mem.Allocator, fixed: Storage.FixedTuple(false), first: u32, port: ArithmeticPort) !Plan {
    var identifiers = try Fusion.materializeIdentifiers(a, port.plan, port.reference, port.kind);
    defer identifiers.deinit();
    if (identifiers.inverse.len != fixed[4].len or identifiers.linear.len != fixed[5].len) return error.InvalidRecursiveFixedIdentifierCount;
    return prepareImpl(a, fixed, first, &identifiers);
}
fn prepareImpl(a: std.mem.Allocator, fixed: Storage.FixedTuple(false), first: u32, identifiers: ?*const Fusion.Identifiers) !Plan {
    if (first == 0) return error.InvalidParentRebase;
    const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
    errdefer if (lease) |owner| owner.destroy();
    var ids = std.AutoHashMap(u32, void).init(a);
    defer ids.deinit();
    var main_rows: usize = 0;
    inline for (Storage.Airs, 0..) |Air, i| if (fixed[i].len != 0) {
        var definition = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
        defer definition.deinit();
        const mask = try Namespace.renamingColumns(Air, &definition);
        for (mask[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |used, column| if (used) {
            // Explicitly classify original typed AIRs, without reading or
            // guessing a private MAIN circuit from a supplied witness.
            if ((Air != Storage.Airs[4] or column != 9) and (Air != Storage.Airs[5] or column != 1)) return error.UnsupportedRecursiveFixedMainNamespace;
            if (identifiers) |emitted| {
                const selected = if (comptime i == 4) emitted.inverse else emitted.linear;
                for (selected) |id| {
                    if (id >= core.fields.m31.Modulus) return error.InvalidParentRebase;
                    try ids.put(id, {});
                }
            } else main_rows = try std.math.add(usize, main_rows, fixed[i].len);
        };
        for (mask[Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |used, column| if (used) {
            for (fixed[i]) |row| {
                if (row[column].v >= core.fields.m31.Modulus) return error.InvalidParentRebase;
                try ids.put(row[column].toU32(), {});
            }
        };
    };
    const old = try a.alloc(u32, ids.count());
    errdefer a.free(old);
    var it = ids.keyIterator();
    var n: usize = 0;
    while (it.next()) |id| : (n += 1) old[n] = id.*;
    std.mem.sort(u32, old, {}, std.sort.asc(u32));
    const plan = Plan{ .original = .{ .allocator = a, .first = first, .old = old }, .main_identifier_rows = main_rows, .lease = lease };
    _ = try plan.end();
    return plan;
}
/// All checks precede mutation. MAIN is deliberately absent; this operation
/// cannot be used to bypass Original.apply in a live verifier preparation.
pub fn apply(fixed: *Storage.FixedTuple(false), plan: *const Plan, expected: [32]u8) !void {
    if (!std.meta.eql(try plan.identity(), expected)) return error.UntrustedParentRebase;
    var masks: Masks = undefined;
    inline for (Storage.Airs, 0..) |Air, i| {
        masks[i] = @splat(false);
        if (fixed.*[i].len != 0) {
            var definition = if (@hasDecl(Air, "Location")) try Air.build(plan.original.allocator, .generated) else try Air.build(plan.original.allocator);
            defer definition.deinit();
            masks[i] = try Namespace.renamingColumns(Air, &definition);
        }
        for (masks[i][Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |used, column| if (used) {
            for (fixed.*[i]) |row| if (plan.original.map(row[column].toU32()) == null) return error.StaleParentRebase;
        };
    }
    // No allocations/validation may fail in this write pass.
    inline for (Storage.Airs, 0..) |Air, i| {
        for (masks[i][Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |used, column| if (used) {
            for (fixed.*[i]) |*row| row[column] = core.fields.m31.M31.fromCanonical(plan.original.map(row[column].toU32()).?);
        };
    }
}
