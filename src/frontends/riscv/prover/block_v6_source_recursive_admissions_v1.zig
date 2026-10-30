//! Owned independent PAGE policy for mixed-root reconstruction. This owner
//! contains no producer proof, witness matrix, transported success receipt or
//! authority to close a block. Context and fold inventory must come from the
//! independently selected job manifest; original fixed roots authenticate them.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Pages = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Admission = @import("block_v5_memory_source_page_recursive_admission_v1.zig");
const Job = @import("block_v5_memory_source_page_job_v1.zig");
const SHA = @import("block_v5_memory_source_packed_sha_columns_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Fixed = @import("block_v5_memory_source_fold_fixed_columns_v1.zig");
const Premix = @import("block_v5_memory_source_fold_premix_v1.zig");
const Mixed = @import("../recursion/block_v6_mixed_direct_public_v1.zig");
const Reconstruct = @import("../recursion/block_v6_mixed_claim_reconstruct_v1.zig");
pub const Limits = struct {
    page: Admission.Limits = .{},
    max_pages: usize = Mixed.MAX_CHILDREN,
    max_metadata_bytes: usize = 64 << 20,
    max_setup_bytes: usize = 256 << 20,
};
pub const Owner = struct {
    backing: std.mem.Allocator,
    budget: *Budget,
    context: Pages.Context,
    inventories: []Job.FoldInventory,
    sha: *const SHA.Setup,
    blake: *const Blake.Setup,
    arithmetic: *const Components.ArithmeticSetup,
    raw: []Admission.ForKind(.raw).Prepared,
    fold: []Admission.ForKind(.fold).Prepared,
    expected: []Mixed.Expected,
    inputs: []Reconstruct.Input,

    /// Extract only bounded public routing metadata from the original pinned
    /// operand files. No wide hash columns or commitments are reconstructed.
    /// The independently supplied context remains the policy; Job records and
    /// file hashes cannot select a different page roster or source epoch.
    pub fn createFromJob(backing: std.mem.Allocator, job: anytype, context: *const Pages.Context, limits: Limits) !*Owner {
        if (context.raw.len + context.fold.len > limits.max_pages or limits.max_pages > Mixed.MAX_CHILDREN or
            job.raws.len != context.raw.len or job.folds.len != context.fold.len or
            !std.meta.eql(job.admitted, context.admitted) or !std.meta.eql(job.raw_plan, context.raw_plan) or
            !std.meta.eql(job.fold_plan, context.fold_plan) or !std.meta.eql(job.base, context.base))
            return error.UntrustedSourceRecursiveJob;
        for (job.raws, context.raw) |record, pin| if (!std.meta.eql(record.pin, pin)) return error.UntrustedSourceRecursiveJob;
        const temporary = try Budget.createRetainingParent(backing, limits.max_metadata_bytes);
        defer temporary.destroy();
        const a = temporary.allocator();
        const inventories = try a.alloc(Job.FoldInventory, context.fold.len);
        var count: usize = 0;
        defer {
            for (inventories[0..count]) |*inventory| inventory.deinit();
            a.free(inventories);
        }
        const views = try a.alloc([]const Semantic.FoldRow, context.fold.len);
        defer a.free(views);
        const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
        for (job.folds, context.fold, inventories, views, 0..) |record, pin, *inventory, *view, i| {
            if (!std.meta.eql(record.pin, pin)) return error.UntrustedSourceRecursiveJob;
            try pin.require(&context.admitted, context.fold_plan, limits.page.page.protocol);
            var path: [96]u8 = undefined;
            var loaded = try Store.load(a, job.dir, try Job.name(&path, .fold, @intCast(i), false), pin.page, context.fold_plan.identity, try pin.identity(&context.admitted, context.fold_plan, limits.page.page.protocol), record.stored, limits.page.page.fold.stored);
            defer loaded.deinit();
            inventory.* = try inventoryFromOperations(a, loaded.operations, limits.max_metadata_bytes);
            count += 1;
            view.* = inventory.rows;
        }
        return create(backing, context, views, limits);
    }

    pub fn create(backing: std.mem.Allocator, context: *const Pages.Context, fold_rows: []const []const Semantic.FoldRow, limits: Limits) !*Owner {
        const count = try std.math.add(usize, context.raw.len, context.fold.len);
        if (count == 0 or limits.max_pages == 0 or limits.max_pages > Mixed.MAX_CHILDREN or count > limits.max_pages or
            fold_rows.len != context.fold.len or limits.max_metadata_bytes == 0 or limits.max_setup_bytes == 0)
            return error.SourceRecursiveAdmissionResourceLimit;
        try context.require(backing, limits.page.page);
        // Charge metadata before allocating it; the shared budget additionally
        // bounds authenticated setup expansion and all temporary admission work.
        var metadata = try std.math.add(usize, @sizeOf(Owner), try std.math.mul(usize, count, @sizeOf(Mixed.Expected) + @sizeOf(Reconstruct.Input)));
        metadata = try std.math.add(usize, metadata, try Job.metadataBytes(context.raw.len, context.fold.len));
        metadata = try std.math.add(usize, metadata, try std.math.mul(usize, context.raw.len, @sizeOf(Admission.ForKind(.raw).Prepared)));
        metadata = try std.math.add(usize, metadata, try std.math.mul(usize, context.fold.len, @sizeOf(Admission.ForKind(.fold).Prepared) + @sizeOf(Job.FoldInventory)));
        for (fold_rows) |rows| {
            if (rows.len == 0 or rows.len > 4096) return error.InvalidSourceRecursiveInventory;
            metadata = try std.math.add(usize, metadata, try std.math.mul(usize, rows.len, @sizeOf(Semantic.FoldRow)));
            for (rows) |row| {
                if (row.recipes.len > 2) return error.InvalidSourceRecursiveInventory;
                metadata = try std.math.add(usize, metadata, try std.math.mul(usize, row.recipes.len, @sizeOf(@import("block_v5_memory_source_blake_semantics_v1.zig").Recipe)));
            }
        }
        if (metadata > limits.max_metadata_bytes) return error.SourceRecursiveAdmissionResourceLimit;
        const budget = try Budget.createRetainingParent(backing, try std.math.add(usize, limits.max_metadata_bytes, limits.max_setup_bytes));
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        var owned_context = try Pages.Context.init(a, context.admitted, context.raw_plan, context.fold_plan, context.raw, context.fold, context.sealed, context.independent_digest, context.base, limits.page.page);
        errdefer owned_context.deinit();
        const inventories = try a.alloc(Job.FoldInventory, fold_rows.len);
        var initialized: usize = 0;
        errdefer {
            for (inventories[0..initialized]) |*inventory| inventory.deinit();
            a.free(inventories);
        }
        for (fold_rows, context.fold, inventories) |rows, pin, *inventory| {
            if (!std.meta.eql(pin.geometry, try Fixed.geometry(pin.page, pin.geometry.first_circuit, rows, limits.page.page.protocol.fold_cores)) or
                !std.meta.eql(pin.inventory_id, try Premix.inventoryId(pin.page, pin.geometry.first_circuit, rows)))
                return error.InvalidSourceRecursiveInventory;
            inventory.* = try Job.FoldInventory.copy(a, rows, limits.max_metadata_bytes);
            initialized += 1;
        }
        const sha = try SHA.Setup.create(a);
        errdefer sha.release();
        const blake = try Blake.Setup.create(a);
        errdefer blake.release();
        const arithmetic = try Components.ArithmeticSetup.create(a);
        errdefer arithmetic.release();
        const raw = try a.alloc(Admission.ForKind(.raw).Prepared, context.raw.len);
        errdefer a.free(raw);
        const fold = try a.alloc(Admission.ForKind(.fold).Prepared, context.fold.len);
        errdefer a.free(fold);
        const expected = try a.alloc(Mixed.Expected, count);
        errdefer a.free(expected);
        const inputs = try a.alloc(Reconstruct.Input, count);
        errdefer a.free(inputs);
        self.* = .{ .backing = backing, .budget = budget, .context = owned_context, .inventories = inventories, .sha = sha, .blake = blake, .arithmetic = arithmetic, .raw = raw, .fold = fold, .expected = expected, .inputs = inputs };
        for (raw, self.context.raw, 0..) |*admitted, pin, i| {
            admitted.* = try Admission.ForKind(.raw).Prepared.init(a, &self.context, pin, &.{}, sha, arithmetic, limits.page);
            expected[i] = .{ .auxiliary = .{ .family = .source_raw, .index = @intCast(i), .template = admitted.template_id } };
            inputs[i] = .{ .source_raw = admitted };
        }
        for (fold, self.context.fold, inventories, 0..) |*admitted, pin, inventory, i| {
            admitted.* = try Admission.ForKind(.fold).Prepared.init(a, &self.context, pin, inventory.rows, blake, arithmetic, limits.page);
            expected[raw.len + i] = .{ .auxiliary = .{ .family = .source_fold, .index = @intCast(i), .template = admitted.template_id } };
            inputs[raw.len + i] = .{ .source_fold = admitted };
        }
        _ = try Mixed.rosterDigest(expected);
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        const a = budget.allocator();
        a.free(self.inputs);
        a.free(self.expected);
        a.free(self.fold);
        a.free(self.raw);
        self.arithmetic.release();
        self.blake.release();
        self.sha.release();
        for (self.inventories) |*inventory| inventory.deinit();
        a.free(self.inventories);
        self.context.deinit();
        a.destroy(self);
        budget.destroy();
    }
};

/// Same recipe scheduler used by the original packed BLAKE producer; only
/// descriptor fields survive. Operand digests are not accepted as hash proofs.
fn inventoryFromOperations(a: std.mem.Allocator, operations: []const @import("block_v5_memory_source_batch_fold_v1.zig").Operation, max_bytes: usize) !Job.FoldInventory {
    const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
    const Recipe = @import("block_v5_memory_source_blake_semantics_v1.zig").Recipe;
    if (operations.len == 0 or operations.len > 4096) return error.InvalidSourceRecursiveInventory;
    var count: usize = 0;
    for (operations) |operation| count = try std.math.add(usize, count, (try Hash.recipes(operation)).count);
    if (try std.math.add(usize, try std.math.mul(usize, operations.len, @sizeOf(Semantic.FoldRow)), try std.math.mul(usize, count, @sizeOf(Recipe))) > max_bytes)
        return error.SourceRecursiveAdmissionResourceLimit;
    const rows = try a.alloc(Semantic.FoldRow, operations.len);
    errdefer a.free(rows);
    const recipes = try a.alloc(Recipe, count);
    errdefer a.free(recipes);
    var next: usize = 0;
    var compression: u32 = 0;
    for (operations, rows) |operation, *row| {
        const proposed = try Hash.recipes(operation);
        const first = compression;
        const start = next;
        for (proposed.values[0..proposed.count], 0..) |recipe, slot| {
            const n: u32 = if (recipe.default_height == null) @intCast((recipe.frame.size() + 63) / 64) else 0;
            recipes[next] = .{ .slot = @intCast(slot), .multiplicity = recipe.multiplicity, .default_height = recipe.default_height, .compression_count = n, .first_compression = compression };
            next += 1;
            compression = try std.math.add(u32, compression, n);
        }
        row.* = .{ .descriptor = .{ .kind = operation.kind, .height = operation.coordinate.height }, .recipes = recipes[start..next], .first_compression = first, .compressions = compression - first };
    }
    return .{ .a = a, .rows = rows, .recipes = recipes };
}

test "source recursive inventory matches original geometry without generating hash columns" {
    const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
    const operations = [_]Fold.Operation{
        .{ .ordinal = 0, .kind = .leaf, .coordinate = .{ .height = 0, .index = 0 }, .value = .{ .before = @splat(1), .after = @splat(2) }, .leaf = .{ .address = 0, .before = 0, .after = 9, .clock = 1, .image = .absent, .touched = true } },
        .{ .ordinal = 1, .kind = .branch, .coordinate = .{ .height = 1, .index = 0 }, .value = .{ .before = @splat(3), .after = @splat(3) }, .left = .{ .before = @splat(1), .after = @splat(1) }, .right = .{ .before = @splat(2), .after = @splat(2) } },
        .{ .ordinal = 2, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = @splat(3), .after = @splat(3) } },
    };
    var inventory = try inventoryFromOperations(std.testing.allocator, &operations, 1 << 20);
    defer inventory.deinit();
    const page = @import("block_v5_memory_source_unified_page_protocol_v1.zig").Page{ .index = 0, .first = 0, .count = operations.len, .row_log = 2 };
    const original = try Blake.Geometry.fromOperations(&operations, 1, .{});
    try std.testing.expectEqualDeep(original, try Fixed.geometry(page, 1, inventory.rows, .{}));
    try std.testing.expectEqual(@as(usize, 2), inventory.rows[0].recipes.len);
    try std.testing.expectEqual(@as(?u32, 0), inventory.rows[0].recipes[0].default_height);
    try std.testing.expectEqual(@as(u32, 2), inventory.rows[1].recipes[0].multiplicity);
    try std.testing.expectEqual(@as(usize, 0), inventory.rows[2].recipes.len);
    inventory.rows[1].first_compression += 1;
    try std.testing.expectError(error.InvalidSourceFoldFixedInventory, Fixed.geometry(page, 1, inventory.rows, .{}));
    try std.testing.expectError(error.SourceRecursiveAdmissionResourceLimit, inventoryFromOperations(std.testing.allocator, &operations, 1));
}
