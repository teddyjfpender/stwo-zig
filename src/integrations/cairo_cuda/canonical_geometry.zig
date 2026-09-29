//! Exact allocation geometry from admitted execution metadata. This plans GPU
//! storage without executing a host witness or accepting proof-derived sizes.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const claims = cairo.claim_generator;

pub const Extent = struct {
    padded_rows: u32,
    active_rows: u32,
    /// Compact keys are counted on input metadata, then checked again against
    /// the device compaction result before any commitment can be admitted.
    distinct_rows: ?u32 = null,
};

pub const Geometry = struct {
    allocator: std.mem.Allocator,
    extents: []Extent,

    pub fn deinit(self: *Geometry) void {
        self.allocator.free(self.extents);
        self.* = undefined;
    }
};

pub fn resolve(
    allocator: std.mem.Allocator,
    input: *const cairo.adapter.ProverInput,
    geometry: *claims.OwnedClaimGeometry,
    topology: cairo.witness.feed_topology.Loaded,
) !Geometry {
    const extents = try allocator.alloc(Extent, geometry.components.len);
    errdefer allocator.free(extents);
    const ready = try allocator.alloc(bool, extents.len);
    defer allocator.free(ready);
    @memset(ready, false);

    for (geometry.components, extents, ready) |component, *extent, *resolved| {
        if (component.log_size == .deferred) continue;
        const padded = try rowsForLog(component.log_size.known);
        const direct = try cairo.witness.direct_inputs.resolve(input, component.name);
        if (direct) |source| {
            if (try source.paddedRowCount() != padded) return error.DirectGeometryMismatch;
            extent.* = .{ .padded_rows = padded, .active_rows = @intCast(try source.realRowCount(padded)) };
        } else extent.* = .{ .padded_rows = padded, .active_rows = padded };
        resolved.* = true;
    }

    var remaining = geometry.deferredCount();
    while (remaining != 0) {
        var progressed = false;
        for (geometry.components, 0..) |component, index| {
            if (ready[index]) continue;
            if (cairo.proof_plan.compactGeometry(component.name)) |compact| {
                var parents_ready = true;
                var parents: usize = 0;
                for (compact.edges) |edge| {
                    const parent = find(geometry.components, edge.producer) orelse continue;
                    parents += 1;
                    parents_ready = parents_ready and ready[parent];
                }
                if (parents == 0) return error.MissingCompactProducer;
                if (!parents_ready) continue;
                const distinct = if (std.mem.eql(u8, component.name, "verify_instruction")) blk: {
                    var keys = try cairo.witness.verify_instruction_inputs.gather(allocator, input);
                    defer keys.deinit();
                    break :blk std.math.cast(u32, keys.rows.len) orelse return error.GeometryOverflow;
                } else try builtinDistinct(allocator, input, component.name);
                const padded = try paddedRows(distinct);
                // The canonical compact source exports its full padded slab to
                // downstream gathers; its own enabler masks inactive tuples.
                extents[index] = .{ .padded_rows = padded, .active_rows = padded, .distinct_rows = distinct };
            } else {
                const target = topology.find(component.name) orelse return error.MissingCanonicalTopology;
                _ = target;
                var count: u64 = 0;
                var parents: usize = 0;
                var parents_ready = true;
                for (topology.parsed.value.components) |producer| {
                    const parent = find(geometry.components, producer.producer) orelse continue;
                    var instances: u32 = 0;
                    for (producer.feeds) |feed| {
                        if (std.mem.eql(u8, feed.target, component.name)) instances += 1;
                    }
                    if (instances == 0) continue;
                    parents += 1;
                    if (!ready[parent]) { parents_ready = false; continue; }
                    const contribution = std.math.mul(u64, extents[parent].active_rows, instances) catch return error.GeometryOverflow;
                    count = std.math.add(u64, count, contribution) catch return error.GeometryOverflow;
                }
                if (parents == 0) return error.MissingGatherProducer;
                if (!parents_ready) continue;
                const active = std.math.cast(u32, count) orelse return error.GeometryOverflow;
                extents[index] = .{ .padded_rows = try paddedRows(active), .active_rows = active };
            }
            ready[index] = true;
            remaining -= 1;
            progressed = true;
        }
        if (!progressed) return error.UnresolvableCanonicalGeometry;
    }

    const reports = try allocator.alloc(claims.FeedGeometry, geometry.deferredCount());
    defer allocator.free(reports);
    var cursor: usize = 0;
    for (geometry.components, extents) |component, extent| {
        if (component.log_size != .deferred) continue;
        reports[cursor] = .{ .name = component.name, .instance = component.instance, .log_size = std.math.log2_int(u32, extent.padded_rows) };
        cursor += 1;
    }
    try geometry.resolveFeedGeometry(allocator, reports);
    return .{ .allocator = allocator, .extents = extents };
}

fn find(components: []const claims.ComponentGeometry, name: []const u8) ?usize {
    for (components, 0..) |component, index| {
        if (component.instance == 0 and std.mem.eql(u8, component.name, name)) return index;
    }
    return null;
}

fn rowsForLog(log: u32) !u32 {
    if (log < claims.simd_log_lanes or log > 30) return error.GeometryOverflow;
    return @as(u32, 1) << @intCast(log);
}

fn paddedRows(active: u32) !u32 {
    if (active == 0) return error.EmptyCanonicalSource;
    return rowsForLog(std.math.log2_int_ceil(u32, @max(active, 16)));
}

fn builtinDistinct(allocator: std.mem.Allocator, input: *const cairo.adapter.ProverInput, name: []const u8) !u32 {
    const poseidon = std.mem.eql(u8, name, "poseidon_aggregator");
    const pedersen = std.mem.eql(u8, name, "pedersen_aggregator_window_bits_18") or
        std.mem.eql(u8, name, "pedersen_aggregator_window_bits_9");
    if (!poseidon and !pedersen) return error.UnsupportedCompactSource;
    const producer = if (poseidon) "poseidon_builtin" else if (std.mem.endsWith(u8, name, "_9")) "pedersen_builtin_narrow_windows" else "pedersen_builtin";
    const direct = (try cairo.witness.direct_inputs.resolve(input, producer)) orelse return error.MissingCompactProducer;
    const rows = try direct.paddedRowCount();
    const begin = direct.builtin.begin_addr;
    const key_words: u32 = if (poseidon) 3 else 2;
    const tuple_words: u32 = if (poseidon) 6 else 3;
    var unique = std.AutoHashMap([3]u32, [3]u32).init(allocator);
    defer unique.deinit();
    for (0..rows) |row| {
        var key: [3]u32 = @splat(0);
        var output: [3]u32 = @splat(0);
        for (0..tuple_words) |word| {
            const address = @as(u64, begin) + @as(u64, @intCast(row)) * tuple_words + word;
            const encoded = cairo.witness.execution_tables.limb(input, cairo.witness.execution_tables.ADDRESS_TO_ID_TABLE,
                std.math.cast(u32, address) orelse return error.GeometryOverflow, 0);
            if (word < key_words) key[word] = encoded else output[word - key_words] = encoded;
        }
        const entry = try unique.getOrPut(key);
        if (entry.found_existing and !std.mem.eql(u32, entry.value_ptr, &output)) return error.ConflictingCompactKey;
        entry.value_ptr.* = output;
    }
    return unique.count();
}

test "canonical CUDA geometry matches independent Rust checkpoints" {
    const cases = [_]struct { name: []const u8, variant: claims.PreprocessedVariant }{
        .{ .name = "all_opcodes", .variant = .canonical_small },
        .{ .name = "all_builtins", .variant = .canonical },
    };
    for (cases) |case| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "vectors/cairo/official/{s}.prover_input.json", .{case.name});
        defer std.testing.allocator.free(path);
        var input = try cairo.adapter.input.readFile(std.testing.allocator, path);
        defer input.deinit(std.testing.allocator);
        var geometry = try claims.deriveFromProverInput(std.testing.allocator, &input, .{ .preprocessed_variant = case.variant });
        defer geometry.deinit();
        var topology = try cairo.witness.feed_topology.readOfficial(std.testing.allocator, "vectors/cairo/official/witness_feed_topology_v1.json");
        defer topology.deinit();
        var planned = try resolve(std.testing.allocator, &input, &geometry, topology);
        defer planned.deinit();
        const checkpoint_path = try std.fmt.allocPrint(std.testing.allocator, "vectors/cairo/official/{s}.base_trace_checkpoint.json", .{case.name});
        defer std.testing.allocator.free(checkpoint_path);
        const encoded = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 2 * 1024 * 1024);
        defer std.testing.allocator.free(encoded);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
        var checkpoint = try cairo.conformance.receipt.readFile(std.testing.allocator, checkpoint_path, .{
            .input_sha256 = digest, .authority = .{ .stwo_cairo_revision = cairo.claim_registry.source_revision.stwo_cairo, .stwo_revision = cairo.claim_registry.source_revision.stwo },
        });
        defer checkpoint.deinit();
        try std.testing.expectEqual(checkpoint.components.len, geometry.components.len);
        for (geometry.components, planned.extents, checkpoint.components) |component, extent, oracle| {
            try std.testing.expectEqual(oracle.columns[0].row_count, @as(u64, extent.padded_rows));
            try std.testing.expectEqual(std.math.log2_int(u32, extent.padded_rows), component.log_size.known);
            try std.testing.expect(extent.active_rows <= extent.padded_rows);
        }
    }
}
