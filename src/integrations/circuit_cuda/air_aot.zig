//! Authenticated circuit AIR bodies lowered through the canonical Cairo CUDA
//! evaluator. This is the first resident circuit-proof boundary: the eleven
//! pinned circuit programs use the same STWZEVA instruction format as Cairo.
//! Every base literal is passed as a proof-session constant after binding the
//! registry geometry; neither the geometry nor its constants select new code.

const std = @import("std");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const circuit = @import("stwo_circuit_frontend");
const cairo_cuda = @import("stwo_cairo_cuda_integration");
const codegen = cairo_cuda.eval_codegen;
const parametric = cairo_cuda.parametric_eval;
pub const bundle_sha256 = circuit_cpu.air.bundle_sha256;

pub const Body = struct {
    normalized_program_identity: [32]u8,
    source_identity: [32]u8,
    cache_key: u64,
    kernel_name: []u8,
    source: []u8,
    constant_count: u32,

    pub fn deinit(self: *Body, allocator: std.mem.Allocator) void {
        allocator.free(self.kernel_name);
        allocator.free(self.source);
        self.* = undefined;
    }
};

pub const Occurrence = struct {
    component_index: u32,
    part_index: u32,
    body_index: u32,
};

pub const Catalog = struct {
    allocator: std.mem.Allocator,
    bodies: []Body,
    occurrences: []Occurrence,

    pub fn deinit(self: *Catalog) void {
        for (self.bodies) |*body| body.deinit(self.allocator);
        self.allocator.free(self.bodies);
        self.allocator.free(self.occurrences);
        self.* = undefined;
    }

    /// Admit a geometry-bound circuit AIR only when every placed program is
    /// the pinned AOT body. Base literals are deliberately dynamic: binding
    /// another registry changes their values, but cannot select new code.
    pub fn admitBound(self: *const Catalog, bound: *const circuit_cpu.air.Bundle) !void {
        var occurrence_index: usize = 0;
        for (bound.components, 0..) |component, component_index| {
            for (component.parts, 0..) |part, part_index| {
                if (occurrence_index >= self.occurrences.len)
                    return error.CircuitAirPlacementMismatch;
                const occurrence = self.occurrences[occurrence_index];
                occurrence_index += 1;
                if (occurrence.component_index != component_index or
                    occurrence.part_index != part_index or
                    occurrence.body_index >= self.bodies.len)
                    return error.CircuitAirPlacementMismatch;
                var normalized = try parametric.normalize(self.allocator, part.program);
                defer normalized.deinit();
                const body = self.bodies[occurrence.body_index];
                if (!std.mem.eql(u8, &body.normalized_program_identity, &codegen.programIdentity(normalized)) or
                    body.constant_count != try parametric.constantWordCount(part.program))
                    return error.CircuitAirBodyMismatch;
            }
        }
        if (occurrence_index != self.occurrences.len)
            return error.CircuitAirPlacementMismatch;
    }
};

/// Build only from the pinned recorded circuit AIR. Runtime binding may vary
/// trace and evaluation logs, but the emitted program semantics are fixed.
pub fn build(allocator: std.mem.Allocator, encoded: []const u8) !Catalog {
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &sha, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(sha, .lower), bundle_sha256))
        return error.CircuitAirAuthorityMismatch;

    var bundle = try circuit_cpu.air.parse(allocator, encoded);
    defer bundle.deinit();
    var bodies = std.ArrayList(Body).empty;
    errdefer {
        for (bodies.items) |*body| body.deinit(allocator);
        bodies.deinit(allocator);
    }
    var occurrences = std.ArrayList(Occurrence).empty;
    errdefer occurrences.deinit(allocator);
    for (bundle.components, 0..) |component, component_index| {
        for (component.parts, 0..) |part, part_index| {
            var normalized = try parametric.normalize(allocator, part.program);
            defer normalized.deinit();
            const constant_count = try parametric.constantWordCount(part.program);
            const dynamic = try allocator.alloc(bool, constant_count);
            defer allocator.free(dynamic);
            @memset(dynamic, true);
            const source = try codegen.generateParametric(allocator, normalized, dynamic);
            var source_owned = true;
            defer if (source_owned) allocator.free(source);
            const kernel_name = try std.fmt.allocPrint(allocator, "stwo_cairo_cuda_eval_v{}_{x:0>16}", .{ codegen.parametric_version, normalized.header.semantic_hash });
            var name_owned = true;
            defer if (name_owned) allocator.free(kernel_name);
            const source_identity = codegen.sourceIdentity(source);
            const program_identity = codegen.programIdentity(normalized);
            var body_index: usize = bodies.items.len;
            for (bodies.items, 0..) |body, index| {
                if (std.mem.eql(u8, &body.source_identity, &source_identity)) {
                    if (!std.mem.eql(u8, body.kernel_name, kernel_name) or
                        !std.mem.eql(u8, &body.normalized_program_identity, &program_identity) or
                        body.constant_count != constant_count)
                        return error.CircuitAirBodyCollision;
                    body_index = index;
                    break;
                }
                if (std.mem.eql(u8, body.kernel_name, kernel_name))
                    return error.CircuitAirBodyCollision;
            }
            if (body_index == bodies.items.len) {
                try bodies.append(allocator, .{
                    .normalized_program_identity = program_identity,
                    .source_identity = source_identity,
                    .cache_key = parametric.cacheKey(program_identity, source_identity, sha),
                    .kernel_name = kernel_name,
                    .source = source,
                    .constant_count = constant_count,
                });
                name_owned = false;
                source_owned = false;
            }
            try occurrences.append(allocator, .{
                .component_index = @intCast(component_index),
                .part_index = @intCast(part_index),
                .body_index = @intCast(body_index),
            });
        }
    }
    const owned_bodies = try bodies.toOwnedSlice(allocator);
    errdefer {
        for (owned_bodies) |*body| body.deinit(allocator);
        allocator.free(owned_bodies);
    }
    return .{
        .allocator = allocator,
        .bodies = owned_bodies,
        .occurrences = try occurrences.toOwnedSlice(allocator),
    };
}

test "pinned circuit AIR lowers to authenticated CUDA evaluation bodies" {
    const allocator = std.testing.allocator;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var catalog = try build(allocator, encoded);
    defer catalog.deinit();
    try std.testing.expect(catalog.bodies.len >= 11);
    try std.testing.expect(catalog.occurrences.len >= catalog.bodies.len);
    for (catalog.bodies) |body| {
        try std.testing.expect(body.cache_key != 0);
        try std.testing.expect(body.source.len > 0);
        try std.testing.expect(std.mem.indexOf(u8, body.source, body.kernel_name) != null);
    }
    for (catalog.occurrences) |occurrence|
        try std.testing.expect(occurrence.body_index < catalog.bodies.len);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    try catalog.admitBound(&template);
    const original_body = catalog.occurrences[0].body_index;
    catalog.occurrences[0].body_index = @intCast(catalog.bodies.len);
    try std.testing.expectError(error.CircuitAirPlacementMismatch, catalog.admitBound(&template));
    catalog.occurrences[0].body_index = original_body;
    var tampered = try allocator.dupe(u8, encoded);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(error.CircuitAirAuthorityMismatch, build(allocator, tampered));
}

test "circuit CUDA AIR bodies are invariant under registry-sized rebinding" {
    const allocator = std.testing.allocator;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    const original_sizes = circuit_cpu.air.recorded_sizes;
    var smaller_sizes = original_sizes;
    smaller_sizes.eq /= 2;
    smaller_sizes.qm31_ops /= 2;
    smaller_sizes.blake_g_gate /= 2;
    const original_layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(original_sizes);
    const smaller_layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(smaller_sizes);
    var original = try circuit_cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&original_layout), &original_layout);
    defer original.deinit();
    var smaller = try circuit_cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&smaller_layout), &smaller_layout);
    defer smaller.deinit();
    var catalog = try build(allocator, encoded);
    defer catalog.deinit();
    try catalog.admitBound(&original);
    try catalog.admitBound(&smaller);
    try std.testing.expectEqual(original.components.len, smaller.components.len);
    for (original.components, smaller.components) |left, right| {
        try std.testing.expectEqual(left.parts.len, right.parts.len);
        for (left.parts, right.parts) |left_part, right_part| {
            var left_normalized = try parametric.normalize(allocator, left_part.program);
            defer left_normalized.deinit();
            var right_normalized = try parametric.normalize(allocator, right_part.program);
            defer right_normalized.deinit();
            try std.testing.expectEqualSlices(u8, &codegen.programIdentity(left_normalized), &codegen.programIdentity(right_normalized));
            try std.testing.expectEqual(try parametric.constantWordCount(left_part.program), try parametric.constantWordCount(right_part.program));
        }
    }
}
