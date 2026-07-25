//! Authenticated product inventory for unfused Cairo CUDA constraint bodies.
//!
//! Bodies are deduplicated by an exact SHA-256 program identity. Placements
//! remain explicit because random-coefficient order, domains, and resident
//! source geometry are statement semantics rather than codegen details.

const std = @import("std");
const composition = @import("../../frontends/cairo/witness/composition_bundle.zig");
const codegen = @import("eval_codegen.zig");

pub const abi_schema = "cairo_eval_part_v1";
pub const codegen_version = codegen.codegen_version;
pub const identity_scheme =
    "sha256-canonical-cairo-eval-program-source-catalog-v1";

pub const Occurrence = struct {
    component_index: u32,
    component_label: []const u8,
    component_source_identity: [32]u8,
    domain_log_size: u32,
    evaluation_log_size: u32,
    global_rc_base: u32,
    instance: u32,
    part_index: u32,
    program_identity: [32]u8,
    rc_base: u32,
    rc_count: u32,
    trace_log_size: u32,
};

pub const Body = struct {
    semantic_hash: u64,
    program_identity: [32]u8,
    source_identity: [32]u8,
    catalog_identity: [32]u8,
    cache_key: u64,
    kernel_name: []u8,
    source: []u8,
    occurrences: []Occurrence,

    pub fn label(
        self: Body,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "cairo_eval_{x:0>16}",
            .{self.semantic_hash},
        );
    }

    pub fn filename(
        self: Body,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        const product_label = try self.label(allocator);
        defer allocator.free(product_label);
        return std.fmt.allocPrint(
            allocator,
            "constraint_{s}_{x:0>16}.cu",
            .{ product_label, self.cache_key },
        );
    }
};

pub const Product = struct {
    allocator: std.mem.Allocator,
    bodies: []Body,
    occurrence_count: usize,

    pub fn deinit(self: *Product) void {
        for (self.bodies) |body| {
            self.allocator.free(body.kernel_name);
            self.allocator.free(body.source);
            self.allocator.free(body.occurrences);
        }
        self.allocator.free(self.bodies);
        self.* = undefined;
    }
};

const BuildingBody = struct {
    semantic_hash: u64,
    source_identity: [32]u8,
    kernel_name: []u8,
    source: []u8,
    occurrences: std.ArrayList(Occurrence),
};

pub fn build(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
) !Product {
    var building = std.ArrayList(BuildingBody).empty;
    defer {
        for (building.items) |*body| {
            allocator.free(body.kernel_name);
            allocator.free(body.source);
            body.occurrences.deinit(allocator);
        }
        building.deinit(allocator);
    }

    var occurrence_count: usize = 0;
    for (bundle.components, 0..) |component, component_index| {
        const source_identity = componentSourceIdentity(component);
        for (component.parts, 0..) |part, part_index| {
            const program_identity = codegen.programIdentity(part.program);
            const generated_source = try codegen.generate(
                allocator,
                part.program,
            );
            const generated_source_identity =
                codegen.sourceIdentity(generated_source);
            var body_index = findBody(
                building.items,
                generated_source_identity,
            );
            if (body_index == null) {
                const kernel_name = codegen.kernelName(
                    allocator,
                    part.semantic_hash,
                ) catch |err| {
                    allocator.free(generated_source);
                    return err;
                };
                building.append(allocator, .{
                    .semantic_hash = part.semantic_hash,
                    .source_identity = generated_source_identity,
                    .kernel_name = kernel_name,
                    .source = generated_source,
                    .occurrences = .empty,
                }) catch |err| {
                    allocator.free(kernel_name);
                    allocator.free(generated_source);
                    return err;
                };
                body_index = building.items.len - 1;
            } else {
                allocator.free(generated_source);
            }
            const body = &building.items[body_index.?];
            const observed_source_identity =
                codegen.sourceIdentity(body.source);
            if (body.semantic_hash != part.semantic_hash or
                !std.mem.eql(
                    u8,
                    &body.source_identity,
                    &observed_source_identity,
                ))
            {
                return error.InconsistentEvalBody;
            }
            const global_rc_base = std.math.add(
                u32,
                component.random_coefficient_offset,
                part.rc_base,
            ) catch return error.InvalidRandomCoefficientRange;
            try body.occurrences.append(allocator, .{
                .component_index = @intCast(component_index),
                .component_label = component.label,
                .component_source_identity = source_identity,
                .domain_log_size = part.program.header.domain_log_size,
                .evaluation_log_size = component.evaluation_log_size,
                .global_rc_base = global_rc_base,
                .instance = component.instance,
                .part_index = @intCast(part_index),
                .program_identity = program_identity,
                .rc_base = part.rc_base,
                .rc_count = part.program.header.n_constraints,
                .trace_log_size = component.trace_log_size,
            });
            occurrence_count += 1;
        }
    }

    const bodies = try allocator.alloc(Body, building.items.len);
    errdefer allocator.free(bodies);
    var initialized: usize = 0;
    errdefer for (bodies[0..initialized]) |body| {
        allocator.free(body.kernel_name);
        allocator.free(body.source);
        allocator.free(body.occurrences);
    };
    while (initialized < building.items.len) : (initialized += 1) {
        const source = &building.items[initialized];
        const occurrences = try source.occurrences.toOwnedSlice(allocator);
        errdefer allocator.free(occurrences);
        const catalog_identity = try catalogIdentity(
            allocator,
            occurrences,
        );
        const program_identity = programSetIdentity(occurrences);
        bodies[initialized] = .{
            .semantic_hash = source.semantic_hash,
            .program_identity = program_identity,
            .source_identity = source.source_identity,
            .catalog_identity = catalog_identity,
            .cache_key = codegen.productCacheKey(
                program_identity,
                source.source_identity,
                catalog_identity,
            ),
            .kernel_name = source.kernel_name,
            .source = source.source,
            .occurrences = occurrences,
        };
        source.kernel_name = &.{};
        source.source = &.{};
    }
    std.mem.sort(Body, bodies, {}, lessThanBody);
    try validateProduct(bodies, occurrence_count);
    return .{
        .allocator = allocator,
        .bodies = bodies,
        .occurrence_count = occurrence_count,
    };
}

pub fn renderManifest(
    allocator: std.mem.Allocator,
    product: Product,
) ![]u8 {
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    const writer = output.writer(allocator);
    try writer.writeAll("[\n");
    for (product.bodies, 0..) |body, body_index| {
        const label = try body.label(allocator);
        defer allocator.free(label);
        const filename = try body.filename(allocator);
        defer allocator.free(filename);
        try writer.writeAll("  {\n");
        try writer.print("    \"abi_schema\": \"{s}\",\n", .{abi_schema});
        try writer.print(
            "    \"cache_key\": \"{x:0>16}\",\n",
            .{body.cache_key},
        );
        try writer.writeAll("    \"catalog_identity\": \"");
        try writeHex(writer, &body.catalog_identity);
        try writer.writeAll("\",\n");
        try writer.print(
            "    \"codegen_version\": {},\n",
            .{codegen.codegen_version},
        );
        try writer.print("    \"file\": \"{s}\",\n", .{filename});
        try writer.print(
            "    \"identity_scheme\": \"{s}\",\n",
            .{identity_scheme},
        );
        try writer.print(
            "    \"kernel_name\": \"{s}\",\n",
            .{body.kernel_name},
        );
        try writer.writeAll("    \"kind\": \"constraint\",\n");
        try writer.print("    \"label\": \"{s}\",\n", .{label});
        try writer.writeAll("    \"module_globals\": \"none\",\n");
        try writer.writeAll("    \"occurrences\": ");
        try writeOccurrences(writer, body.occurrences, true);
        try writer.writeAll(",\n    \"program_identity\": \"");
        try writeHex(writer, &body.program_identity);
        try writer.print(
            "\",\n    \"semantic_hash\": \"{x:0>16}\",\n",
            .{body.semantic_hash},
        );
        try writer.writeAll("    \"source_sha256\": \"");
        try writeHex(writer, &body.source_identity);
        try writer.writeAll("\"\n  }");
        try writer.writeAll(
            if (body_index + 1 == product.bodies.len)
                "\n"
            else
                ",\n",
        );
    }
    try writer.writeAll("]\n");
    return output.toOwnedSlice(allocator);
}

pub fn catalogIdentity(
    allocator: std.mem.Allocator,
    occurrences: []const Occurrence,
) ![32]u8 {
    var encoded = std.ArrayList(u8).empty;
    defer encoded.deinit(allocator);
    try writeOccurrences(encoded.writer(allocator), occurrences, false);
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded.items, &identity, .{});
    return identity;
}

pub fn componentSourceIdentity(
    component: composition.Component,
) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cairo-eval-component-source/v1\x00");
    hashUnsigned(&hasher, u32, component.trace_log_size);
    hashUnsigned(&hasher, u32, component.evaluation_log_size);
    hashUnsigned(&hasher, u32, component.n_constraints);
    hashLength(&hasher, component.trace_spans.len);
    for (component.trace_spans) |span| {
        hashUnsigned(&hasher, u32, span.tree);
        hashUnsigned(&hasher, u32, span.start);
        hashUnsigned(&hasher, u32, span.end);
    }
    hashLength(&hasher, component.preprocessed_indices.len);
    for (component.preprocessed_indices) |index| {
        hashUnsigned(&hasher, u32, index);
    }
    hashLength(&hasher, component.denominator_inverses.len);
    for (component.denominator_inverses) |value| {
        hashUnsigned(&hasher, u32, value);
    }
    hashLength(&hasher, component.ext_sources.len);
    for (component.ext_sources) |source| hashExtSource(&hasher, source);
    var identity: [32]u8 = undefined;
    hasher.final(&identity);
    return identity;
}

fn validateProduct(
    bodies: []const Body,
    occurrence_count: usize,
) !void {
    if (bodies.len == 0 or occurrence_count == 0)
        return error.EmptyEvalProduct;
    var counted: usize = 0;
    for (bodies, 0..) |body, index| {
        if (body.semantic_hash == 0 or body.cache_key == 0 or
            body.occurrences.len == 0 or body.source.len == 0 or
            body.kernel_name.len == 0)
        {
            return error.InvalidEvalProduct;
        }
        if (index != 0 and !lessThanBody(
            {},
            bodies[index - 1],
            body,
        )) return error.DuplicateEvalProductBody;
        for (body.occurrences) |occurrence| {
            if (occurrence.component_label.len == 0 or
                occurrence.rc_count == 0 or
                occurrence.domain_log_size !=
                    occurrence.trace_log_size or
                occurrence.trace_log_size >
                    occurrence.evaluation_log_size)
            {
                return error.InvalidEvalOccurrence;
            }
        }
        counted += body.occurrences.len;
    }
    if (counted != occurrence_count)
        return error.InvalidEvalOccurrenceCount;
}

fn writeOccurrences(
    writer: anytype,
    occurrences: []const Occurrence,
    pretty: bool,
) !void {
    try writer.writeByte('[');
    if (pretty and occurrences.len != 0) try writer.writeByte('\n');
    for (occurrences, 0..) |occurrence, index| {
        if (pretty) try writer.writeAll("      ");
        try writer.writeAll("{\"component_index\":");
        try writer.print("{}", .{occurrence.component_index});
        try writer.writeAll(",\"component_label\":\"");
        try writeJsonLabel(writer, occurrence.component_label);
        try writer.writeAll("\",\"component_source_identity\":\"");
        try writeHex(writer, &occurrence.component_source_identity);
        try writer.print(
            "\",\"domain_log_size\":{},\"evaluation_log_size\":{},\"global_rc_base\":{},\"instance\":{},\"part_index\":{},\"program_identity\":\"",
            .{
                occurrence.domain_log_size,
                occurrence.evaluation_log_size,
                occurrence.global_rc_base,
                occurrence.instance,
                occurrence.part_index,
            },
        );
        try writeHex(writer, &occurrence.program_identity);
        try writer.print(
            "\",\"rc_base\":{},\"rc_count\":{},\"trace_log_size\":{}",
            .{
                occurrence.rc_base,
                occurrence.rc_count,
                occurrence.trace_log_size,
            },
        );
        try writer.writeByte('}');
        if (index + 1 != occurrences.len) try writer.writeByte(',');
        if (pretty) try writer.writeByte('\n');
    }
    if (pretty and occurrences.len != 0) try writer.writeAll("    ");
    try writer.writeByte(']');
}

fn findBody(
    bodies: []const BuildingBody,
    identity: [32]u8,
) ?usize {
    for (bodies, 0..) |body, index| {
        if (std.mem.eql(u8, &body.source_identity, &identity))
            return index;
    }
    return null;
}

fn programSetIdentity(occurrences: []const Occurrence) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cairo-eval-program-set/v1\x00");
    hashLength(&hasher, occurrences.len);
    for (occurrences) |occurrence| {
        hasher.update(&occurrence.program_identity);
    }
    var identity: [32]u8 = undefined;
    hasher.final(&identity);
    return identity;
}

fn lessThanBody(_: void, lhs: Body, rhs: Body) bool {
    if (lhs.semantic_hash != rhs.semantic_hash)
        return lhs.semantic_hash < rhs.semantic_hash;
    return std.mem.order(
        u8,
        &lhs.program_identity,
        &rhs.program_identity,
    ) == .lt;
}

fn hashExtSource(
    hasher: *std.crypto.hash.sha2.Sha256,
    source: composition.ExtSource,
) void {
    switch (source) {
        .constant => |value| {
            hashUnsigned(hasher, u8, 0);
            for (value) |coordinate| {
                hashUnsigned(hasher, u32, coordinate);
            }
        },
        .lookup_z => hashUnsigned(hasher, u8, 1),
        .lookup_alpha_power => |power| {
            hashUnsigned(hasher, u8, 2);
            hashUnsigned(hasher, u32, power);
        },
        .claimed_sum_scaled => hashUnsigned(hasher, u8, 3),
        .lookup_alpha_power_scaled => |value| {
            hashUnsigned(hasher, u8, 4);
            hashUnsigned(hasher, u32, value.power);
            hashUnsigned(hasher, u32, value.scale);
        },
    }
}

fn writeJsonLabel(writer: anytype, label: []const u8) !void {
    if (label.len == 0) return error.InvalidComponentLabel;
    for (label) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_')
            return error.InvalidComponentLabel;
        try writer.writeByte(byte);
    }
}

fn writeHex(writer: anytype, bytes: []const u8) !void {
    for (bytes) |byte| try writer.print("{x:0>2}", .{byte});
}

fn hashLength(
    hasher: *std.crypto.hash.sha2.Sha256,
    value: usize,
) void {
    hashUnsigned(hasher, u64, @intCast(value));
}

fn hashUnsigned(
    hasher: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}
