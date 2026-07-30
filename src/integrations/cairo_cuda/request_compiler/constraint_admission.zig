//! Request-local admission map for authenticated Cairo CUDA constraints.

const std = @import("std");
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const eval_aot = @import("../eval_aot.zig");
const eval_codegen = @import("../eval_codegen.zig");
const eval_product_registry = @import("../eval_product_registry.zig");

pub const Catalog = struct {
    product: eval_aot.Product,
    registry: eval_product_registry.Registry,
    catalog_identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        bundle: composition.Bundle,
    ) !Catalog {
        var product = try eval_aot.build(allocator, bundle);
        errdefer product.deinit();
        var registry = try eval_product_registry.Registry.initProduct(
            allocator,
        );
        errdefer registry.deinit();
        const catalog_identity = try catalogIdentity(product, registry);
        return .{
            .product = product,
            .registry = registry,
            .catalog_identity = catalog_identity,
        };
    }

    pub fn deinit(self: *Catalog) void {
        self.registry.deinit();
        self.product.deinit();
        self.* = undefined;
    }

    pub fn admits(
        self: Catalog,
        component: composition.Component,
        component_index: u32,
        part: composition.Part,
        part_index: u32,
    ) bool {
        const component_source =
            eval_aot.componentSourceIdentity(component);
        const program_identity =
            eval_codegen.programIdentity(part.program);
        const global_rc_base = std.math.add(
            u32,
            component.random_coefficient_offset,
            part.rc_base,
        ) catch return false;
        for (self.product.bodies) |body| {
            if (body.semantic_hash != part.semantic_hash or
                self.registry.resolve(body) == null)
            {
                continue;
            }
            for (body.occurrences) |occurrence| {
                if (occurrence.component_index == component_index and
                    occurrence.instance == component.instance and
                    occurrence.part_index == part_index and
                    occurrence.rc_base == part.rc_base and
                    occurrence.rc_count ==
                        part.program.header.n_constraints and
                    occurrence.global_rc_base == global_rc_base and
                    occurrence.trace_log_size ==
                        component.trace_log_size and
                    occurrence.evaluation_log_size ==
                        component.evaluation_log_size and
                    occurrence.domain_log_size ==
                        part.program.header.domain_log_size and
                    std.mem.eql(
                        u8,
                        occurrence.component_label,
                        component.label,
                    ) and
                    std.mem.eql(
                        u8,
                        &occurrence.component_source_identity,
                        &component_source,
                    ) and
                    std.mem.eql(
                        u8,
                        &occurrence.program_identity,
                        &program_identity,
                    ))
                {
                    return true;
                }
            }
        }
        return false;
    }
};

fn catalogIdentity(
    product: eval_aot.Product,
    registry: eval_product_registry.Registry,
) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/cairo/cuda/constraint-admission-catalog/v1\x00",
    );
    hashInt(&hash, u64, product.bodies.len);
    hashInt(&hash, u64, product.occurrence_count);
    for (product.bodies) |body| {
        const resolved = registry.resolve(body) orelse
            return error.MissingCairoEvalProductBody;
        hashInt(&hash, u64, resolved.semantic_hash);
        hashInt(&hash, u64, resolved.cache_key);
        hashInt(&hash, u64, resolved.kernel_name.len);
        hash.update(resolved.kernel_name);
        hash.update(&resolved.program_identity);
        hash.update(&resolved.source_identity);
        hash.update(&resolved.catalog_identity);
    }
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}
