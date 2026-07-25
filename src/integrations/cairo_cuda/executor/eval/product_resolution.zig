//! Resolution of authenticated Cairo evaluation products.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const constraint_catalog = @import(
    "../../request_compiler/constraint_admission.zig",
);

pub const Resolved = struct {
    cache_key: u64,
    kernel_name: []const u8,
};

pub fn resolve(
    catalog: constraint_catalog.Catalog,
    component_index: u32,
    part_index: u32,
    program_identity: proof_ir.Digest,
) !Resolved {
    for (catalog.product.bodies) |body| {
        for (body.occurrences) |occurrence| {
            if (occurrence.component_index != component_index or
                occurrence.part_index != part_index or
                !std.mem.eql(
                    u8,
                    &occurrence.program_identity,
                    &program_identity,
                ))
            {
                continue;
            }
            const resolved = catalog.registry.resolve(body) orelse
                return error.MissingCairoEvalProduct;
            return .{
                .cache_key = resolved.cache_key,
                .kernel_name = resolved.kernel_name,
            };
        }
    }
    return error.MissingCairoEvalProduct;
}
