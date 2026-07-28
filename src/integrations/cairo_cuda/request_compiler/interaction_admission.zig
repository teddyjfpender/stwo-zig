//! Request-local admission map for the authenticated Cairo relation graph.

const std = @import("std");
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const relation_adapter = @import("../relation_adapter.zig");

pub const production_ready = false;

pub const Catalog = struct {
    plan: relation_adapter.Plan,
    catalog_identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        proof: *const proof_plan.CairoProofPlan,
        relations: relation_bundle.Bundle,
    ) !Catalog {
        var plan = try relation_adapter.Plan.compile(
            allocator,
            proof,
            relations,
        );
        errdefer plan.deinit();
        const catalog_identity = catalogIdentity(&plan);
        if (std.mem.allEqual(u8, &catalog_identity, 0))
            return error.InvalidInteractionCatalogIdentity;
        return .{
            .plan = plan,
            .catalog_identity = catalog_identity,
        };
    }

    pub fn deinit(self: *Catalog) void {
        self.plan.deinit();
        self.* = undefined;
    }

    pub fn admits(
        self: *const Catalog,
        component_index: u32,
        component: proof_plan.Component,
    ) bool {
        const ordinal = std.math.cast(
            usize,
            component.canonical_ordinal,
        ) orelse return false;
        if (ordinal >= self.plan.instances.len) return false;
        const instance = self.plan.instances[ordinal];
        return instance.component_index == component_index and
            instance.component_instance == component.instance and
            std.mem.eql(u8, instance.component, component.name) and
            !std.mem.allEqual(u8, &self.plan.topology_identity, 0) and
            !std.mem.allEqual(u8, &self.catalog_identity, 0);
    }
};

fn catalogIdentity(plan: *const relation_adapter.Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/cairo/cuda/interaction-admission-catalog/v1\x00",
    );
    hash.update(&plan.topology_identity);
    hashInt(&hash, u64, plan.instances.len);
    hashInt(&hash, u32, plan.max_alpha_powers);
    hashInt(&hash, u32, plan.total_pair_blocks);
    hashInt(&hash, u32, plan.total_inverse_blocks);
    hashInt(&hash, u32, plan.total_row_blocks);
    for (plan.instances, 0..) |instance, canonical_ordinal| {
        hashInt(&hash, u32, @intCast(canonical_ordinal));
        hashInt(&hash, u32, instance.component_index);
        hashInt(&hash, u32, instance.component_instance);
        hashInt(&hash, u32, instance.relation_component_index);
        hashInt(&hash, u32, instance.relation_trace_index);
        hashInt(&hash, u64, instance.component.len);
        hash.update(instance.component);
        hashInt(&hash, u32, @intFromEnum(instance.part));
        hashInt(&hash, u32, @intFromEnum(instance.layout));
        inline for (std.meta.fields(@TypeOf(instance.geometry))) |field| {
            hashInt(
                &hash,
                u32,
                @field(instance.geometry, field.name),
            );
        }
        hashInt(&hash, u64, instance.descriptors.len);
        hash.update(std.mem.sliceAsBytes(instance.descriptors));
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

test "SN2 interaction admission binds all canonical relation instances" {
    const allocator = std.testing.allocator;
    const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
    var composition = try composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer composition.deinit();
    var relations = try relation_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();

    const parts = try allocator.alloc(
        proof_plan.TracePart,
        composition.components.len,
    );
    defer allocator.free(parts);
    const components = try allocator.alloc(
        proof_plan.Component,
        composition.components.len,
    );
    defer allocator.free(components);
    for (composition.components, parts, components, 0..) |
        component,
        *part,
        *planned,
        index,
    | {
        const rows = @as(u32, 1) << @intCast(component.trace_log_size);
        const derived = derivedRelationRows(component.label);
        part.* = .{
            .id = .main,
            .rows = .{
                .real_rows = if (derived) null else rows,
                .padded_rows = rows,
            },
        };
        planned.* = .{
            .name = component.label,
            .instance = component.instance,
            .canonical_ordinal = @intCast(index),
            .writer = .recorded_aot,
            .trace_parts = parts[index .. index + 1],
            .producer_edges = if (derived)
                proof_plan.gatheredProducerEdges(component.label).?
            else
                &.{},
            .capacity_feeds = &.{},
        };
    }
    var proof = try proof_plan.CairoProofPlan.init(
        allocator,
        components,
    );
    defer proof.deinit();
    var catalog = try Catalog.init(allocator, &proof, relations);
    defer catalog.deinit();

    try std.testing.expectEqual(
        @as(usize, 58),
        catalog.plan.instances.len,
    );
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &catalog.catalog_identity,
        0,
    ));
    for (proof.components, 0..) |component, component_index| {
        try std.testing.expect(catalog.admits(
            @intCast(component_index),
            component,
        ));
    }
    var forged = proof.components[0];
    forged.instance +%= 1;
    try std.testing.expect(!catalog.admits(0, forged));
    try std.testing.expect(!production_ready);
}

fn derivedRelationRows(component: []const u8) bool {
    return std.mem.eql(u8, component, "blake_round") or
        std.mem.eql(u8, component, "partial_ec_mul_window_bits_18") or
        std.mem.eql(u8, component, "cube_252");
}
