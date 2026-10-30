const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("block_v7_lookup_compact_algebra_v1.zig");
const L = @import("block_v7_lookup_compact_layout_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig");
const Mapped = @import("block_v7_memory_joint_component_v1.zig");
const Slot = union(enum) {
    bitwise_dense: Mapped.ForPlacement(A.For(.bitwise, .dense), L.Part),
    bitwise_sparse: Mapped.ForPlacement(A.For(.bitwise, .sparse), L.Part),
    range_check_20_dense: Mapped.ForPlacement(A.For(.range_check_20, .dense), L.Part),
    range_check_20_sparse: Mapped.ForPlacement(A.For(.range_check_20, .sparse), L.Part),
    range_check_8_11_dense: Mapped.ForPlacement(A.For(.range_check_8_11, .dense), L.Part),
    range_check_8_11_sparse: Mapped.ForPlacement(A.For(.range_check_8_11, .sparse), L.Part),
    range_check_8_8_4_dense: Mapped.ForPlacement(A.For(.range_check_8_8_4, .dense), L.Part),
    range_check_8_8_4_sparse: Mapped.ForPlacement(A.For(.range_check_8_8_4, .sparse), L.Part),
    range_check_8_8_dense: Mapped.ForPlacement(A.For(.range_check_8_8, .dense), L.Part),
    range_check_8_8_sparse: Mapped.ForPlacement(A.For(.range_check_8_8, .sparse), L.Part),
    range_check_m31_dense: Mapped.ForPlacement(A.For(.range_check_m31, .dense), L.Part),
    range_check_m31_sparse: Mapped.ForPlacement(A.For(.range_check_m31, .sparse), L.Part),
};
pub const Owner = struct {
    allocator: std.mem.Allocator,
    slots: [6]Slot,
    provers: [6]Engine.air.component_prover.ComponentProver,
    verifiers: [6]core.air.components.Component,
    pub fn init(a: std.mem.Allocator, layout: L.Layout, relations: Shared.SharedProviderRelations, claims: [6]R.Q) !*Owner {
        try layout.validate();
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.allocator = a;
        inline for (0..6) |i| {
            const kind: A.Schema.Kind = @enumFromInt(i);
            inline for (.{ A.Mode.dense, A.Mode.sparse }) |mode| {
                if (layout.parts[i].mode == mode) {
                    const name = @tagName(kind) ++ "_" ++ @tagName(mode);
                    const Spec = A.For(kind, mode);
                    const C = Mapped.ForPlacement(Spec, L.Part);
                    self.slots[i] = @unionInit(Slot, name, try C.init(.{ .relation = .from(@field(relations.native, @tagName(kind))), .sums = .{claims[i]} }, layout.parts[i]));
                    const c = &@field(self.slots[i], name);
                    self.provers[i] = c.asProverComponent();
                    self.verifiers[i] = c.asVerifierComponent();
                }
            }
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        self.allocator.destroy(self);
    }
};
