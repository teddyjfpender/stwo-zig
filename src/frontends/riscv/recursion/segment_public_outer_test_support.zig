//! Shared authenticated fixture for V2 public-spine source/component gates.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const public_data_v2 = @import("../air/public_data_v2.zig");
const public_data_support = @import("../air/public_data_v2_test_support.zig");
const native_relations = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const source_v2 = @import("segment_leaf_authority_v2.zig");
const public_v2 = @import("segment_public_outer_source_v2.zig");
const fixed_profile = @import("fixed_profile.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");
const schedule = @import("air/verifier_schedule.zig");

pub const component_descs = [_]statement_v1.FamilyComponentDesc{.{
    .family = .base_alu_imm,
    .log_size = 4,
    .n_rows = 3,
    .n_columns = 10,
}};

pub const infra_descs = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 4,
    .n_rows = 3,
    .n_columns = 4,
}};

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    owned_public: statement_v2.OwnedPublicDataV2,
    keys: source_v2.VerifierKeyAuthorityV2,
    source_trace: OwnedSourceTrace,
    source_prepared: source_v2.PreparedV2,
    relations: native_relations.Relations,
    native_sums: statement_v2.NativePublicSums,
    receipt: statement_v2.VerifiedReceipt,
    publication: source_v2.VerifiedNativePublicLogUpPublicationV2,
    vm_plan: schedule.Plan,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        const support_fixture = try public_data_support.Fixture.init();
        const source = support_fixture.rightSource();
        const words = try public_data_support.encode(allocator, &source);
        defer allocator.free(words);
        const borrowed = try public_data_v2.PublicDataV2.authenticate(words);
        var owned_public = try statement_v2.OwnedPublicDataV2.initVerified(
            allocator,
            &borrowed,
        );
        errdefer owned_public.deinit();
        const keys = try source_v2.VerifierKeyAuthorityV2.init(
            public_data_support.id("public-spine-v2-leaf-vk"),
            public_data_support.id("public-spine-v2-parent-vk"),
        );
        const source_shape = try source_v2.preflight(&owned_public.data, &keys);
        var source_trace = try OwnedSourceTrace.init(
            allocator,
            source_shape.manifest.trace_row_count,
        );
        errdefer source_trace.deinit();
        var source_prepared: source_v2.PreparedV2 = undefined;
        try source_v2.prepareInto(
            &source_prepared,
            source_trace.columns(),
            &owned_public.data,
            &keys,
        );

        const relations = native_relations.Relations.dummy();
        const native_sums = try statement_v2.NativePublicSums.init(
            &owned_public.data,
            &relations,
        );
        const receipt = try verifiedReceipt(&owned_public.data);
        var publication: source_v2.VerifiedNativePublicLogUpPublicationV2 =
            undefined;
        try source_v2.prepareVerifiedNativePublicLogUpInto(
            &publication,
            &source_prepared,
            &owned_public.data,
            &relations,
            &native_sums,
            &receipt,
            &component_descs,
            &infra_descs,
        );
        var vm_plan = try schedule.Plan.initShape(
            allocator,
            schedule.VM_PROGRAM_SPEC_V1,
            .{
                .protocol_id = channel.hashBytes(
                    "public-spine-v2-protocol",
                    0x5032_5650,
                ),
                .shape_id = channel.hashBytes(
                    "public-spine-v2-shape",
                    0x5032_5653,
                ),
                .interaction_pow_bits = 0,
                .pcs_pow_bits = protocol.PCS_POW_BITS,
                .query_count = 1,
                .table_count = 4,
                .claimed_sum_count = 4,
                .sampled_value_count = 8,
                .tree_heights = .{ 9, 9, 9, 9 },
                .fri = try fixed_profile.FriSchedule.init(
                    8,
                    protocol.PCS_CONFIG.fri_config,
                ),
            },
        );
        errdefer vm_plan.deinit();
        return .{
            .allocator = allocator,
            .owned_public = owned_public,
            .keys = keys,
            .source_trace = source_trace,
            .source_prepared = source_prepared,
            .relations = relations,
            .native_sums = native_sums,
            .receipt = receipt,
            .publication = publication,
            .vm_plan = vm_plan,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.vm_plan.deinit();
        self.source_trace.deinit();
        self.owned_public.deinit();
        self.* = undefined;
    }

    pub fn inputs(self: *const Fixture) public_v2.InputsV2 {
        return .{
            .statement_source = &self.source_prepared,
            .owned_public_data = &self.owned_public,
            .publication = &self.publication,
            .native_public_sums = &self.native_sums,
            .verified_receipt = &self.receipt,
            .relations = &self.relations,
            .component_descs = &component_descs,
            .infra_descs = &infra_descs,
            .vm_plan = &self.vm_plan,
        };
    }
};

const OwnedSourceTrace = struct {
    allocator: std.mem.Allocator,
    active: []M31,
    scope: []M31,
    index: []M31,
    value: []M31,

    fn init(allocator: std.mem.Allocator, rows: usize) !OwnedSourceTrace {
        const active = try allocator.alloc(M31, rows);
        errdefer allocator.free(active);
        const scope = try allocator.alloc(M31, rows);
        errdefer allocator.free(scope);
        const index = try allocator.alloc(M31, rows);
        errdefer allocator.free(index);
        const value = try allocator.alloc(M31, rows);
        errdefer allocator.free(value);
        return .{
            .allocator = allocator,
            .active = active,
            .scope = scope,
            .index = index,
            .value = value,
        };
    }

    fn deinit(self: *OwnedSourceTrace) void {
        self.allocator.free(self.value);
        self.allocator.free(self.index);
        self.allocator.free(self.scope);
        self.allocator.free(self.active);
        self.* = undefined;
    }

    fn columns(self: *OwnedSourceTrace) source_v2.TraceColumnsV2 {
        return .{
            .active = self.active,
            .scope = self.scope,
            .index = self.index,
            .value = self.value,
        };
    }
};

fn verifiedReceipt(
    data: *const public_data_v2.PublicDataV2,
) !statement_v2.VerifiedReceipt {
    var components: [statement_v1.MAX_COMPONENTS]statement_v1.FamilyComponentDesc =
        undefined;
    components[0] = component_descs[0];
    var infra: [statement_v1.MAX_INFRA_COMPONENTS]statement_v1.InfraComponentDesc =
        undefined;
    infra[0] = infra_descs[0];
    const core_public = try statement_v2.canonicalCorePublicData(data);
    const core = statement_v1.RiscVStatement{
        .n_components = 1,
        .component_descs = components,
        .initial_pc = core_public.initial_pc,
        .final_pc = core_public.final_pc,
        .total_steps = core_public.clock,
        .public_data = core_public,
        .n_infra = 1,
        .infra_descs = infra,
    };
    const statement = try statement_v2.RiscVStatementV2.init(core, data.*);
    return statement.verifiedReceipt();
}
