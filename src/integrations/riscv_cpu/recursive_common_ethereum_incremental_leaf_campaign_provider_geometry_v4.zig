//! Cold-audited campaign-wide provider geometry for the role-0 wrapper.
//! Production minting accepts the protocol-bounded count and order sealed by
//! STWCIT04. No caller supplies tuple counts, capacity, or provider log sizes.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact = @import("recursive_node_artifact_v1.zig");
const field_public =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");
const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const campaign_table =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const PRODUCTION_LEAF_COUNT: usize = artifact.REAL_LEAF_COUNT;
pub const PRODUCTION_MINT_REQUIRES_FRESH_INPUTS = true;
pub const RUNTIME_CAMPAIGN_COUNT = true;
pub const STREAMING_COLD_OPENER_AVAILABLE = true;
pub const CALLER_AUTHORED_MAXIMUM_ADMITTED = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const PRODUCTION_ACTIVATION = false;

const ORDERED_INPUT_DOMAIN =
    "stwo-zig/ethereum-incremental-provider-geometry-inputs/v4-schema3\x00";
const GEOMETRY_DOMAIN =
    "stwo-zig/ethereum-incremental-provider-geometry/v4-schema3\x00";
const AUTHORITY_DOMAIN =
    "stwo-zig/ethereum-incremental-provider-geometry-authority/v4-schema3\x00";
const OWNED_AUTHORITY_DOMAIN =
    "stwo-zig/ethereum-incremental-provider-geometry-owned-authority/v4-schema3\x00";

pub const Error = field_public.Error || error{
    ArithmeticOverflow,
    CampaignProviderGeometryMismatchV4,
    InvalidCampaignProviderGeometryInputV4,
};

/// Pointer-free audit receipt. It remints only from the exact fresh inputs;
/// it is not itself a verifier lease or proof-admission capability.
pub fn CampaignProviderGeometryAuthorityV4ForCount(
    comptime campaign_leaf_count: usize,
) type {
    if (campaign_leaf_count == 0 or
        campaign_leaf_count > std.math.maxInt(u32))
        @compileError("campaign provider geometry count is invalid");
    return struct {
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        leaf_count: u32 = campaign_leaf_count,
        active_tuple_counts: [campaign_leaf_count]u32,
        fresh_input_identities: [campaign_leaf_count][32]u8,
        maximum_active_tuple_count: u32,
        maximum_leaf_index: u32,
        provider_geometry: field_public.LiveProviderGeometryV4,
        ordered_input_identity_sha256: [32]u8,
        geometry_identity_sha256: [32]u8,
        authority_identity_sha256: [32]u8,

        const Self = @This();

        pub fn mint(
            comptime Engine: type,
            allocator: std.mem.Allocator,
            inputs: *const [campaign_leaf_count]*const input_mod.FreshInputV4(Engine),
        ) !Self {
            const observations = try observeFreshInputs(
                Engine,
                campaign_leaf_count,
                allocator,
                inputs,
            );
            var result = try mintFromObservations(
                campaign_leaf_count,
                &observations.counts,
                &observations.identities,
            );
            try validateSharedGeometryAgainstFreshInputs(
                Engine,
                campaign_leaf_count,
                allocator,
                inputs,
                result,
            );
            try result.validateStructure();
            return result;
        }

        pub fn validateAgainst(
            self: *const Self,
            comptime Engine: type,
            allocator: std.mem.Allocator,
            inputs: *const [campaign_leaf_count]*const input_mod.FreshInputV4(Engine),
        ) !void {
            const expected = try Self.mint(Engine, allocator, inputs);
            if (!std.meta.eql(self.*, expected))
                return error.CampaignProviderGeometryMismatchV4;
        }

        pub fn validateStructure(self: *const Self) Error!void {
            try validateForCount(self, campaign_leaf_count);
        }

        /// Reconstructs this leaf's tuple stream from its live verifier-owned
        /// Stage101 capability and checks exact ordered campaign membership.
        pub fn validateFreshInputAt(
            self: *const Self,
            comptime Engine: type,
            allocator: std.mem.Allocator,
            index: usize,
            input: *const input_mod.FreshInputV4(Engine),
        ) !void {
            try self.validateStructure();
            if (index >= campaign_leaf_count)
                return error.InvalidCampaignProviderGeometryInputV4;
            try input.validate();
            const leaf_index = std.math.cast(u32, index) orelse
                return error.ArithmeticOverflow;
            if (input.coordinate.height != 0 or
                input.coordinate.index != leaf_index or
                input.coordinate.global_ordinal != leaf_index or
                !std.mem.eql(
                    u8,
                    &input.capability_identity_sha256,
                    &self.fresh_input_identities[index],
                ))
            {
                return error.InvalidCampaignProviderGeometryInputV4;
            }
            var witness = try role_io.OwnedWitnessV4.initUnfrozenForAudit(
                allocator,
                &input.stage101.public_data.data,
                &input.stage101.role_aware_public.value,
                &input.stage101.relations.base,
                self.provider_geometry.role_io_tuple_capacity,
            );
            defer witness.deinit();
            if (witness.active_tuple_count != self.active_tuple_counts[index])
                return error.CampaignProviderGeometryMismatchV4;
            var schedule = try field_public.OwnedPoseidonScheduleV4.init(
                Engine,
                allocator,
                input,
                &witness,
            );
            defer schedule.deinit();
            const observed = try schedule.liveProviderGeometry();
            if (!sharedGeometryEql(observed, self.provider_geometry))
                return error.CampaignProviderGeometryMismatchV4;
        }
    };
}

pub const CampaignProviderGeometryAuthorityV4 =
    CampaignProviderGeometryAuthorityV4ForCount(PRODUCTION_LEAF_COUNT);

/// Authenticated, path-free campaign custody used by the runtime authority.
/// `table_identity_sha256` is copied only from a validated STWCIT04 table.
pub const CampaignInventoryAuthorityV4 = struct {
    leaf_count: u32,
    table_identity_sha256: [32]u8,

    pub fn fromTable(table: *const campaign_table.CampaignTableV4) !@This() {
        try table.validate();
        const result = @This(){
            .leaf_count = table.segment_count,
            .table_identity_sha256 = table.content_sha256,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: @This()) Error!void {
        _ = campaign_table.TopologyV4.derive(self.leaf_count) catch
            return error.InvalidCampaignProviderGeometryInputV4;
        if (std.mem.allEqual(u8, &self.table_identity_sha256, 0))
            return error.InvalidCampaignProviderGeometryInputV4;
    }
};

/// Runtime-count, process-local authority consumed by production role-0
/// materializers. It owns only observations and identities, never fresh input
/// pointers or serializable verifier capabilities.
pub const OwnedCampaignProviderGeometryV4 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    campaign_inventory: CampaignInventoryAuthorityV4,
    leaf_count: u32,
    active_tuple_counts: []u32,
    fresh_input_identities: [][32]u8,
    maximum_active_tuple_count: u32,
    maximum_leaf_index: u32,
    provider_geometry: field_public.LiveProviderGeometryV4,
    ordered_input_identity_sha256: [32]u8,
    geometry_identity_sha256: [32]u8,
    authority_identity_sha256: [32]u8,

    const Self = @This();

    /// Audits already-live, independently cold-opened inputs without retaining
    /// their pointers. The input slice is borrowed only for this call.
    pub fn mintFromBorrowedFreshInputs(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        inventory: CampaignInventoryAuthorityV4,
        inputs: []const *const input_mod.FreshInputV4(Engine),
    ) !Self {
        try inventory.validate();
        if (inputs.len != inventory.leaf_count)
            return error.InvalidCampaignProviderGeometryInputV4;
        const counts = try allocator.alloc(u32, inputs.len);
        var counts_owned = true;
        errdefer if (counts_owned) allocator.free(counts);
        const identities = try allocator.alloc([32]u8, inputs.len);
        var identities_owned = true;
        errdefer if (identities_owned) allocator.free(identities);
        for (inputs, 0..) |input, index| {
            const observation = try observeFreshInput(
                Engine,
                allocator,
                index,
                input,
            );
            counts[index] = observation.active_tuple_count;
            identities[index] = observation.identity_sha256;
            for (identities[0..index]) |earlier| if (std.mem.eql(
                u8,
                &earlier,
                &identities[index],
            )) return error.InvalidCampaignProviderGeometryInputV4;
        }
        var result = try mintOwnedFromObservationsInternal(
            allocator,
            inventory,
            counts,
            identities,
        );
        counts_owned = false;
        identities_owned = false;
        errdefer result.deinit();
        for (inputs, 0..) |input, index|
            try result.validateFreshInputAt(Engine, allocator, index, input);
        return result;
    }

    /// Two-pass streaming mint. `opener.openFreshInput(allocator, index)` must
    /// return one owned `FreshInputV4(Engine)`; every opened value is destroyed
    /// before the next index, so campaign cardinality does not set live-memory
    /// ownership. The second pass proves the common maximum geometry.
    pub fn mintFromColdOpener(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        inventory: CampaignInventoryAuthorityV4,
        opener: anytype,
    ) !Self {
        try inventory.validate();
        const count = std.math.cast(usize, inventory.leaf_count) orelse
            return error.ArithmeticOverflow;
        const counts = try allocator.alloc(u32, count);
        var counts_owned = true;
        errdefer if (counts_owned) allocator.free(counts);
        const identities = try allocator.alloc([32]u8, count);
        var identities_owned = true;
        errdefer if (identities_owned) allocator.free(identities);
        for (0..count) |index| {
            var input = try opener.openFreshInput(allocator, index);
            defer input.deinit();
            const observation = try observeFreshInput(
                Engine,
                allocator,
                index,
                &input,
            );
            counts[index] = observation.active_tuple_count;
            identities[index] = observation.identity_sha256;
            for (identities[0..index]) |earlier| if (std.mem.eql(
                u8,
                &earlier,
                &identities[index],
            )) return error.InvalidCampaignProviderGeometryInputV4;
        }
        var result = try mintOwnedFromObservationsInternal(
            allocator,
            inventory,
            counts,
            identities,
        );
        counts_owned = false;
        identities_owned = false;
        errdefer result.deinit();
        for (0..count) |index| {
            var input = try opener.openFreshInput(allocator, index);
            defer input.deinit();
            try result.validateFreshInputAt(Engine, allocator, index, &input);
        }
        return result;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.fresh_input_identities);
        self.allocator.free(self.active_tuple_counts);
        self.* = undefined;
    }

    pub fn validateStructure(self: *const Self) Error!void {
        try self.campaign_inventory.validate();
        const count = std.math.cast(usize, self.leaf_count) orelse
            return error.ArithmeticOverflow;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.leaf_count != self.campaign_inventory.leaf_count or
            self.active_tuple_counts.len != count or
            self.fresh_input_identities.len != count)
        {
            return error.CampaignProviderGeometryMismatchV4;
        }
        var maximum: u32 = 0;
        var maximum_index: u32 = 0;
        for (
            self.active_tuple_counts,
            self.fresh_input_identities,
            0..,
        ) |active, identity_value, index| {
            if (std.mem.allEqual(u8, &identity_value, 0))
                return error.CampaignProviderGeometryMismatchV4;
            for (self.fresh_input_identities[0..index]) |earlier|
                if (std.mem.eql(u8, &earlier, &identity_value))
                    return error.CampaignProviderGeometryMismatchV4;
            if (active > maximum) {
                maximum = active;
                maximum_index = std.math.cast(u32, index) orelse
                    return error.ArithmeticOverflow;
            }
        }
        try self.provider_geometry.validate();
        const expected_capacity = try capacityForMaximum(maximum);
        if (self.maximum_active_tuple_count != maximum or
            self.maximum_leaf_index != maximum_index or
            self.provider_geometry.role_io_tuple_count != maximum or
            self.provider_geometry.role_io_tuple_capacity != expected_capacity or
            !std.mem.eql(
                u8,
                &self.ordered_input_identity_sha256,
                &orderedInputsIdentitySlices(
                    self.campaign_inventory,
                    self.active_tuple_counts,
                    self.fresh_input_identities,
                ),
            ) or !std.mem.eql(
            u8,
            &self.geometry_identity_sha256,
            &geometryIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.authority_identity_sha256,
            &ownedAuthorityIdentity(self),
        )) return error.CampaignProviderGeometryMismatchV4;
    }

    pub fn validateFreshInputAt(
        self: *const Self,
        comptime Engine: type,
        allocator: std.mem.Allocator,
        index: usize,
        input: *const input_mod.FreshInputV4(Engine),
    ) !void {
        try self.validateStructure();
        if (index >= self.active_tuple_counts.len)
            return error.InvalidCampaignProviderGeometryInputV4;
        const observation = try observeFreshInput(
            Engine,
            allocator,
            index,
            input,
        );
        if (observation.active_tuple_count != self.active_tuple_counts[index] or
            !std.mem.eql(
                u8,
                &observation.identity_sha256,
                &self.fresh_input_identities[index],
            )) return error.InvalidCampaignProviderGeometryInputV4;
        var witness = try role_io.OwnedWitnessV4.initUnfrozenForAudit(
            allocator,
            &input.stage101.public_data.data,
            &input.stage101.role_aware_public.value,
            &input.stage101.relations.base,
            self.provider_geometry.role_io_tuple_capacity,
        );
        defer witness.deinit();
        var schedule = try field_public.OwnedPoseidonScheduleV4.init(
            Engine,
            allocator,
            input,
            &witness,
        );
        defer schedule.deinit();
        if (!sharedGeometryEql(
            try schedule.liveProviderGeometry(),
            self.provider_geometry,
        )) return error.CampaignProviderGeometryMismatchV4;
    }
};

pub const testing = struct {
    /// Synthetic two-leaf seam. It exercises maximum/order/capacity logic but
    /// cannot mint the production 210-leaf authority because leaf_count stays
    /// two and `validateStructure` therefore rejects it.
    pub fn mintForTwo(
        counts: [2]u32,
        identities: [2][32]u8,
    ) !CampaignProviderGeometryAuthorityV4ForCount(2) {
        return mintFromObservations(2, &counts, &identities);
    }

    pub fn validateForTwo(
        value: *const CampaignProviderGeometryAuthorityV4ForCount(2),
    ) Error!void {
        try validateForCount(value, 2);
    }

    pub fn mintOwnedFromObservations(
        allocator: std.mem.Allocator,
        campaign_identity_sha256: [32]u8,
        counts: []const u32,
        identities: []const [32]u8,
    ) !OwnedCampaignProviderGeometryV4 {
        const count = std.math.cast(u32, counts.len) orelse
            return error.ArithmeticOverflow;
        const owned_counts = try allocator.dupe(u32, counts);
        errdefer allocator.free(owned_counts);
        const owned_identities = try allocator.dupe([32]u8, identities);
        errdefer allocator.free(owned_identities);
        return mintOwnedFromObservationsInternal(
            allocator,
            .{
                .leaf_count = count,
                .table_identity_sha256 = campaign_identity_sha256,
            },
            owned_counts,
            owned_identities,
        );
    }
};

const FreshObservationV4 = struct {
    active_tuple_count: u32,
    identity_sha256: [32]u8,
};

fn observeFreshInput(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    index: usize,
    input: *const input_mod.FreshInputV4(Engine),
) !FreshObservationV4 {
    const leaf_index = std.math.cast(u32, index) orelse
        return error.ArithmeticOverflow;
    try input.validate();
    if (input.coordinate.height != 0 or
        input.coordinate.index != leaf_index or
        input.coordinate.global_ordinal != leaf_index)
    {
        return error.InvalidCampaignProviderGeometryInputV4;
    }
    var witness = try role_io.OwnedWitnessV4.initLive(
        allocator,
        &input.stage101.public_data.data,
        &input.stage101.role_aware_public.value,
        &input.stage101.relations.base,
    );
    defer witness.deinit();
    var schedule = try field_public.OwnedPoseidonScheduleV4.init(
        Engine,
        allocator,
        input,
        &witness,
    );
    defer schedule.deinit();
    _ = try schedule.liveProviderGeometry();
    return .{
        .active_tuple_count = witness.active_tuple_count,
        .identity_sha256 = input.capability_identity_sha256,
    };
}

fn mintOwnedFromObservationsInternal(
    allocator: std.mem.Allocator,
    inventory: CampaignInventoryAuthorityV4,
    owned_counts: []u32,
    owned_identities: [][32]u8,
) !OwnedCampaignProviderGeometryV4 {
    try inventory.validate();
    if (owned_counts.len != inventory.leaf_count or
        owned_identities.len != owned_counts.len)
    {
        return error.InvalidCampaignProviderGeometryInputV4;
    }
    var maximum: u32 = 0;
    var maximum_index: u32 = 0;
    for (owned_counts, owned_identities, 0..) |active, identity_value, index| {
        if (std.mem.allEqual(u8, &identity_value, 0))
            return error.InvalidCampaignProviderGeometryInputV4;
        for (owned_identities[0..index]) |earlier| if (std.mem.eql(
            u8,
            &earlier,
            &identity_value,
        )) return error.InvalidCampaignProviderGeometryInputV4;
        if (active > maximum) {
            maximum = active;
            maximum_index = std.math.cast(u32, index) orelse
                return error.ArithmeticOverflow;
        }
    }
    const capacity = try capacityForMaximum(maximum);
    var result = OwnedCampaignProviderGeometryV4{
        .allocator = allocator,
        .campaign_inventory = inventory,
        .leaf_count = inventory.leaf_count,
        .active_tuple_counts = owned_counts,
        .fresh_input_identities = owned_identities,
        .maximum_active_tuple_count = maximum,
        .maximum_leaf_index = maximum_index,
        .provider_geometry = try geometryForCapacity(maximum, capacity),
        .ordered_input_identity_sha256 = orderedInputsIdentitySlices(
            inventory,
            owned_counts,
            owned_identities,
        ),
        .geometry_identity_sha256 = undefined,
        .authority_identity_sha256 = undefined,
    };
    result.geometry_identity_sha256 = geometryIdentity(&result);
    result.authority_identity_sha256 = ownedAuthorityIdentity(&result);
    try result.validateStructure();
    return result;
}

fn Observations(comptime count: usize) type {
    return struct {
        counts: [count]u32,
        identities: [count][32]u8,
    };
}

fn observeFreshInputs(
    comptime Engine: type,
    comptime count: usize,
    allocator: std.mem.Allocator,
    inputs: *const [count]*const input_mod.FreshInputV4(Engine),
) !Observations(count) {
    var result: Observations(count) = undefined;
    for (inputs, 0..) |input, index| {
        const leaf_index = std.math.cast(u32, index) orelse
            return error.ArithmeticOverflow;
        try input.validate();
        if (input.coordinate.height != 0 or
            input.coordinate.index != leaf_index or
            input.coordinate.global_ordinal != leaf_index)
        {
            return error.InvalidCampaignProviderGeometryInputV4;
        }
        for (inputs[0..index]) |earlier| if (earlier == input)
            return error.InvalidCampaignProviderGeometryInputV4;
        var witness = try role_io.OwnedWitnessV4.initLive(
            allocator,
            &input.stage101.public_data.data,
            &input.stage101.role_aware_public.value,
            &input.stage101.relations.base,
        );
        defer witness.deinit();
        var schedule = try field_public.OwnedPoseidonScheduleV4.init(
            Engine,
            allocator,
            input,
            &witness,
        );
        defer schedule.deinit();
        _ = try schedule.liveProviderGeometry();
        result.counts[index] = witness.active_tuple_count;
        result.identities[index] = input.capability_identity_sha256;
    }
    return result;
}

fn validateSharedGeometryAgainstFreshInputs(
    comptime Engine: type,
    comptime count: usize,
    allocator: std.mem.Allocator,
    inputs: *const [count]*const input_mod.FreshInputV4(Engine),
    authority: CampaignProviderGeometryAuthorityV4ForCount(count),
) !void {
    for (inputs, 0..) |input, index| {
        var witness = try role_io.OwnedWitnessV4.initUnfrozenForAudit(
            allocator,
            &input.stage101.public_data.data,
            &input.stage101.role_aware_public.value,
            &input.stage101.relations.base,
            authority.provider_geometry.role_io_tuple_capacity,
        );
        defer witness.deinit();
        var schedule = try field_public.OwnedPoseidonScheduleV4.init(
            Engine,
            allocator,
            input,
            &witness,
        );
        defer schedule.deinit();
        const geometry = try schedule.liveProviderGeometry();
        if (geometry.role_io_tuple_count >
            authority.maximum_active_tuple_count or
            !sharedGeometryEql(geometry, authority.provider_geometry) or
            (index == authority.maximum_leaf_index and
                geometry.role_io_tuple_count !=
                    authority.maximum_active_tuple_count))
        {
            return error.CampaignProviderGeometryMismatchV4;
        }
    }
}

fn mintFromObservations(
    comptime count: usize,
    counts: *const [count]u32,
    identities: *const [count][32]u8,
) !CampaignProviderGeometryAuthorityV4ForCount(count) {
    if (count == 0) return error.InvalidCampaignProviderGeometryInputV4;
    var maximum: u32 = 0;
    var maximum_index: u32 = 0;
    for (counts, identities, 0..) |active, identity_value, index| {
        if (std.mem.allEqual(u8, &identity_value, 0))
            return error.InvalidCampaignProviderGeometryInputV4;
        if (active > maximum) {
            maximum = active;
            maximum_index = @intCast(index);
        }
    }
    const capacity = try capacityForMaximum(maximum);
    const provider_geometry = try geometryForCapacity(maximum, capacity);
    var result = CampaignProviderGeometryAuthorityV4ForCount(count){
        .leaf_count = count,
        .active_tuple_counts = counts.*,
        .fresh_input_identities = identities.*,
        .maximum_active_tuple_count = maximum,
        .maximum_leaf_index = maximum_index,
        .provider_geometry = provider_geometry,
        .ordered_input_identity_sha256 = orderedInputsIdentity(
            count,
            counts,
            identities,
        ),
        .geometry_identity_sha256 = undefined,
        .authority_identity_sha256 = undefined,
    };
    result.geometry_identity_sha256 = geometryIdentity(&result);
    result.authority_identity_sha256 = authorityIdentity(&result);
    try validateForCount(&result, count);
    return result;
}

fn geometryForCapacity(
    maximum: u32,
    capacity: u32,
) Error!field_public.LiveProviderGeometryV4 {
    const word_count = std.math.add(
        usize,
        role_io.HEADER_WORD_COUNT,
        std.math.mul(usize, capacity, role_io.TUPLE_WORD_COUNT) catch
            return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
    const io_calls = frontend.recursion.poseidon2_channel
        .canonicalWordPermutationCount(word_count);
    const active_rows = std.math.add(
        usize,
        field_public.FIXED_PROVIDER_CALL_COUNT,
        io_calls,
    ) catch return error.ArithmeticOverflow;
    const log_size = try role_io.providerLogSize(@intCast(active_rows));
    const result = field_public.LiveProviderGeometryV4{
        .role_io_tuple_count = maximum,
        .role_io_tuple_capacity = capacity,
        .role_io_word_count = @intCast(word_count),
        .role_io_call_count = @intCast(io_calls),
        .provider_active_row_count = @intCast(active_rows),
        .provider_log_size = log_size,
        .provider_row_capacity = @as(u32, 1) << @intCast(log_size),
    };
    try result.validate();
    return result;
}

/// Even an empty active prefix commits the canonical header and one zero
/// padding tuple. This matches `OwnedWitnessV4.initLive` and keeps the shared
/// provider domain nonempty without inventing a public-I/O relation tuple.
fn capacityForMaximum(maximum: u32) Error!u32 {
    return std.math.ceilPowerOfTwo(u32, @max(maximum, 1)) catch
        error.ArithmeticOverflow;
}

fn validateForCount(
    self: anytype,
    comptime expected_count: usize,
) Error!void {
    const expected_count_u32 = std.math.cast(u32, expected_count) orelse
        return error.ArithmeticOverflow;
    var maximum: u32 = 0;
    var maximum_index: u32 = 0;
    for (
        self.active_tuple_counts,
        self.fresh_input_identities,
        0..,
    ) |active, identity_value, index| {
        if (std.mem.allEqual(u8, &identity_value, 0))
            return error.CampaignProviderGeometryMismatchV4;
        if (active > maximum) {
            maximum = active;
            maximum_index = std.math.cast(u32, index) orelse
                return error.ArithmeticOverflow;
        }
    }
    try self.provider_geometry.validate();
    const expected_capacity = try capacityForMaximum(
        self.maximum_active_tuple_count,
    );
    if (self.format_version != FORMAT_VERSION or
        self.schema_version != SCHEMA_VERSION or
        self.leaf_count != expected_count_u32 or
        self.maximum_active_tuple_count != maximum or
        self.maximum_leaf_index != maximum_index or
        self.provider_geometry.role_io_tuple_count !=
            self.maximum_active_tuple_count or
        self.provider_geometry.role_io_tuple_capacity != expected_capacity or
        !std.mem.eql(
            u8,
            &self.ordered_input_identity_sha256,
            &orderedInputsIdentity(
                expected_count,
                &self.active_tuple_counts,
                &self.fresh_input_identities,
            ),
        ) or
        !std.mem.eql(
            u8,
            &self.geometry_identity_sha256,
            &geometryIdentity(self),
        ) or !std.mem.eql(
        u8,
        &self.authority_identity_sha256,
        &authorityIdentity(self),
    )) {
        return error.CampaignProviderGeometryMismatchV4;
    }
}

fn sharedGeometryEql(
    leaf: field_public.LiveProviderGeometryV4,
    campaign: field_public.LiveProviderGeometryV4,
) bool {
    var normalized = leaf;
    normalized.role_io_tuple_count = campaign.role_io_tuple_count;
    return std.meta.eql(normalized, campaign);
}

fn orderedInputsIdentity(
    comptime count: usize,
    counts: *const [count]u32,
    identities: *const [count][32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ORDERED_INPUT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, count);
    for (counts, identities, 0..) |active, identity_value, index| {
        hashInt(&hash, u32, index);
        hashInt(&hash, u32, active);
        hash.update(&identity_value);
    }
    return hash.finalResult();
}

fn orderedInputsIdentitySlices(
    inventory: CampaignInventoryAuthorityV4,
    counts: []const u32,
    identities: []const [32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ORDERED_INPUT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, inventory.leaf_count);
    hash.update(&inventory.table_identity_sha256);
    for (counts, identities, 0..) |active, identity_value, index| {
        hashInt(&hash, u32, index);
        hashInt(&hash, u32, active);
        hash.update(&identity_value);
    }
    return hash.finalResult();
}

fn geometryIdentity(self: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GEOMETRY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, self.leaf_count);
    hashInt(&hash, u32, self.maximum_active_tuple_count);
    hashInt(&hash, u32, self.provider_geometry.role_io_tuple_capacity);
    hashInt(&hash, u32, self.provider_geometry.role_io_word_count);
    hashInt(&hash, u32, self.provider_geometry.role_io_call_count);
    hashInt(&hash, u32, self.provider_geometry.fixed_call_count);
    hashInt(&hash, u32, self.provider_geometry.provider_active_row_count);
    hashInt(&hash, u32, self.provider_geometry.provider_log_size);
    hashInt(&hash, u32, self.provider_geometry.provider_row_capacity);
    return hash.finalResult();
}

fn authorityIdentity(self: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hash.update(&self.geometry_identity_sha256);
    hash.update(&self.ordered_input_identity_sha256);
    hashInt(&hash, u32, self.maximum_leaf_index);
    return hash.finalResult();
}

fn ownedAuthorityIdentity(self: *const OwnedCampaignProviderGeometryV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(OWNED_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, self.format_version);
    hashInt(&hash, u16, self.schema_version);
    hashInt(&hash, u32, self.leaf_count);
    hash.update(&self.campaign_inventory.table_identity_sha256);
    hash.update(&self.geometry_identity_sha256);
    hash.update(&self.ordered_input_identity_sha256);
    hashInt(&hash, u32, self.maximum_leaf_index);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        PRODUCTION_LEAF_COUNT != 210 or
        !PRODUCTION_MINT_REQUIRES_FRESH_INPUTS or
        !RUNTIME_CAMPAIGN_COUNT or !STREAMING_COLD_OPENER_AVAILABLE or
        CALLER_AUTHORED_MAXIMUM_ADMITTED or SERIALIZABLE_FRESH_CAPABILITY or
        PRODUCTION_ACTIVATION)
    {
        @compileError("campaign provider geometry V4 drifted");
    }
}
