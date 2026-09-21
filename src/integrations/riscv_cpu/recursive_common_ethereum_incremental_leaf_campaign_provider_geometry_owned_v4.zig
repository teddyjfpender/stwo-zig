//! Immutable runtime campaign observations. Fresh inputs are borrowed only
//! during admission; each owner retains its own private counts and identities.
const std = @import("std");
const common = @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const field_public = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");
const input_mod = @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const FORMAT_VERSION = common.FORMAT_VERSION;
const SCHEMA_VERSION = common.SCHEMA_VERSION;
const Error = common.Error;
const CampaignInventoryAuthorityV4 = common.CampaignInventoryAuthorityV4;
const observeFreshInput = common.observeFreshInput;
const validateFreshInputForCampaign = common.validateFreshInputForCampaign;
const capacityForMaximum = common.capacityForMaximum;
const geometryForCapacity = common.geometryForCapacity;
const geometryIdentity = common.geometryIdentity;
const orderedInputsIdentitySlices = common.orderedInputsIdentitySlices;
const hashInt = common.hashInt;
const OWNED_AUTHORITY_DOMAIN = "stwo-zig/ethereum-incremental-provider-geometry-owned-authority/v4-schema3\x00";

pub const ViewV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    campaign_inventory: CampaignInventoryAuthorityV4,
    leaf_count: u32,
    first_leaf_index: u32 = 0,
    active_tuple_counts: []const u32,
    fresh_input_identities: []const [32]u8,
    maximum_active_tuple_count: u32,
    maximum_leaf_index: u32,
    provider_geometry: field_public.LiveProviderGeometryV4,
    ordered_input_identity_sha256: [32]u8,
    geometry_identity_sha256: [32]u8,
    authority_identity_sha256: [32]u8,

    pub fn validateStructure(self: *const ViewV4) Error!void {
        try self.campaign_inventory.validate();
        const count = std.math.cast(usize, self.leaf_count) orelse
            return error.ArithmeticOverflow;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != (if (self.first_leaf_index == 0) SCHEMA_VERSION else SCHEMA_VERSION + 1) or
            self.leaf_count > std.math.maxInt(u32) - self.first_leaf_index or
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

    pub fn view(self: *const ViewV4) *const ViewV4 {
        return self;
    }
};

/// Runtime-count, process-local authority consumed by production role-0
/// materializers. It owns only observations and identities, never fresh input
/// pointers or serializable verifier capabilities.
pub const OwnedCampaignProviderGeometryV4 = struct {
    handle: *Handle,

    const Self = @This();

    /// Audits already-live, independently cold-opened inputs without retaining
    /// their pointers. The input slice is borrowed only for this call.
    pub fn mintFromBorrowedFreshInputs(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        inventory: CampaignInventoryAuthorityV4,
        inputs: []const *const input_mod.FreshInputV4(Engine),
    ) !Self {
        return mintFromBorrowedFreshInputsAt(Engine, allocator, inventory, 0, inputs);
    }

    /// Admits a contiguous independently verified subrange. Local array slots
    /// stay separate from authenticated native/global leaf coordinates.
    pub fn mintFromBorrowedFreshInputsAt(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        inventory: CampaignInventoryAuthorityV4,
        first_leaf_index: u32,
        inputs: []const *const input_mod.FreshInputV4(Engine),
    ) !Self {
        try inventory.validate();
        if (inventory.leaf_count > std.math.maxInt(u32) - first_leaf_index) return error.ArithmeticOverflow;
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
                @as(usize, first_leaf_index) + index,
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
        var result = try mintOwnedFromObservationsAt(
            allocator,
            inventory,
            counts,
            identities,
            first_leaf_index,
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

    const Handle = opaque {};
    const Storage = struct { allocator: std.mem.Allocator, value: ViewV4 };

    fn storage(self: *const Self) *Storage {
        return @ptrCast(@alignCast(self.handle));
    }

    /// Immutable metadata: callers receive no mutable aliases to observations.
    pub fn view(self: *const Self) *const ViewV4 {
        return &self.storage().value;
    }

    pub fn clone(self: *const Self, allocator: std.mem.Allocator) !Self {
        const value = self.view();
        const counts = try allocator.dupe(u32, value.active_tuple_counts);
        errdefer allocator.free(counts);
        const identities = try allocator.dupe([32]u8, value.fresh_input_identities);
        errdefer allocator.free(identities);
        // This private storage was admitted by mint and exposes only deeply
        // const observations. Cloning owns new buffers with identical values;
        // it does not admit new campaign data or need another quadratic audit.
        const backing = try allocator.create(Storage);
        backing.* = .{ .allocator = allocator, .value = value.* };
        backing.value.active_tuple_counts = counts;
        backing.value.fresh_input_identities = identities;
        return .{ .handle = @ptrCast(backing) };
    }

    pub fn deinit(self: *Self) void {
        const backing = self.storage();
        const allocator = backing.allocator;
        allocator.free(backing.value.fresh_input_identities);
        allocator.free(backing.value.active_tuple_counts);
        allocator.destroy(backing);
        self.* = undefined;
    }

    pub fn validateStructure(self: *const Self) Error!void {
        try self.view().validateStructure();
    }

    pub fn validateFreshInputAt(
        self: *const Self,
        comptime Engine: type,
        allocator: std.mem.Allocator,
        index: usize,
        input: *const input_mod.FreshInputV4(Engine),
    ) !void {
        try validateFreshInputForCampaign(Engine, allocator, self, index, input);
    }
};

fn mintOwnedFromObservationsInternal(
    allocator: std.mem.Allocator,
    inventory: CampaignInventoryAuthorityV4,
    owned_counts: []u32,
    owned_identities: [][32]u8,
) !OwnedCampaignProviderGeometryV4 {
    return mintOwnedFromObservationsAt(allocator, inventory, owned_counts, owned_identities, 0);
}

fn mintOwnedFromObservationsAt(
    allocator: std.mem.Allocator,
    inventory: CampaignInventoryAuthorityV4,
    owned_counts: []u32,
    owned_identities: [][32]u8,
    first_leaf_index: u32,
) !OwnedCampaignProviderGeometryV4 {
    try inventory.validate();
    if (inventory.leaf_count > std.math.maxInt(u32) - first_leaf_index) return error.ArithmeticOverflow;
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
    var result = ViewV4{
        .schema_version = if (first_leaf_index == 0) SCHEMA_VERSION else SCHEMA_VERSION + 1,
        .first_leaf_index = first_leaf_index,
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
    const backing = try allocator.create(OwnedCampaignProviderGeometryV4.Storage);
    backing.* = .{ .allocator = allocator, .value = result };
    return .{ .handle = @ptrCast(backing) };
}

fn ownedAuthorityIdentity(self: *const ViewV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(OWNED_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, self.format_version);
    hashInt(&hash, u16, self.schema_version);
    hashInt(&hash, u32, self.leaf_count);
    hash.update(&self.campaign_inventory.table_identity_sha256);
    hash.update(&self.geometry_identity_sha256);
    hash.update(&self.ordered_input_identity_sha256);
    hashInt(&hash, u32, self.maximum_leaf_index);
    if (self.first_leaf_index != 0) hashInt(&hash, u32, self.first_leaf_index);
    return hash.finalResult();
}

/// Synthetic observations may exercise invariants only in a test executable.
/// Runtime callers must admit real cold inputs or clone an existing owner.
pub const testing = if (@import("builtin").is_test) struct {
    pub const mintFromObservations = mintOwnedFromObservationsInternal;
} else struct {};

test "runtime campaign subrange preserves coordinates through clone and rejects metadata mutation" {
    const allocator = std.testing.allocator;
    const Helper = struct {
        fn mint(first: u32) !OwnedCampaignProviderGeometryV4 {
            const a = std.testing.allocator;
            const counts = try a.dupe(u32, &.{ 1, 1 });
            errdefer a.free(counts);
            const identities = try a.dupe([32]u8, &.{ [_]u8{1} ** 32, [_]u8{2} ** 32 });
            errdefer a.free(identities);
            return mintOwnedFromObservationsAt(a, .{ .leaf_count = 2, .table_identity_sha256 = [_]u8{3} ** 32 }, counts, identities, first);
        }
    };
    var legacy = try Helper.mint(0);
    defer legacy.deinit();
    var selected = try Helper.mint(1);
    defer selected.deinit();
    try std.testing.expectEqual(@as(u16, 3), legacy.view().schema_version);
    try std.testing.expectEqual(@as(u16, 4), selected.view().schema_version);
    try std.testing.expectEqual(legacy.view().geometry_identity_sha256, selected.view().geometry_identity_sha256);
    try std.testing.expect(!std.meta.eql(legacy.view().authority_identity_sha256, selected.view().authority_identity_sha256));
    var copy = try selected.clone(allocator);
    defer copy.deinit();
    try std.testing.expectEqualDeep(selected.view().*, copy.view().*);
    try std.testing.expect(selected.view().active_tuple_counts.ptr != copy.view().active_tuple_counts.ptr);
    var changed = selected.view().*;
    changed.first_leaf_index += 1;
    try std.testing.expectError(error.CampaignProviderGeometryMismatchV4, changed.validateStructure());
    changed = selected.view().*;
    changed.schema_version = SCHEMA_VERSION;
    try std.testing.expectError(error.CampaignProviderGeometryMismatchV4, changed.validateStructure());
    try std.testing.expectError(error.ArithmeticOverflow, Helper.mint(std.math.maxInt(u32)));
}
