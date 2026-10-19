//! Native VM composition profile rebuilt from leaf-key descriptor geometry.
//! No proof, sampled value, public statement, or captured profile is an input.
const std = @import("std");
const PcsConfig = @import("stwo_core").pcs.PcsConfig;
const descriptors_mod = @import("detached_segment_authority_boundary_v1.zig");
const columns = @import("detached_native_column_geometry_v1.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");

pub fn derive(
    allocator: std.mem.Allocator,
    descriptors: descriptors_mod.DescriptorsV1,
    pcs_config: PcsConfig,
) !profile_mod.ProfileV2 {
    var native_geometry = try columns.init(
        allocator,
        descriptors,
        pcs_config.fri_config.log_blowup_factor,
    );
    defer native_geometry.deinit();
    const pcs_profile = try native_geometry.pcsProfile(
        std.math.cast(u32, pcs_config.fri_config.n_queries) orelse
            return error.InvalidNativeDescriptorGeometry,
    );
    const sample_count = std.math.cast(u32, try pcs_profile.sampleCount()) orelse
        return error.InvalidNativeDescriptorGeometry;
    const manifest = lookup.Manifest.native();
    const authenticated = try lookup.AuthenticatedStatement.initFromComponents(
        descriptors.components,
        &manifest,
    );
    return profile_mod.deriveAuthorityFromGeometryWithCircuitProfile(
        allocator,
        .{ .components = descriptors.components, .infrastructure = descriptors.infrastructure },
        &manifest,
        &authenticated,
        sample_count,
        .legacy_v4,
    );
}
