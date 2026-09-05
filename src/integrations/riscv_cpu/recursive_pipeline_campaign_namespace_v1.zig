//! Stable Zig-owned namespace for one recursive pipeline campaign.
//!
//! This is controller/cache isolation, not proof admission.  It intentionally
//! excludes the leaf table, manifests, segment count, and per-leaf inventory:
//! reminting or repartitioning the same admitted program/input/output campaign
//! does not poison branch-local cache reuse.  The three typed CAS roots are
//! available both in the fully cold-validated table and every leaf recipe, so
//! the worker can independently derive and compare the namespace.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const recipe_mod =
    @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");

const namespace_domain =
    "stwo-zig/recursive-pipeline-campaign-namespace/v1\x00";

pub const Error = error{InvalidRecursivePipelineCampaignNamespaceV1};

pub fn fromValidatedTable(
    table: *const table_mod.CampaignTableV4,
) Error!artifact_store.Digest {
    table.validate() catch
        return error.InvalidRecursivePipelineCampaignNamespaceV1;
    return derive(
        table.globals.program,
        table.globals.raw_input,
        table.globals.expected_output,
    );
}

pub fn fromValidatedRecipe(
    recipe: *const recipe_mod.RecipeV4,
) Error!artifact_store.Digest {
    recipe.validate() catch
        return error.InvalidRecursivePipelineCampaignNamespaceV1;
    return derive(
        recipe.program,
        recipe.raw_input,
        recipe.expected_output,
    );
}

pub fn validate(
    namespace: artifact_store.Digest,
    program: artifact_store.BlobRefV1,
    raw_input: artifact_store.BlobRefV1,
    expected_output: artifact_store.BlobRefV1,
) Error!void {
    if (!std.mem.eql(
        u8,
        &namespace,
        &derive(program, raw_input, expected_output),
    )) return error.InvalidRecursivePipelineCampaignNamespaceV1;
}

fn derive(
    program: artifact_store.BlobRefV1,
    raw_input: artifact_store.BlobRefV1,
    expected_output: artifact_store.BlobRefV1,
) artifact_store.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(namespace_domain);
    hashBlob(&hash, program);
    hashBlob(&hash, raw_input);
    hashBlob(&hash, expected_output);
    return hash.finalResult();
}

fn hashBlob(
    hash: *std.crypto.hash.sha2.Sha256,
    value: artifact_store.BlobRefV1,
) void {
    hashInt(hash, u32, @intFromEnum(value.kind));
    hashInt(hash, u16, value.format_version);
    hashInt(hash, u16, value.schema_version);
    hashInt(hash, u64, value.byte_count);
    hash.update(&value.sha256);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
