//! Identity-bearing contract for the first generic Native AIR program shape.
//!
//! This describes data already materialized by a frontend. It does not grant
//! the backend permission to regenerate a trace or reinterpret public inputs.

const std = @import("std");

pub const Digest = [32]u8;

pub const TraceGeometry = struct {
    component: u32,
    component_count: u32 = 1,
    log_rows: u32,
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,
    /// Exact logical cell count for mixed-height component trees. Uniform
    /// frontends leave this null and retain the original calculation.
    mixed_height_element_count: u64 = 0,

    pub fn columnCount(self: TraceGeometry) Error!u64 {
        const preprocessed_and_main = std.math.add(
            u64,
            self.preprocessed_columns,
            self.main_columns,
        ) catch return error.GeometryOverflow;
        return std.math.add(
            u64,
            preprocessed_and_main,
            self.interaction_columns,
        ) catch return error.GeometryOverflow;
    }

    pub fn elementCount(self: TraceGeometry) Error!u64 {
        if (self.mixed_height_element_count != 0)
            return self.mixed_height_element_count;
        if (self.log_rows >= 63) return error.InvalidGeometry;
        return std.math.mul(
            u64,
            try self.columnCount(),
            @as(u64, 1) << @intCast(self.log_rows),
        ) catch return error.GeometryOverflow;
    }
};

pub const MaterializedHostTrace = struct {
    /// Identifies the frontend algorithm that produced the materialized trace.
    recipe_identity: Digest,
    /// Identifies element encoding, column order, and host-memory ownership.
    layout_abi_identity: Digest,
    element_count: u64,
};

pub const StatementBinding = struct {
    /// Identifies the exact statement-to-transcript serialization recipe.
    transcript_recipe_identity: Digest,
    /// Identifies the public-input field order and scalar encoding.
    public_input_abi_identity: Digest,
    public_input_words: u32,
};

pub const SampleMaskRecipe = struct {
    /// Identifies OODS derivation and per-tree sampling order.
    recipe_identity: Digest,
    /// Identifies the ordered mask offsets for every declared trace column.
    mask_layout_identity: Digest,
    mask_point_count: u32,
};

pub const ConstraintParameterAbi = struct {
    /// Identifies the executable kernel argument order and scalar encoding.
    identity: Digest,
    statement_words: u32,
    challenge_words: u32,
    parameter_words: u32,
};

pub const Contract = struct {
    pub const current_version: u32 = 1;

    version: u32 = current_version,
    geometry: TraceGeometry,
    ingress: MaterializedHostTrace,
    statement: StatementBinding,
    sampling: SampleMaskRecipe,
    constraint_parameters: ConstraintParameterAbi,

    pub fn validate(self: Contract) Error!void {
        if (self.version != current_version) return error.UnsupportedVersion;
        if (self.geometry.log_rows == 0 or
            self.geometry.component_count == 0 or
            try self.geometry.columnCount() == 0)
        {
            return error.InvalidGeometry;
        }
        if (self.ingress.element_count != try self.geometry.elementCount())
            return error.InvalidIngress;
        if (self.sampling.mask_point_count == 0)
            return error.InvalidSampling;
        inline for (.{
            self.ingress.recipe_identity,
            self.ingress.layout_abi_identity,
            self.statement.transcript_recipe_identity,
            self.statement.public_input_abi_identity,
            self.sampling.recipe_identity,
            self.sampling.mask_layout_identity,
            self.constraint_parameters.identity,
        }) |digest| {
            if (std.mem.allEqual(u8, &digest, 0))
                return error.EmptyIdentity;
        }
    }
};

pub const Error = error{
    EmptyIdentity,
    GeometryOverflow,
    InvalidGeometry,
    InvalidIngress,
    InvalidSampling,
    UnsupportedVersion,
};

fn identity(value: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    return digest;
}

fn fixture() Contract {
    return .{
        .geometry = .{
            .component = 7,
            .log_rows = 8,
            .preprocessed_columns = 0,
            .main_columns = 2,
            .interaction_columns = 1,
        },
        .ingress = .{
            .recipe_identity = identity("trace"),
            .layout_abi_identity = identity("layout"),
            .element_count = 3 * 256,
        },
        .statement = .{
            .transcript_recipe_identity = identity("statement"),
            .public_input_abi_identity = identity("public-input"),
            .public_input_words = 0,
        },
        .sampling = .{
            .recipe_identity = identity("sample"),
            .mask_layout_identity = identity("mask"),
            .mask_point_count = 3,
        },
        .constraint_parameters = .{
            .identity = identity("constraint-abi"),
            .statement_words = 0,
            .challenge_words = 0,
            .parameter_words = 0,
        },
    };
}

test "native AIR contract accepts zero-width trees" {
    try fixture().validate();
}

test "native AIR contract rejects unbound and inconsistent ingress" {
    var contract = fixture();
    contract.ingress.element_count -= 1;
    try std.testing.expectError(error.InvalidIngress, contract.validate());

    contract = fixture();
    contract.sampling.mask_layout_identity = [_]u8{0} ** 32;
    try std.testing.expectError(error.EmptyIdentity, contract.validate());

    contract = fixture();
    contract.geometry.main_columns = 0;
    contract.geometry.interaction_columns = 0;
    try std.testing.expectError(error.InvalidGeometry, contract.validate());
}
