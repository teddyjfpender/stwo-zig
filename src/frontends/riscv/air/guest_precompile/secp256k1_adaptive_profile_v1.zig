//! Non-production adaptive secp256k1 verifier-program profile.
//!
//! The compact Ethereum profile commits eleven secp256k1 components even when
//! the public signer-recovery count is zero.  This compiler admits an omitted
//! family only when the complete retirement arithmetic and the legacy empty
//! geometry both say zero.  Active shards retain the existing compact family.
//! No existing statement, component, or proof identity is relabelled.

const std = @import("std");
const bundle = @import("secp256k1_component_bundle.zig");
const config = @import("secp256k1_component_config.zig");
const statement = @import("ethereum_statement.zig");
const trace = @import("secp256k1_component_trace.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const component_count: u32 = 11;
pub const Digest = [32]u8;

pub const Mode = enum(u8) {
    inactive_zero_count = 0,
    compact_v1 = 1,
};

pub const RetirementAuthority = struct {
    base_steps: u32,
    keccak_calls: u32,
    signer_calls: u32,
    total_steps: u32,

    pub fn validate(self: RetirementAuthority) Error!void {
        const external = std.math.add(
            u32,
            self.keccak_calls,
            self.signer_calls,
        ) catch return error.ArithmeticOverflow;
        const expected = std.math.add(u32, self.base_steps, external) catch
            return error.ArithmeticOverflow;
        if (self.total_steps != expected) return error.RetirementCountMismatch;
    }
};

pub const Costs = struct {
    preprocessed_cells: u64,
    main_cells: u64,
    interaction_cells: u64,
    total_cells: u64,

    fn zero() Costs {
        return .{
            .preprocessed_cells = 0,
            .main_cells = 0,
            .interaction_cells = 0,
            .total_cells = 0,
        };
    }

    fn add(self: Costs, other: Costs) Error!Costs {
        const preprocessed = try checkedAdd(
            self.preprocessed_cells,
            other.preprocessed_cells,
        );
        const main = try checkedAdd(self.main_cells, other.main_cells);
        const interaction = try checkedAdd(
            self.interaction_cells,
            other.interaction_cells,
        );
        return .{
            .preprocessed_cells = preprocessed,
            .main_cells = main,
            .interaction_cells = interaction,
            .total_cells = try checkedAdd(
                try checkedAdd(preprocessed, main),
                interaction,
            ),
        };
    }
};

pub const Plan = struct {
    version: u16,
    mode: Mode,
    retirement: RetirementAuthority,
    shapes: statement.SecpShapes,
    selected_component_count: u32,
    legacy_costs: Costs,
    selected_costs: Costs,
    verifier_program_identity: Digest,
    instance_identity: Digest,

    pub fn validate(self: Plan) Error!void {
        const expected = try compile(self.retirement, self.shapes);
        if (!std.meta.eql(self, expected)) return error.PlanMismatch;
    }
};

pub const Error = error{
    ArithmeticOverflow,
    CallCountMismatch,
    InvalidComponentGeometry,
    PlanMismatch,
    RetirementCountMismatch,
};

pub fn compile(
    retirement: RetirementAuthority,
    shapes: statement.SecpShapes,
) Error!Plan {
    try retirement.validate();
    try validateShapes(retirement.signer_calls, shapes);
    const legacy = try compactCosts(shapes);
    var result = Plan{
        .version = schema_version,
        .mode = if (retirement.signer_calls == 0)
            .inactive_zero_count
        else
            .compact_v1,
        .retirement = retirement,
        .shapes = shapes,
        .selected_component_count = if (retirement.signer_calls == 0)
            0
        else
            component_count,
        .legacy_costs = legacy,
        .selected_costs = if (retirement.signer_calls == 0)
            Costs.zero()
        else
            legacy,
        .verifier_program_identity = undefined,
        .instance_identity = undefined,
    };
    result.verifier_program_identity = programIdentity(result);
    result.instance_identity = instanceIdentity(result);
    return result;
}

pub fn omittedCells(plan: Plan) Error!u64 {
    try plan.validate();
    if (plan.selected_costs.total_cells > plan.legacy_costs.total_cells)
        return error.PlanMismatch;
    return plan.legacy_costs.total_cells - plan.selected_costs.total_cells;
}

pub fn projectedOmittedCells(plan: Plan, leaf_count: u32) Error!u64 {
    return checkedMul(try omittedCells(plan), leaf_count);
}

fn validateShapes(signer_calls: u32, shapes: statement.SecpShapes) Error!void {
    const ordered = orderedShapes(shapes);
    for (ordered) |shape| try validateShape(shape);
    if (shapes.recovery.n_rows != signer_calls or
        shapes.recovery_caller.n_rows != signer_calls or
        shapes.byte.log_size != 8 or shapes.byte.n_rows != 256)
    {
        return error.CallCountMismatch;
    }
    if (signer_calls == 0) {
        for (ordered[0..9]) |shape| {
            if (shape.log_size != 1 or shape.n_rows != 0)
                return error.InvalidComponentGeometry;
        }
        if (ordered[10].log_size != 1 or ordered[10].n_rows != 0)
            return error.InvalidComponentGeometry;
    } else {
        for (ordered[0..9]) |shape| {
            if (shape.n_rows == 0) return error.InvalidComponentGeometry;
        }
    }
}

fn validateShape(shape: statement.Shape) Error!void {
    if (shape.log_size == 0 or shape.log_size >= 31 or
        @as(u64, shape.n_rows) > (@as(u64, 1) << @intCast(shape.log_size)))
    {
        return error.InvalidComponentGeometry;
    }
}

fn compactCosts(shapes: statement.SecpShapes) Error!Costs {
    var result = Costs.zero();
    result = try result.add(try componentCosts(bundle.ProductBase, shapes.product_base));
    result = try result.add(try componentCosts(bundle.ProductScalar, shapes.product_scalar));
    result = try result.add(try componentCosts(bundle.LinearBase, shapes.linear_base));
    result = try result.add(try componentCosts(bundle.LinearScalar, shapes.linear_scalar));
    result = try result.add(try componentCosts(config.Point, shapes.point));
    result = try result.add(try componentCosts(config.Split, shapes.split));
    result = try result.add(try componentCosts(config.ScalarProgram, shapes.scalar));
    result = try result.add(try componentCosts(config.Table, shapes.table));
    result = try result.add(try componentCosts(config.Recovery, shapes.recovery));
    result = try result.add(try componentCosts(config.ByteTable, shapes.byte));
    result = try result.add(try componentCosts(
        config.RecoveryCaller,
        shapes.recovery_caller,
    ));
    return result;
}

fn componentCosts(comptime Config: type, shape: statement.Shape) Error!Costs {
    const domain = @as(u64, 1) << @intCast(shape.log_size);
    const preprocessed = try checkedMul(trace.preprocessed_column_count, domain);
    const main = try checkedMul(Config.main_column_count, domain);
    const interaction = try checkedMul(4 * Config.batch_count, domain);
    return .{
        .preprocessed_cells = preprocessed,
        .main_cells = main,
        .interaction_cells = interaction,
        .total_cells = try checkedAdd(
            try checkedAdd(preprocessed, main),
            interaction,
        ),
    };
}

fn orderedShapes(shapes: statement.SecpShapes) [component_count]statement.Shape {
    return .{
        shapes.product_base,
        shapes.product_scalar,
        shapes.linear_base,
        shapes.linear_scalar,
        shapes.point,
        shapes.split,
        shapes.scalar,
        shapes.table,
        shapes.recovery,
        shapes.byte,
        shapes.recovery_caller,
    };
}

fn programIdentity(plan: Plan) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.secp256k1.adaptive-verifier-program.v1\x00");
    hashInt(&hash, schema_version);
    hashInt(&hash, @intFromEnum(plan.mode));
    hashInt(&hash, plan.selected_component_count);
    if (plan.mode == .compact_v1) {
        hashConfig(&hash, 0, bundle.ProductBase, plan.shapes.product_base.log_size);
        hashConfig(&hash, 1, bundle.ProductScalar, plan.shapes.product_scalar.log_size);
        hashConfig(&hash, 2, bundle.LinearBase, plan.shapes.linear_base.log_size);
        hashConfig(&hash, 3, bundle.LinearScalar, plan.shapes.linear_scalar.log_size);
        hashConfig(&hash, 4, config.Point, plan.shapes.point.log_size);
        hashConfig(&hash, 5, config.Split, plan.shapes.split.log_size);
        hashConfig(&hash, 6, config.ScalarProgram, plan.shapes.scalar.log_size);
        hashConfig(&hash, 7, config.Table, plan.shapes.table.log_size);
        hashConfig(&hash, 8, config.Recovery, plan.shapes.recovery.log_size);
        hashConfig(&hash, 9, config.ByteTable, plan.shapes.byte.log_size);
        hashConfig(&hash, 10, config.RecoveryCaller, plan.shapes.recovery_caller.log_size);
    }
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn instanceIdentity(plan: Plan) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.secp256k1.adaptive-instance.v1\x00");
    hash.update(&plan.verifier_program_identity);
    hashInt(&hash, plan.retirement.base_steps);
    hashInt(&hash, plan.retirement.keccak_calls);
    hashInt(&hash, plan.retirement.signer_calls);
    hashInt(&hash, plan.retirement.total_steps);
    for (orderedShapes(plan.shapes)) |shape| {
        hashInt(&hash, shape.log_size);
        hashInt(&hash, shape.n_rows);
    }
    hashInt(&hash, plan.legacy_costs.total_cells);
    hashInt(&hash, plan.selected_costs.total_cells);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashConfig(
    hash: anytype,
    ordinal: u8,
    comptime Config: type,
    log_size: u32,
) void {
    hashInt(hash, ordinal);
    hashInt(hash, trace.preprocessed_column_count);
    hashInt(hash, Config.main_column_count);
    hashInt(hash, 4 * Config.batch_count);
    hashInt(hash, Config.maximum_constraint_degree);
    hashInt(hash, log_size);
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn checkedAdd(left: anytype, right: anytype) Error!u64 {
    return std.math.add(u64, @intCast(left), @intCast(right)) catch
        error.ArithmeticOverflow;
}

fn checkedMul(left: anytype, right: anytype) Error!u64 {
    return std.math.mul(u64, @intCast(left), @intCast(right)) catch
        error.ArithmeticOverflow;
}

comptime {
    if (component_count != 11 or production_active)
        @compileError("adaptive secp256k1 profile drifted");
}
