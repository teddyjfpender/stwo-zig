//! Checked native base-component geometry shared by admission and its policy tests.
const std = @import("std");
const ethereum_statement = @import("../air/guest_precompile/ethereum_statement.zig");
const ethereum_assembly = @import("../prover/guest_precompile/ethereum_assembly.zig");
const EXTENSION_COMPONENT_COUNT = @import("ethereum_leaf_context.zig").EXTENSION_COMPONENT_COUNT;
const base_statement = @import("stwo_riscv_rv32").air.statement;

pub fn physicalBaseComponentCount(
    core: *const base_statement.RiscVStatement,
) !usize {
    const opcode = std.math.mul(
        usize,
        @intCast(core.n_components),
        2,
    ) catch return error.EthereumContextOverflow;
    return std.math.add(
        usize,
        opcode,
        @intCast(core.n_infra),
    ) catch error.EthereumContextOverflow;
}

pub fn canonicalPlacements(
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base_interaction_columns: usize,
) ![EXTENSION_COMPONENT_COUNT]ethereum_assembly.PlacementDescriptor {
    var result: [EXTENSION_COMPONENT_COUNT]ethereum_assembly.PlacementDescriptor = undefined;
    var pp: usize = core.nPreprocessedColumns();
    var main: usize = core.nMainColumns();
    var interaction = base_interaction_columns;
    for (&result, extension.components) |*placement, descriptor| {
        placement.* = .{
            .preprocessed_offset = pp,
            .main_offset = main,
            .interaction_offset = interaction,
        };
        pp = try add(pp, descriptor.preprocessed_columns);
        main = try add(main, descriptor.main_columns);
        interaction = try add(interaction, descriptor.interaction_columns);
    }
    return result;
}

pub fn add(left: usize, right: u32) !usize {
    return std.math.add(usize, left, right) catch
        error.EthereumContextOverflow;
}

pub fn castOffset(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.EthereumContextOverflow;
}
