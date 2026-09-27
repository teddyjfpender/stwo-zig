//! Deterministic zero-external SegmentV2 fixture for Ethereum context tests.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const base_statement = @import("../air/statement.zig");
const ethereum_statement = @import("../air/guest_precompile/ethereum_statement.zig");
const secp_bundle = @import("../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_component = @import("../air/guest_precompile/secp256k1_component.zig");
const secp_config = @import("../air/guest_precompile/secp256k1_component_config.zig");
const ethereum_types = @import("../prover/guest_precompile/ethereum_types.zig");

pub fn emptySecpShapes() ethereum_statement.SecpShapes {
    const empty = ethereum_statement.Shape{ .log_size = 1, .n_rows = 0 };
    return .{
        .product_base = empty,
        .product_scalar = empty,
        .linear_base = empty,
        .linear_scalar = empty,
        .point = empty,
        .split = empty,
        .scalar = empty,
        .table = empty,
        .recovery = empty,
        .byte = .{ .log_size = 8, .n_rows = 256 },
        .recovery_caller = empty,
    };
}

pub fn zeroExtensionClaim(
    statement: *const ethereum_statement.Statement,
) ethereum_types.ExtensionClaim {
    return .{
        .keccak_shard = .{
            .log_size = statement.components[0].log_size,
            .n_rows = statement.components[0].n_rows,
            .first_call_index = 0,
            .call_count = 0,
            .batch_sums = @splat(QM31.zero()),
            .component_sum = QM31.zero(),
        },
        .keccak_chi_table = QM31.zero(),
        .keccak_xor5_table = QM31.zero(),
        .product_base = zeroSecpClaim(
            secp_bundle.ProductBase,
            statement.components[3],
        ),
        .product_scalar = zeroSecpClaim(
            secp_bundle.ProductScalar,
            statement.components[4],
        ),
        .linear_base = zeroSecpClaim(
            secp_bundle.LinearBase,
            statement.components[5],
        ),
        .linear_scalar = zeroSecpClaim(
            secp_bundle.LinearScalar,
            statement.components[6],
        ),
        .point = zeroSecpClaim(
            secp_config.Point,
            statement.components[7],
        ),
        .split = zeroSecpClaim(
            secp_config.Split,
            statement.components[8],
        ),
        .scalar = zeroSecpClaim(
            secp_config.ScalarProgram,
            statement.components[9],
        ),
        .table = zeroSecpClaim(
            secp_config.Table,
            statement.components[10],
        ),
        .recovery = zeroSecpClaim(
            secp_config.Recovery,
            statement.components[11],
        ),
        .byte = zeroSecpClaim(
            secp_config.ByteTable,
            statement.components[12],
        ),
        .recovery_caller = zeroSecpClaim(
            secp_config.RecoveryCaller,
            statement.components[13],
        ),
    };
}

fn zeroSecpClaim(
    comptime Config: type,
    descriptor: ethereum_statement.Descriptor,
) secp_component.Claim(Config) {
    return .{
        .log_size = descriptor.log_size,
        .n_rows = descriptor.n_rows,
        .batch_sums = @splat(QM31.zero()),
        .component_sum = QM31.zero(),
    };
}

pub fn retainedSegmentZeroCore() base_statement.RiscVStatement {
    const component_order = @import("../air/component_order.zig");
    const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
    const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
    const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
    const program_commitment = @import("../air/program/commitment.zig");
    const infra = @import("../infra_trace.zig");
    const trace = @import("../runner/trace.zig");
    var core: base_statement.RiscVStatement = undefined;
    core.n_components = 0;
    core.component_descs = undefined;
    core.initial_pc = 0;
    core.final_pc = 0;
    core.total_steps = 0;
    core.public_data = undefined;
    for (component_order.opcodeFamilies()) |family| {
        const rows = retainedSegmentZeroRows(family);
        if (rows == 0) continue;
        core.component_descs[core.n_components] = .{
            .family = family,
            .log_size = @max(@as(u32, 4), std.math.log2_int_ceil(u32, rows)),
            .n_rows = rows,
            .n_columns = trace.nColumnsForFamily(family),
        };
        core.n_components += 1;
    }
    core.n_infra = 4;
    core.infra_descs = undefined;
    core.infra_descs[0] = infraDescriptor(
        .program,
        program_commitment.N_MAIN_COLUMNS,
        4,
        0,
    );
    core.infra_descs[1] = infraDescriptor(
        .merkle,
        merkle_node.N_MAIN_COLUMNS,
        4,
        0,
    );
    core.infra_descs[2] = infraDescriptor(
        .poseidon2,
        poseidon2_air.N_MAIN_COLUMNS,
        4,
        0,
    );
    core.infra_descs[3] = infraDescriptor(
        .clock_update,
        infra.CLOCK_UPDATE_COLS,
        4,
        0,
    );
    for (component_order.lookupTables()) |kind| {
        core.infra_descs[core.n_infra] = infraDescriptor(
            base_statement.infraKindForTable(kind),
            1,
            lookup_table_schema.logSize(kind),
            @intCast(lookup_table_schema.size(kind)),
        );
        core.n_infra += 1;
    }
    return core;
}

fn infraDescriptor(
    kind: base_statement.InfraKind,
    n_columns: usize,
    log_size: u32,
    n_rows: u32,
) base_statement.InfraComponentDesc {
    return .{
        .kind = kind,
        .log_size = log_size,
        .n_rows = n_rows,
        .n_columns = @intCast(n_columns),
    };
}

fn retainedSegmentZeroRows(
    family: @import("../runner/trace.zig").OpcodeFamily,
) u32 {
    return switch (family) {
        .auipc => 9,
        .base_alu_imm => 205,
        .base_alu_reg => 55,
        .branch_eq => 29,
        .branch_lt => 100,
        .jal => 4,
        .jalr => 11,
        .load_store => 204,
        .lui => 8,
        .mul => 2,
        else => 0,
    };
}
