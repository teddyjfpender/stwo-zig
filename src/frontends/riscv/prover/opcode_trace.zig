//! Parallel generation and ownership of committed opcode-family columns.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const infra = @import("../infra_trace.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const trace = @import("../runner/trace.zig");

const MAX_COMPONENTS = statement_mod.MAX_COMPONENTS;
const MAX_OPCODE_SHARD_ROWS: usize = 1 << 16;

/// Transitional host-derived columns removed by the exact lookup integration.
pub const LEGACY_BUS_COLUMNS: u32 = 5;

pub fn isCommittedFamilyColumn(_: trace.OpcodeFamily, _: usize) bool {
    return true;
}

pub fn nCommittedColumnsForFamily(family: trace.OpcodeFamily) u32 {
    var count: u32 = 0;
    for (0..trace.nColumnsForFamily(family)) |column| {
        if (isCommittedFamilyColumn(family, column)) count += 1;
    }
    return count;
}

pub fn generateIsFirst(allocator: std.mem.Allocator, log_size: u32) ![]M31 {
    const size = @as(usize, 1) << @intCast(log_size);
    const values = try allocator.alloc(M31, size);
    @memset(values, M31.zero());
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    values[placement.map(0)] = M31.one();
    return values;
}

pub fn generateIsActive(
    allocator: std.mem.Allocator,
    log_size: u32,
    n_rows: u32,
) ![]M31 {
    const size = @as(usize, 1) << @intCast(log_size);
    if (n_rows > size) return error.InvalidLogSize;
    const values = try allocator.alloc(M31, size);
    @memset(values, M31.zero());
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    for (0..n_rows) |row| values[placement.map(row)] = M31.one();
    return values;
}

pub const Columns = struct {
    components: [MAX_COMPONENTS]trace.TraceColumns,

    pub fn deinit(
        self: *Columns,
        allocator: std.mem.Allocator,
        statement: statement_mod.RiscVStatement,
    ) void {
        for (0..statement.n_components) |component_index| {
            const component = &self.components[component_index];
            for (component.columns[0..component.n_columns]) |*values| {
                if (values.len == 0) continue;
                allocator.free(values.*);
                values.* = &.{};
            }
        }
    }
};

/// Generates every active opcode shard in one pass over the execution trace.
pub fn generate(
    allocator: std.mem.Allocator,
    exec_trace: *const trace.Trace,
    statement: statement_mod.RiscVStatement,
) !Columns {
    // Run the filter once, up front, and carry its result.
    //
    // Both loops below classify every row, and both used to do it through a
    // total map over raw `Opcode` whose "the filter already ran" precondition
    // nothing checked. The worker body is a `void` function, so it had no way
    // to report an inadmissible opcode even if it noticed one. Classifying here
    // -- where an error can still be returned -- both discharges that and hands
    // the workers `ProofOpcode` values, which is the only argument type the
    // total map now accepts.
    const proof_opcodes = try exec_trace.proofOpcodes(allocator);
    defer allocator.free(proof_opcodes);

    var result: Columns = undefined;
    var log_sizes: [MAX_COMPONENTS]u32 = undefined;
    var domain_sizes: [MAX_COMPONENTS]usize = undefined;
    var n_cols: [MAX_COMPONENTS]usize = undefined;
    var row_counters: [trace.N_FAMILIES]usize = .{0} ** trace.N_FAMILIES;
    var first_component: [trace.N_FAMILIES]usize = undefined;
    var family_component_counts: [trace.N_FAMILIES]usize = .{0} ** trace.N_FAMILIES;

    var initialized_components: [MAX_COMPONENTS]usize = undefined;
    var n_initialized: usize = 0;
    var partial_component: usize = 0;
    var partial_cols: usize = 0;
    errdefer {
        for (initialized_components[0..n_initialized]) |component_index| {
            for (result.components[component_index].columns[0..n_cols[component_index]]) |values| {
                if (values.len != 0) allocator.free(values);
            }
        }
        for (result.components[partial_component].columns[0..partial_cols]) |values| {
            if (values.len != 0) allocator.free(values);
        }
    }

    for (0..statement.n_components) |component_index| {
        const desc = statement.component_descs[component_index];
        const family_index = @intFromEnum(desc.family);
        if (family_component_counts[family_index] == 0) {
            first_component[family_index] = component_index;
        }
        family_component_counts[family_index] += 1;
        log_sizes[component_index] = desc.log_size;
        domain_sizes[component_index] = @as(usize, 1) << @intCast(desc.log_size);
        n_cols[component_index] = trace.nColumnsForFamily(desc.family);

        partial_component = component_index;
        partial_cols = 0;
        for (0..n_cols[component_index]) |column| {
            if (!isCommittedFamilyColumn(desc.family, column)) {
                result.components[component_index].columns[column] = &.{};
                partial_cols = column + 1;
                continue;
            }
            const values = try allocator.alloc(M31, domain_sizes[component_index]);
            @memset(values, M31.zero());
            result.components[component_index].columns[column] = values;
            partial_cols = column + 1;
        }
        result.components[component_index].n_columns = n_cols[component_index];
        initialized_components[n_initialized] = component_index;
        n_initialized += 1;
        partial_cols = 0;
    }

    var placements: [MAX_COMPONENTS]?infra.BitReversalTable = .{null} ** MAX_COMPONENTS;
    errdefer deinitPlacements(allocator, &placements);
    for (0..statement.n_components) |component_index| {
        placements[component_index] = try infra.BitReversalTable.init(
            allocator,
            log_sizes[component_index],
        );
    }
    defer deinitPlacements(allocator, &placements);

    const FillWork = struct {
        rows: []const trace.TraceRow,
        proof_opcodes: []const trace.ProofOpcode,
        family_offsets: [trace.N_FAMILIES]usize,
        result: *Columns,
        placements: *const [MAX_COMPONENTS]?infra.BitReversalTable,
        domain_sizes: *const [MAX_COMPONENTS]usize,
        first_component: *const [trace.N_FAMILIES]usize,
        family_component_counts: *const [trace.N_FAMILIES]usize,

        fn run(work: *@This()) void {
            var offsets = work.family_offsets;
            for (work.rows, work.proof_opcodes) |row, proof_opcode| {
                const family = trace.opcodeFamily(proof_opcode);
                const family_index = @intFromEnum(family);
                const family_row = offsets[family_index];
                offsets[family_index] += 1;
                const shard_index = family_row / MAX_OPCODE_SHARD_ROWS;
                if (shard_index >= work.family_component_counts[family_index]) continue;
                const component_index = work.first_component[family_index] + shard_index;
                const row_index = family_row - shard_index * MAX_OPCODE_SHARD_ROWS;
                if (row_index >= work.domain_sizes[component_index]) continue;
                trace.fillFamilyColumns(
                    &work.result.components[component_index].columns,
                    work.placements[component_index].?.map(row_index),
                    row,
                    family,
                );
            }
        }
    };

    const active_pool = work_pool.getGlobalPool();
    const worker_count = if (active_pool) |pool|
        @max(@as(usize, 1), @min(pool.workerCount(), exec_trace.rows.items.len / 65_536))
    else
        1;
    var worker_family_counts: [work_pool.MAX_WORKERS][trace.N_FAMILIES]usize =
        .{.{0} ** trace.N_FAMILIES} ** work_pool.MAX_WORKERS;
    const chunk_len = (exec_trace.rows.items.len + worker_count - 1) / worker_count;
    for (0..worker_count) |worker| {
        const start = worker * chunk_len;
        const end = @min(exec_trace.rows.items.len, start + chunk_len);
        for (proof_opcodes[start..end]) |proof_opcode| {
            worker_family_counts[worker][@intFromEnum(trace.opcodeFamily(proof_opcode))] += 1;
        }
    }

    var works: [work_pool.MAX_WORKERS]FillWork = undefined;
    for (0..worker_count) |worker| {
        var offsets: [trace.N_FAMILIES]usize = undefined;
        for (0..trace.N_FAMILIES) |family_index| {
            offsets[family_index] = row_counters[family_index];
            row_counters[family_index] += worker_family_counts[worker][family_index];
        }
        const start = worker * chunk_len;
        const end = @min(exec_trace.rows.items.len, start + chunk_len);
        works[worker] = .{
            .rows = exec_trace.rows.items[start..end],
            .proof_opcodes = proof_opcodes[start..end],
            .family_offsets = offsets,
            .result = &result,
            .placements = &placements,
            .domain_sizes = &domain_sizes,
            .first_component = &first_component,
            .family_component_counts = &family_component_counts,
        };
    }
    if (worker_count > 1) {
        var wait_group: std.Thread.WaitGroup = .{};
        for (works[1..worker_count]) |*work| {
            active_pool.?.spawnWg(&wait_group, FillWork.run, .{work});
        }
        FillWork.run(&works[0]);
        wait_group.wait();
    } else {
        FillWork.run(&works[0]);
    }

    for (0..statement.n_components) |component_index| {
        const family_index = @intFromEnum(statement.component_descs[component_index].family);
        const shard_index = component_index - first_component[family_index];
        result.components[component_index].n_real_rows = @min(
            row_counters[family_index] -| shard_index * MAX_OPCODE_SHARD_ROWS,
            domain_sizes[component_index],
        );
    }
    try validateDirectSemantics(allocator, statement, &result);
    return result;
}

/// Fail before committing a family witness whose direct AIR constraints do
/// not vanish. This turns an opaque OODS mismatch into an exact family, row,
/// and constraint diagnostic without accepting anything the proof would not.
pub fn validateDirectSemantics(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: *const Columns,
) !void {
    for (0..statement.n_components) |component_index| {
        const desc = statement.component_descs[component_index];
        const component = &columns.components[component_index];
        const size = @as(usize, 1) << @intCast(desc.log_size);
        var placement = try infra.BitReversalTable.init(allocator, desc.log_size);
        defer placement.deinit(allocator);
        for (0..size) |logical_row| {
            const physical_row = placement.map(logical_row);
            var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
            for (
                sampled[0..component.n_columns],
                component.columns[0..component.n_columns],
            ) |*value, column| {
                value.* = QM31.fromBase(column[physical_row]);
            }
            const is_active = if (logical_row < component.n_real_rows)
                QM31.one()
            else
                QM31.zero();
            const evaluation = try semantic_eval.evaluate(
                desc.family,
                sampled[0..component.n_columns],
                is_active,
            );
            for (evaluation.values[0..evaluation.len], 0..) |value, constraint| {
                if (!value.isZero()) {
                    std.log.debug(
                        "invalid RISC-V semantic witness: family={s} shard={d} row={d} constraint={d}",
                        .{ @tagName(desc.family), component_index, logical_row, constraint },
                    );
                    return error.InvalidSemanticWitness;
                }
            }
        }
    }
}

fn deinitPlacements(
    allocator: std.mem.Allocator,
    placements: *[MAX_COMPONENTS]?infra.BitReversalTable,
) void {
    for (placements) |*placement| {
        if (placement.*) |table| table.deinit(allocator);
        placement.* = null;
    }
}
