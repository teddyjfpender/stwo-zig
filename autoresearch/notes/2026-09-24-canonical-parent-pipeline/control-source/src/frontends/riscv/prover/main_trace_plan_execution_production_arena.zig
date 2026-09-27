//! Exact-capacity ownership for production Tree-1 destinations.
//!
//! The coordinator selects one explicit destination policy before any worker
//! starts. CPU and other non-adopting backends receive independently owned
//! final columns, so the ordinary commitment path consumes them without a
//! whole-trace detach copy. Backends that explicitly adopt a source arena
//! receive one aligned, log-size-grouped allocation and its backing descriptor.
//! A separate exact allocation retains the opcode and clock columns required by
//! Tree 2. Workers receive only borrowed, disjoint slices; publication remains
//! impossible until the one-byte-per-column ownership ledger is complete.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const statement_mod = @import("../air/statement.zig");
const plan_mod = @import("main_trace_plan.zig");

/// Metal's no-copy source binding requires 16 KiB alignment. A grouped arena is
/// allocated with this alignment directly; its eligibility never depends on a
/// lucky address returned by a naturally aligned allocation.
pub const GROUPED_ARENA_ALIGNMENT: std.mem.Alignment =
    std.mem.Alignment.fromByteUnits(16 * 1024);

pub const DestinationPolicy = enum {
    /// Every final column is one ordinary allocator-owned slice. This is the
    /// correct policy for CPU/non-adopting engines: `Engine.commit` can consume
    /// the columns directly and performs no backing-arena detach copy.
    independent_columns,
    /// Equal-log-size columns borrow one aligned allocation. This policy is
    /// valid only for engines whose backend explicitly adopts source arenas.
    grouped_backing,

    pub fn forBackend(comptime Backend: type) DestinationPolicy {
        const adopts = @hasDecl(Backend, "adopts_source_trace_arena") and
            Backend.adopts_source_trace_arena;
        if (!adopts) return .independent_columns;
        if (!@hasDecl(Backend, "resident_column_arena_alignment")) {
            @compileError(
                "a source-arena-adopting backend must declare " ++
                    "resident_column_arena_alignment",
            );
        }
        const required: std.mem.Alignment = Backend.resident_column_arena_alignment;
        if (comptime required.toByteUnits() > GROUPED_ARENA_ALIGNMENT.toByteUnits()) {
            @compileError(
                "the production Tree-1 grouped arena alignment is smaller " ++
                    "than the adopting backend requirement",
            );
        }
        return .grouped_backing;
    }

    pub fn forEngine(comptime Engine: type) DestinationPolicy {
        if (!@hasDecl(Engine, "Backend")) return .independent_columns;
        return forBackend(Engine.Backend);
    }

    pub fn hasSharedBacking(self: DestinationPolicy) bool {
        return self == .grouped_backing;
    }
};

/// One strongly aligned allocation plus the natural-alignment descriptor shape
/// accepted by `Engine.commitWithBacking`. Keeping the two together makes
/// optional backing one ownership state rather than two nullable fields whose
/// agreement callers would have to maintain.
pub const SharedBacking = struct {
    payload: []align(GROUPED_ALIGNMENT_BYTES) M31,
    buffers: [][]M31,

    fn deinit(self: *SharedBacking, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        allocator.free(self.buffers);
        self.* = undefined;
    }
};

pub const Artifacts = struct {
    allocator: std.mem.Allocator,
    destination_policy: DestinationPolicy,
    columns: []ColumnEvaluation,
    backing: ?SharedBacking,
    retained_payload: []M31,
    ownership: []std.atomic.Value(u8),

    /// Compatibility entrypoint for the already-prepared production kernel.
    /// Live orchestration must call `initWithPolicy` with
    /// `DestinationPolicy.forEngine(Engine)` before enabling the CPU path.
    pub fn init(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        plan: *const plan_mod.Plan,
    ) !*Artifacts {
        return initWithPolicy(
            allocator,
            statement,
            plan,
            .grouped_backing,
        );
    }

    pub fn initWithPolicy(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        plan: *const plan_mod.Plan,
        policy: DestinationPolicy,
    ) !*Artifacts {
        if (statement.nMainColumns() != plan.total_columns) {
            return error.InvalidProductionDestinationShape;
        }
        const main_cells = try cellsFromBytes(
            plan.resources.main_output_payload_bytes,
        );
        if (try countMainCells(statement) != main_cells) {
            return error.InvalidProductionDestinationShape;
        }
        const retained_bytes = std.math.add(
            usize,
            plan.resources.retained_opcode_payload_bytes,
            plan.resources.retained_clock_payload_bytes,
        ) catch return error.Tree1ResourceOverflow;
        const retained_cells = try cellsFromBytes(retained_bytes);

        const self = try allocator.create(Artifacts);
        errdefer allocator.destroy(self);
        var destinations = try Destinations.init(
            allocator,
            statement,
            plan.total_columns,
            main_cells,
            policy,
        );
        errdefer destinations.deinit(allocator);
        const retained_payload = try allocator.alloc(M31, retained_cells);
        errdefer allocator.free(retained_payload);
        const ownership = try allocator.alloc(
            std.atomic.Value(u8),
            plan.total_columns,
        );
        errdefer allocator.free(ownership);

        @memset(retained_payload, M31.zero());
        for (ownership) |*slot| slot.* = .init(0);
        self.* = .{
            .allocator = allocator,
            .destination_policy = policy,
            .columns = destinations.columns,
            .backing = destinations.backing,
            .retained_payload = retained_payload,
            .ownership = ownership,
        };
        destinations.disarm();
        return self;
    }

    pub fn deinit(self: *Artifacts) void {
        const allocator = self.allocator;
        if (self.ownership.len != 0) allocator.free(self.ownership);
        allocator.free(self.retained_payload);
        releaseDestinations(
            allocator,
            self.columns,
            self.backing,
        );
        allocator.destroy(self);
    }

    /// Transfers final Tree-1 storage exactly once. The retained Tree-2 payload
    /// stays here. No allocation or copy occurs for either destination policy.
    pub fn takeCommitment(self: *Artifacts) !Commitment {
        if (self.columns.len == 0) {
            return error.Tree1ProductionOutputAlreadyTransferred;
        }
        if (!self.allComplete()) return error.IncompleteProductionOwner;
        try validateDestinationShape(
            self.destination_policy,
            self.columns,
            self.backing,
        );
        const result = Commitment{
            .destination_policy = self.destination_policy,
            .columns = self.columns,
            .backing = self.backing,
        };
        self.columns = &.{};
        self.backing = null;
        self.allocator.free(self.ownership);
        self.ownership = &.{};
        return result;
    }

    pub fn mutableColumn(self: *Artifacts, index: usize) ![]M31 {
        if (index >= self.columns.len) {
            return error.InvalidProductionDestinationShape;
        }
        return @constCast(self.columns[index].values);
    }

    /// Claims a complete descriptor range exactly once. The preflight makes a
    /// duplicate fail without partially changing the ledger.
    pub fn completeRange(
        self: *Artifacts,
        range: plan_mod.ColumnRange,
    ) !void {
        const start: usize = @intCast(range.start);
        const len: usize = @intCast(range.len);
        if (start > self.ownership.len or len > self.ownership.len - start) {
            return error.InvalidProductionDestinationShape;
        }
        for (self.ownership[start .. start + len]) |*slot| {
            if (slot.load(.acquire) != 0) {
                return error.DuplicateProductionDestinationOwner;
            }
        }
        for (self.ownership[start .. start + len]) |*slot| {
            slot.store(1, .release);
        }
    }

    pub fn rangeComplete(
        self: *const Artifacts,
        range: plan_mod.ColumnRange,
    ) bool {
        const start: usize = @intCast(range.start);
        const len: usize = @intCast(range.len);
        if (start > self.ownership.len or len > self.ownership.len - start) {
            return false;
        }
        for (self.ownership[start .. start + len]) |*slot| {
            if (slot.load(.acquire) != 1) return false;
        }
        return true;
    }

    pub fn allComplete(self: *const Artifacts) bool {
        if (self.ownership.len == 0) return false;
        for (self.ownership) |*slot| {
            if (slot.load(.acquire) != 1) return false;
        }
        return true;
    }
};

/// Exact ownership shape consumed by a commitment engine. `backing` is present
/// only when all column views borrow its grouped payload; otherwise each column
/// owns its allocation and must be passed to ordinary `Engine.commit`.
pub const Commitment = struct {
    destination_policy: DestinationPolicy,
    columns: []ColumnEvaluation,
    backing: ?SharedBacking,

    pub fn hasSharedBacking(self: *const Commitment) bool {
        return self.destination_policy.hasSharedBacking();
    }

    pub fn backingBuffers(self: *const Commitment) ?[][]M31 {
        return if (self.backing) |owned| owned.buffers else null;
    }

    /// Defensive assertion at the integration boundary. It prevents an
    /// independent CPU column set from being mislabeled as adoptable backing,
    /// and prevents a grouped owner from reaching a per-column free path.
    pub fn validatePolicy(self: *const Commitment) !void {
        try validateDestinationShape(
            self.destination_policy,
            self.columns,
            self.backing,
        );
    }

    pub fn deinit(self: *Commitment, allocator: std.mem.Allocator) void {
        releaseDestinations(
            allocator,
            self.columns,
            self.backing,
        );
        self.* = undefined;
    }
};

const GROUPED_ALIGNMENT_BYTES = GROUPED_ARENA_ALIGNMENT.toByteUnits();

const Destinations = struct {
    columns: []ColumnEvaluation,
    backing: ?SharedBacking = null,

    fn init(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        column_count: usize,
        main_cells: usize,
        policy: DestinationPolicy,
    ) !Destinations {
        return switch (policy) {
            .independent_columns => initIndependent(
                allocator,
                statement,
                column_count,
            ),
            .grouped_backing => initGrouped(
                allocator,
                statement,
                column_count,
                main_cells,
            ),
        };
    }

    fn initIndependent(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        column_count: usize,
    ) !Destinations {
        const columns = try allocator.alloc(ColumnEvaluation, column_count);
        var initialized: usize = 0;
        errdefer {
            for (columns[0..initialized]) |column| {
                allocator.free(@constCast(column.values));
            }
            allocator.free(columns);
        }
        for (statement.component_descs[0..statement.n_components]) |desc| {
            try allocateDescriptor(
                allocator,
                columns,
                &initialized,
                desc.log_size,
                desc.n_columns,
            );
        }
        for (statement.infra_descs[0..statement.n_infra]) |desc| {
            try allocateDescriptor(
                allocator,
                columns,
                &initialized,
                desc.log_size,
                desc.n_columns,
            );
        }
        if (initialized != columns.len) {
            return error.InvalidProductionDestinationShape;
        }
        return .{ .columns = columns };
    }

    fn initGrouped(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        column_count: usize,
        main_cells: usize,
    ) !Destinations {
        const columns = try allocator.alloc(ColumnEvaluation, column_count);
        errdefer allocator.free(columns);
        const grouped_payload = try allocator.alignedAlloc(
            M31,
            GROUPED_ARENA_ALIGNMENT,
            main_cells,
        );
        errdefer allocator.free(grouped_payload);
        const backing_buffers = try allocator.alloc([]M31, 1);
        errdefer allocator.free(backing_buffers);
        backing_buffers[0] = grouped_payload;

        @memset(grouped_payload, M31.zero());
        try bindColumns(columns, grouped_payload, statement);
        return .{
            .columns = columns,
            .backing = .{
                .payload = grouped_payload,
                .buffers = backing_buffers,
            },
        };
    }

    fn deinit(self: *Destinations, allocator: std.mem.Allocator) void {
        releaseDestinations(
            allocator,
            self.columns,
            self.backing,
        );
        self.* = undefined;
    }

    fn disarm(self: *Destinations) void {
        self.columns = &.{};
        self.backing = null;
    }
};

fn allocateDescriptor(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    initialized: *usize,
    log_size: u32,
    n_columns: u32,
) !void {
    if (log_size >= @bitSizeOf(usize)) {
        return error.InvalidProductionDestinationShape;
    }
    const domain = @as(usize, 1) << @intCast(log_size);
    for (0..n_columns) |_| {
        if (initialized.* >= columns.len) {
            return error.InvalidProductionDestinationShape;
        }
        const values = try allocator.alloc(M31, domain);
        @memset(values, M31.zero());
        columns[initialized.*] = .{ .log_size = log_size, .values = values };
        initialized.* += 1;
    }
}

fn releaseDestinations(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    maybe_backing: ?SharedBacking,
) void {
    if (columns.len == 0) return;
    if (maybe_backing) |owned| {
        var backing = owned;
        backing.deinit(allocator);
    } else {
        for (columns) |column| allocator.free(@constCast(column.values));
    }
    allocator.free(columns);
}

fn validateDestinationShape(
    policy: DestinationPolicy,
    columns: []const ColumnEvaluation,
    maybe_backing: ?SharedBacking,
) !void {
    if (columns.len == 0) return error.InvalidProductionDestinationShape;
    switch (policy) {
        .independent_columns => {
            if (maybe_backing != null) {
                return error.InvalidProductionDestinationPolicy;
            }
            for (columns) |column| {
                if (column.values.len == 0) {
                    return error.InvalidProductionDestinationShape;
                }
            }
        },
        .grouped_backing => {
            const backing = maybe_backing orelse
                return error.InvalidProductionDestinationPolicy;
            const payload = backing.payload;
            const buffers = backing.buffers;
            if (buffers.len != 1 or
                buffers[0].ptr != payload.ptr or
                buffers[0].len != payload.len or
                @intFromPtr(payload.ptr) % GROUPED_ALIGNMENT_BYTES != 0)
            {
                return error.InvalidProductionDestinationPolicy;
            }
            const payload_start = @intFromPtr(payload.ptr);
            const payload_end = @intFromPtr(payload.ptr + payload.len);
            for (columns) |column| {
                const start = @intFromPtr(column.values.ptr);
                const end = @intFromPtr(column.values.ptr + column.values.len);
                if (column.values.len == 0 or
                    start < payload_start or
                    end > payload_end)
                {
                    return error.InvalidProductionDestinationShape;
                }
            }
        },
    }
}

fn countMainCells(statement: *const statement_mod.RiscVStatement) !usize {
    var total: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |desc| {
        total = try addDescriptorCells(total, desc.log_size, desc.n_columns);
    }
    for (statement.infra_descs[0..statement.n_infra]) |desc| {
        total = try addDescriptorCells(total, desc.log_size, desc.n_columns);
    }
    return total;
}

fn addDescriptorCells(total: usize, log_size: u32, n_columns: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) {
        return error.InvalidProductionDestinationShape;
    }
    const domain = @as(usize, 1) << @intCast(log_size);
    const cells = std.math.mul(
        usize,
        domain,
        n_columns,
    ) catch return error.Tree1ResourceOverflow;
    return std.math.add(usize, total, cells) catch
        return error.Tree1ResourceOverflow;
}

fn bindColumns(
    columns: []ColumnEvaluation,
    payload: []M31,
    statement: *const statement_mod.RiscVStatement,
) !void {
    var seen = [_]bool{false} ** @bitSizeOf(usize);
    var group_order: [@bitSizeOf(usize)]u32 = undefined;
    var group_cells = [_]usize{0} ** @bitSizeOf(usize);
    var group_count: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |desc| {
        try countDescriptor(
            &seen,
            &group_order,
            &group_cells,
            &group_count,
            desc.log_size,
            desc.n_columns,
        );
    }
    for (statement.infra_descs[0..statement.n_infra]) |desc| {
        try countDescriptor(
            &seen,
            &group_order,
            &group_cells,
            &group_count,
            desc.log_size,
            desc.n_columns,
        );
    }

    var group_starts = [_]usize{0} ** @bitSizeOf(usize);
    var group_cursors = [_]usize{0} ** @bitSizeOf(usize);
    var total_cells: usize = 0;
    for (group_order[0..group_count]) |log_size| {
        group_starts[log_size] = total_cells;
        group_cursors[log_size] = total_cells;
        total_cells = std.math.add(
            usize,
            total_cells,
            group_cells[log_size],
        ) catch return error.Tree1ResourceOverflow;
    }
    if (total_cells != payload.len) {
        return error.InvalidProductionDestinationShape;
    }

    var column_index: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |desc| {
        try appendDescriptor(
            columns,
            payload,
            &column_index,
            &group_cursors,
            desc.log_size,
            desc.n_columns,
        );
    }
    for (statement.infra_descs[0..statement.n_infra]) |desc| {
        try appendDescriptor(
            columns,
            payload,
            &column_index,
            &group_cursors,
            desc.log_size,
            desc.n_columns,
        );
    }
    if (column_index != columns.len) {
        return error.InvalidProductionDestinationShape;
    }
    for (group_order[0..group_count]) |log_size| {
        if (group_cursors[log_size] !=
            group_starts[log_size] + group_cells[log_size])
        {
            return error.InvalidProductionDestinationShape;
        }
    }
}

fn countDescriptor(
    seen: *[@bitSizeOf(usize)]bool,
    group_order: *[@bitSizeOf(usize)]u32,
    group_cells: *[@bitSizeOf(usize)]usize,
    group_count: *usize,
    log_size: u32,
    n_columns: u32,
) !void {
    if (log_size >= @bitSizeOf(usize)) {
        return error.InvalidProductionDestinationShape;
    }
    const index: usize = @intCast(log_size);
    if (!seen[index]) {
        seen[index] = true;
        group_order[group_count.*] = log_size;
        group_count.* += 1;
    }
    const domain = @as(usize, 1) << @intCast(log_size);
    const cells = std.math.mul(
        usize,
        domain,
        n_columns,
    ) catch return error.Tree1ResourceOverflow;
    group_cells[index] = std.math.add(
        usize,
        group_cells[index],
        cells,
    ) catch return error.Tree1ResourceOverflow;
}

fn appendDescriptor(
    columns: []ColumnEvaluation,
    payload: []M31,
    column_index: *usize,
    group_cursors: *[@bitSizeOf(usize)]usize,
    log_size: u32,
    n_columns: u32,
) !void {
    if (log_size >= @bitSizeOf(usize)) {
        return error.InvalidProductionDestinationShape;
    }
    const domain = @as(usize, 1) << @intCast(log_size);
    const cursor = &group_cursors[@intCast(log_size)];
    for (0..n_columns) |_| {
        if (column_index.* >= columns.len or
            cursor.* > payload.len or
            domain > payload.len - cursor.*)
        {
            return error.InvalidProductionDestinationShape;
        }
        columns[column_index.*] = .{
            .log_size = log_size,
            .values = payload[cursor.* .. cursor.* + domain],
        };
        column_index.* += 1;
        cursor.* += domain;
    }
}

fn cellsFromBytes(bytes: usize) !usize {
    if (bytes % @sizeOf(M31) != 0) {
        return error.InvalidProductionDestinationShape;
    }
    return bytes / @sizeOf(M31);
}

comptime {
    if (@sizeOf(std.atomic.Value(u8)) != @sizeOf(bool)) {
        @compileError("Tree-1 ownership cell no longer matches the plan ledger");
    }
}
