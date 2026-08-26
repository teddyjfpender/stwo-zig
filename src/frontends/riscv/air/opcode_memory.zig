//! Opcode-side `memory_access` LogUp columns and constraints.
//!
//! Every Stark-V RV32IM family has at most three register/RW-memory accesses
//! per row. Fixed slots keep the proof shape independent of opcode counts;
//! unused slots are zero recurrences with zero claims. The verifier rebuilds
//! every tuple from the committed family columns through `accessFromMain`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const diagnostic_hints = @import("diagnostic_hints.zig");

/// Owner-exported source used by the root regression test to pin diagnostic
/// reporting without reaching across the frontend package boundary.
pub const diagnostic_wiring_source = @embedFile("opcode_memory.zig");
const memory_logup = @import("memory_logup.zig");
const relation_challenges = @import("relation_challenges.zig");
const trace_columns = @import("trace_columns.zig");
const trace_mod = @import("../runner/trace.zig");
const decode = @import("../isa/decode.zig");
const access_clock = @import("../access_clock.zig");

pub const N_ACCESSES: usize = 3;
pub const N_COLUMNS: usize = N_ACCESSES * 4;
pub const Previous = [N_ACCESSES][4][]M31;

/// Physical encoding of one opcode-side register or memory access.
///
/// `writable` and `read_only` both commit the legacy ten-column block: address,
/// four consumed limbs, previous clock, and four emitted limbs. `compact_read`
/// commits only the first six columns because a read emits exactly what it
/// consumed; its emitted limb indices therefore alias its consumed limb
/// indices. This is a storage fact, not a different memory-bus protocol.
pub const AccessMode = enum(u8) {
    writable,
    read_only,
    compact_read,

    pub inline fn aliasesEmittedValue(self: AccessMode) bool {
        return self == .compact_read;
    }

    pub inline fn committedColumnCount(self: AccessMode) usize {
        return if (self.aliasesEmittedValue()) 6 else 10;
    }
};

/// Production-owned map from one semantic access to its committed columns.
///
/// Consumers must use the column accessors. In particular, adding six to
/// `addressColumn()` is not valid for compact reads: their emitted columns are
/// the same physical cells as their consumed columns. The descriptor stays two
/// bytes so selecting it in the per-row verifier path does not copy a large
/// index table; its tiny accessors inline to constants and additions.
pub const AccessLayout = struct {
    mode: AccessMode,
    address_column: u8,

    pub inline fn addressColumn(self: AccessLayout) usize {
        return self.address_column;
    }

    pub inline fn previousLimbColumn(self: AccessLayout, limb: usize) ?usize {
        if (limb >= 4) return null;
        return self.addressColumn() + 1 + limb;
    }

    pub inline fn nextLimbColumn(self: AccessLayout, limb: usize) ?usize {
        if (limb >= 4) return null;
        const value_offset: usize = if (self.aliasesEmittedValue()) 1 else 6;
        return self.addressColumn() + value_offset + limb;
    }

    pub inline fn previousColumns(self: AccessLayout) [4]usize {
        return limbColumns(self.addressColumn() + 1);
    }

    pub inline fn nextColumns(self: AccessLayout) [4]usize {
        const value_offset: usize = if (self.aliasesEmittedValue()) 1 else 6;
        return limbColumns(self.addressColumn() + value_offset);
    }

    pub inline fn previousClockColumn(self: AccessLayout) usize {
        return self.addressColumn() + 5;
    }

    pub inline fn endColumn(self: AccessLayout) usize {
        return self.addressColumn() + self.mode.committedColumnCount();
    }

    pub inline fn aliasesEmittedValue(self: AccessLayout) bool {
        return self.mode.aliasesEmittedValue();
    }

    pub inline fn fits(self: AccessLayout, column_count: usize) bool {
        return self.endColumn() <= column_count;
    }

    fn init(address_column: usize, mode: AccessMode) AccessLayout {
        return .{
            .mode = mode,
            .address_column = @intCast(address_column),
        };
    }
};

inline fn limbColumns(first: usize) [4]usize {
    return .{ first, first + 1, first + 2, first + 3 };
}

const empty_access = AccessLayout{ .mode = .read_only, .address_column = 0 };

const FamilyAccessLayout = struct {
    count: u8,
    accesses: [N_ACCESSES]AccessLayout = .{empty_access} ** N_ACCESSES,
};

comptime {
    // This descriptor is selected for every opcode-side access in verifier
    // evaluation; keep its indexed-table footprint and copy cost explicit.
    if (@sizeOf(AccessLayout) != 2 or @sizeOf(FamilyAccessLayout) != 7) {
        @compileError("opcode access descriptors exceeded their pinned hot-path footprint");
    }
}

/// Complete access-layout table for every opcode family. Building offsets by
/// accumulating each access's physical width keeps the compact encoding in one
/// production authority and makes lookup a fixed-size indexed read in hot AIR
/// evaluation paths.
const access_layouts: [trace_mod.N_FAMILIES]FamilyAccessLayout = blk: {
    var families: [trace_mod.N_FAMILIES]FamilyAccessLayout = undefined;
    for (0..trace_mod.N_FAMILIES) |family_index| {
        const family: trace_mod.OpcodeFamily = @enumFromInt(family_index);
        var description = FamilyAccessLayout{ .count = @intCast(rawAccessCount(family)) };
        var column = firstAccessColumn(family);
        for (0..@as(usize, description.count)) |slot| {
            const mode = rawAccessMode(family, slot);
            description.accesses[slot] = AccessLayout.init(column, mode);
            column += mode.committedColumnCount();
        }
        if (column > trace_mod.nColumnsForFamily(family)) {
            @compileError("opcode access layout exceeds its committed family row");
        }
        families[family_index] = description;
    }
    break :blk families;
};

inline fn familyAccessLayout(family: trace_mod.OpcodeFamily) *const FamilyAccessLayout {
    return &access_layouts[@intFromEnum(family)];
}

/// Returns null for an absent slot. Callers that accept a runtime slot can
/// therefore reject malformed requests without an unchecked offset or
/// release-mode `unreachable`.
pub inline fn accessLayout(
    family: trace_mod.OpcodeFamily,
    slot: usize,
) ?AccessLayout {
    const description = familyAccessLayout(family);
    if (slot >= description.count) return null;
    return description.accesses[slot];
}

/// The one access that may change its value, or null for read-only families.
pub fn writtenSlot(family: trace_mod.OpcodeFamily) ?usize {
    const description = familyAccessLayout(family);
    for (description.accesses[0..description.count], 0..) |access, slot| {
        if (access.mode == .writable) return slot;
    }
    return null;
}

const load_store_columns = struct {
    const dst_addr_selector = columnIndex(
        trace_columns.LoadStoreColumns,
        "dst_addr_selector",
    );
    const src_addr_selector = columnIndex(
        trace_columns.LoadStoreColumns,
        "src_addr_selector",
    );
    const opcode_lb = columnIndex(trace_columns.LoadStoreColumns, "opcode_lb_flag");
    const opcode_lh = columnIndex(trace_columns.LoadStoreColumns, "opcode_lh_flag");
    const opcode_lbu = columnIndex(trace_columns.LoadStoreColumns, "opcode_lbu_flag");
    const opcode_lhu = columnIndex(trace_columns.LoadStoreColumns, "opcode_lhu_flag");
    const opcode_lw = columnIndex(trace_columns.LoadStoreColumns, "opcode_lw_flag");
    const opcode_sb = columnIndex(trace_columns.LoadStoreColumns, "opcode_sb_flag");
    const opcode_sh = columnIndex(trace_columns.LoadStoreColumns, "opcode_sh_flag");
    const opcode_sw = columnIndex(trace_columns.LoadStoreColumns, "opcode_sw_flag");
};

fn columnIndex(comptime Layout: type, comptime name: []const u8) usize {
    return comptime found: {
        for (@typeInfo(Layout).@"struct".fields, 0..) |field, index| {
            if (std.mem.eql(u8, field.name, name)) break :found index;
        }
        @compileError("missing committed column '" ++ name ++ "' in " ++ @typeName(Layout));
    };
}

pub const RegisterBoundary = struct {
    initial: [32]u32 = .{0} ** 32,
    final: [32]u32 = .{0} ** 32,
    last_clock: [32]u32 = .{0} ** 32,
};

pub const Generated = struct {
    columns: [N_COLUMNS][]M31,
    previous: Previous,
    claims: [N_ACCESSES]QM31,

    pub fn deinit(self: *Generated, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        for (&self.previous) |*set| freeColumns(allocator, set);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    rows: []const trace_mod.TraceRow,
    family: trace_mod.OpcodeFamily,
    log_size: u32,
    relation: *const relation_challenges.RelationElements(7),
) !Generated {
    var result: Generated = undefined;
    var initialized: usize = 0;
    errdefer {
        freeColumns(allocator, result.columns[0 .. initialized * 4]);
        for (result.previous[0..initialized]) |*set| freeColumns(allocator, set);
    }

    for (0..N_ACCESSES) |slot| {
        const has_access = slot < accessCount(family);
        var accesses: []memory_logup.AccessWitness = &.{};
        if (has_access) accesses = try allocator.alloc(memory_logup.AccessWitness, rows.len);
        defer if (has_access) allocator.free(accesses);
        if (has_access) {
            for (rows, accesses) |row, *access| access.* = accessFromTrace(row, family, slot);
        }

        const generated = try memory_logup.generate(allocator, accesses, log_size, relation);
        for (generated.columns, 0..) |column, coordinate| {
            result.columns[slot * 4 + coordinate] = column;
        }
        result.previous[slot] = generated.previous_columns;
        result.claims[slot] = generated.claimed;
        initialized += 1;
    }
    return result;
}

/// Reconstruct one access from the committed main row. This is the sole
/// verifier-side family layout map for the memory-access relation.
pub fn accessFromMain(
    family: trace_mod.OpcodeFamily,
    main: []const QM31,
    slot: usize,
    is_active: QM31,
) !memory_logup.AccessWitness {
    if (main.len < trace_mod.nColumnsForFamily(family)) return error.InvalidOracleTraceShape;
    const family_layout = familyAccessLayout(family);
    if (slot >= family_layout.count) return disabledAccess();
    const access = family_layout.accesses[slot];
    if (!access.fits(main.len)) return error.InvalidOracleTraceShape;
    const instruction_clock = main[clockColumn(family)];

    if (family == .load_store) {
        const is_load = main[load_store_columns.opcode_lb]
            .add(main[load_store_columns.opcode_lh])
            .add(main[load_store_columns.opcode_lbu])
            .add(main[load_store_columns.opcode_lhu])
            .add(main[load_store_columns.opcode_lw]);
        const is_store = main[load_store_columns.opcode_sb]
            .add(main[load_store_columns.opcode_sh])
            .add(main[load_store_columns.opcode_sw]);
        const first = derivedClock(instruction_clock, .first);
        const second = derivedClock(instruction_clock, .second);
        return switch (slot) {
            0 => fromMainAccess(
                main,
                access,
                is_store,
                main[load_store_columns.dst_addr_selector],
                second.add(is_store),
                is_active,
            ),
            1 => fromMainAccess(
                main,
                access,
                QM31.zero(),
                main[access.addressColumn()],
                first,
                is_active,
            ),
            2 => fromMainAccess(
                main,
                access,
                is_load,
                main[load_store_columns.src_addr_selector],
                second.add(is_load),
                is_active,
            ),
            else => return error.InvalidOracleAccessLayout,
        };
    }

    return fromMainAccess(
        main,
        access,
        QM31.zero(),
        main[access.addressColumn()],
        derivedClock(instruction_clock, accessOrdinal(family, slot)),
        is_active,
    );
}

pub fn constraints(
    family: trace_mod.OpcodeFamily,
    main: []const QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [N_ACCESSES]QM31,
    previous: [N_ACCESSES]QM31,
    claims: [N_ACCESSES]QM31,
    relation: *const relation_challenges.RelationElements(7),
) ![N_ACCESSES]QM31 {
    var result: [N_ACCESSES]QM31 = undefined;
    for (&result, 0..) |*constraint, slot| {
        const access = try accessFromMain(family, main, slot, is_active);
        constraint.* = memory_logup.pairConstraint(
            sums[slot],
            previous[slot],
            is_first,
            claims[slot],
            memory_logup.rowPair(relation, access),
        );
    }
    return result;
}

/// Failure modes of `deriveRegisterBoundary`.
///
/// The two are deliberately distinct conditions and must never be conflated.
/// `UnsupportedForProof` means the trace contains an instruction the proof
/// system cannot represent at all, so no register boundary exists to derive;
/// `InvalidRegisterAccessChain` means a fully representable trace's
/// source-before-destination chain does not close. Reporting the former as the
/// latter points the reader at witness generation for a defect that lives in
/// the caller's opcode admission instead.
///
/// `UnsupportedForProof` is the canonical, codebase-wide name for "this opcode
/// has no proof encoding" (`decode.proofOpcode`, `Trace.groupByOpcodeFamily`),
/// and is reused here on purpose: one root cause deserves one name, and the
/// remedy -- keep execution-only opcodes out of the proven trace -- is the same
/// wherever it is raised.
pub const RegisterBoundaryError = decode.ProofOpcodeError || error{InvalidRegisterAccessChain};

/// Derive the register boundary used by the convenience trace-only proving
/// API while validating the exact source-before-destination access chain.
/// Production ELF proving supplies the runner's full initial/final state.
///
/// This runs at the very top of `prover.proveRiscVTraceOnlyNoPublicIoUsingChannel`,
/// which is *before* `prover/statement_geometry.build` invokes
/// `Trace.groupByOpcodeFamily`. It therefore cannot assume the execution-only
/// opcodes have already been filtered out and must fail closed itself, which is
/// why it resolves families through the fallible `proofOpcodeFamily` rather
/// than the post-filter `opcodeFamily` helper. Since `opcodeFamily` now takes a
/// `trace.ProofOpcode`, that is no longer a discipline this comment has to
/// carry: the post-filter helper is not callable from here at all.
///
/// Both failures are reported with the diagnostic that answers them before the
/// error propagates, because the two send a reader to different modules and the
/// error names alone have historically not been enough to tell them apart.
pub fn deriveRegisterBoundary(rows: []const trace_mod.TraceRow) RegisterBoundaryError!RegisterBoundary {
    return deriveRegisterBoundaryUnreported(rows) catch |err| {
        diagnostic_hints.reportRegisterBoundary(err);
        return err;
    };
}

fn deriveRegisterBoundaryUnreported(
    rows: []const trace_mod.TraceRow,
) RegisterBoundaryError!RegisterBoundary {
    var result = RegisterBoundary{};
    var seen = [_]bool{false} ** 32;
    for (rows) |row| {
        const family = try trace_mod.proofOpcodeFamily(row.opcode);
        switch (family) {
            .base_alu_reg, .shifts_reg, .lt_reg, .mul, .mulh, .div => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rs2Trace(row, .second));
                try observe(&result, &seen, rdTrace(row, .third));
            },
            .base_alu_imm, .shifts_imm, .lt_imm => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rdTrace(row, .second));
            },
            .branch_eq, .branch_lt => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rs2Trace(row, .second));
            },
            .lui, .auipc, .jal => try observe(&result, &seen, rdTrace(row, .first)),
            .jalr => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rdTrace(row, .second));
            },
            .load_store => {
                try observe(&result, &seen, rs1Trace(row, .first));
                if (row.is_load) {
                    try observe(&result, &seen, rdTrace(row, .second));
                } else {
                    try observe(&result, &seen, rs2Trace(row, .second));
                }
            },
            .fence => {},
        }
    }
    return result;
}

pub fn accessCount(family: trace_mod.OpcodeFamily) usize {
    return familyAccessLayout(family).count;
}

fn rawAccessCount(family: trace_mod.OpcodeFamily) usize {
    return switch (family) {
        .base_alu_reg, .shifts_reg, .lt_reg, .load_store, .mul, .mulh, .div => 3,
        .base_alu_imm, .shifts_imm, .lt_imm, .branch_eq, .branch_lt, .jalr => 2,
        .lui, .auipc, .jal => 1,
        .fence => 0,
    };
}

pub fn clockColumn(family: trace_mod.OpcodeFamily) usize {
    return switch (family) {
        .lui, .auipc, .jalr, .jal, .mul, .fence => 1,
        else => 0,
    };
}

fn firstAccessColumn(family: trace_mod.OpcodeFamily) usize {
    // Every family places pc immediately after clock, followed by accesses.
    return clockColumn(family) + 2;
}

fn rawAccessMode(family: trace_mod.OpcodeFamily, slot: usize) AccessMode {
    if (family == .base_alu_reg or family == .load_store) {
        return if (slot == 0) .writable else .compact_read;
    }
    return switch (family) {
        .branch_eq, .branch_lt => .read_only,
        .fence => unreachable,
        else => if (slot == 0) .writable else .read_only,
    };
}

fn accessFromTrace(
    row: trace_mod.TraceRow,
    family: trace_mod.OpcodeFamily,
    slot: usize,
) memory_logup.AccessWitness {
    if (family == .load_store) return switch (slot) {
        0 => if (row.is_store)
            memoryAccess(row, .third)
        else
            rdAccess(row, .second),
        1 => rs1Access(row, .first),
        2 => if (row.is_load)
            memoryAccess(row, .third)
        else
            rs2Access(row, .second),
        else => unreachable,
    };
    const ordinal = accessOrdinal(family, slot);
    return switch (accessKind(family, slot)) {
        .rd => rdAccess(row, ordinal),
        .rs1 => rs1Access(row, ordinal),
        .rs2 => rs2Access(row, ordinal),
    };
}

const AccessKind = enum { rd, rs1, rs2 };

const TraceAccess = struct {
    addr: u5,
    previous_clock: u32,
    previous: u32,
    clock: u32,
    next: u32,
};

fn accessKind(family: trace_mod.OpcodeFamily, slot: usize) AccessKind {
    return switch (family) {
        .branch_eq, .branch_lt => if (slot == 0) .rs1 else .rs2,
        .lui, .auipc, .jal => .rd,
        .jalr => if (slot == 0) .rd else .rs1,
        .fence => unreachable,
        else => @enumFromInt(slot),
    };
}

fn accessOrdinal(
    family: trace_mod.OpcodeFamily,
    slot: usize,
) access_clock.Ordinal {
    return switch (accessKind(family, slot)) {
        .rs1 => .first,
        .rs2 => .second,
        .rd => switch (family) {
            .base_alu_reg, .shifts_reg, .lt_reg, .mul, .mulh, .div => .third,
            .base_alu_imm, .shifts_imm, .lt_imm, .jalr => .second,
            .lui, .auipc, .jal => .first,
            .branch_eq, .branch_lt, .load_store, .fence => unreachable,
        },
    };
}

fn rdAccess(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        0,
        row.rd,
        row.rd_prev_clk,
        row.rd_prev_val,
        access_clock.encode(row.clk, ordinal),
        row.rd_val,
    );
}

fn rdTrace(row: trace_mod.TraceRow, ordinal: access_clock.Ordinal) TraceAccess {
    return .{
        .addr = row.rd,
        .previous_clock = row.rd_prev_clk,
        .previous = row.rd_prev_val,
        .clock = access_clock.encode(row.clk, ordinal),
        .next = row.rd_val,
    };
}

fn rs1Access(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        0,
        row.rs1,
        row.rs1_prev_clk,
        row.rs1_val,
        access_clock.encode(row.clk, ordinal),
        row.rs1_val,
    );
}

fn rs1Trace(row: trace_mod.TraceRow, ordinal: access_clock.Ordinal) TraceAccess {
    return .{
        .addr = row.rs1,
        .previous_clock = row.rs1_prev_clk,
        .previous = row.rs1_val,
        .clock = access_clock.encode(row.clk, ordinal),
        .next = row.rs1_val,
    };
}

fn rs2Access(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        0,
        row.rs2,
        row.rs2_prev_clk,
        row.rs2_val,
        access_clock.encode(row.clk, ordinal),
        row.rs2_val,
    );
}

fn rs2Trace(row: trace_mod.TraceRow, ordinal: access_clock.Ordinal) TraceAccess {
    return .{
        .addr = row.rs2,
        .previous_clock = row.rs2_prev_clk,
        .previous = row.rs2_val,
        .clock = access_clock.encode(row.clk, ordinal),
        .next = row.rs2_val,
    };
}

fn observe(boundary: *RegisterBoundary, seen: *[32]bool, access: TraceAccess) !void {
    const index = @as(usize, access.addr);
    if (!seen[index]) {
        if (access.previous_clock != 0) return error.InvalidRegisterAccessChain;
        boundary.initial[index] = access.previous;
        boundary.final[index] = access.previous;
        seen[index] = true;
    }
    if (boundary.last_clock[index] != access.previous_clock or
        boundary.final[index] != access.previous)
        return error.InvalidRegisterAccessChain;
    boundary.last_clock[index] = access.clock;
    boundary.final[index] = access.next;
}

fn memoryAccess(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        1,
        row.mem_addr & ~@as(u32, 3),
        row.mem_prev_clk,
        row.mem_prev_word,
        access_clock.encode(row.clk, ordinal),
        row.mem_next_word,
    );
}

fn witness(
    addr_space: u1,
    addr: u32,
    previous_clock: u32,
    previous_value: u32,
    clock: u32,
    next_value: u32,
) memory_logup.AccessWitness {
    return .{
        .addr_space = base(addr_space),
        .addr = base(addr),
        .previous_clock = base(previous_clock),
        .previous = limbs(previous_value),
        .clock = base(clock),
        .next = limbs(next_value),
        .enabler = QM31.one(),
    };
}

fn fromMainAccess(
    main: []const QM31,
    access: AccessLayout,
    addr_space: QM31,
    addr: QM31,
    clock: QM31,
    enabler: QM31,
) memory_logup.AccessWitness {
    return .{
        .addr_space = addr_space,
        .addr = addr,
        .previous_clock = main[access.previousClockColumn()],
        .previous = readLimbs(main, access.previousColumns()),
        .clock = clock,
        .next = readLimbs(main, access.nextColumns()),
        .enabler = enabler,
    };
}

inline fn readLimbs(main: []const QM31, columns: [4]usize) [4]QM31 {
    return .{ main[columns[0]], main[columns[1]], main[columns[2]], main[columns[3]] };
}

fn derivedClock(
    instruction_clock: QM31,
    ordinal: access_clock.Ordinal,
) QM31 {
    return instruction_clock.sub(QM31.one())
        .mul(base(access_clock.STRIDE))
        .add(base(@intFromEnum(ordinal) + 1));
}

fn disabledAccess() memory_logup.AccessWitness {
    return .{
        .addr_space = QM31.zero(),
        .addr = QM31.zero(),
        .previous_clock = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
        .enabler = QM31.zero(),
    };
}

fn limbs(value: u32) [4]QM31 {
    return .{
        base(@as(u8, @truncate(value))),
        base(@as(u8, @truncate(value >> 8))),
        base(@as(u8, @truncate(value >> 16))),
        base(@as(u8, @truncate(value >> 24))),
    };
}

fn base(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

test "opcode memory: committed load/store selectors choose address spaces" {
    var main = [_]QM31{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
    main[0] = base(9);
    main[load_store_columns.dst_addr_selector] = base(4);
    main[load_store_columns.src_addr_selector] = base(0x1000);
    main[load_store_columns.opcode_lw] = QM31.one();
    const committed = main[0..trace_mod.nColumnsForFamily(.load_store)];

    const dst = try accessFromMain(.load_store, committed, 0, QM31.one());
    const source = try accessFromMain(.load_store, committed, 2, QM31.one());
    try std.testing.expect(dst.addr_space.isZero());
    try std.testing.expect(dst.addr.eql(base(4)));
    try std.testing.expect(source.addr_space.eql(QM31.one()));
    try std.testing.expect(source.addr.eql(base(0x1000)));

    main[load_store_columns.opcode_lw] = QM31.zero();
    main[load_store_columns.opcode_sw] = QM31.one();
    main[load_store_columns.dst_addr_selector] = base(0x1000);
    main[load_store_columns.src_addr_selector] = base(3);
    const store_dst = try accessFromMain(.load_store, committed, 0, QM31.one());
    const store_source = try accessFromMain(.load_store, committed, 2, QM31.one());
    try std.testing.expect(store_dst.addr_space.eql(QM31.one()));
    try std.testing.expect(store_dst.addr.eql(base(0x1000)));
    try std.testing.expect(store_source.addr_space.isZero());
    try std.testing.expect(store_source.addr.eql(base(3)));
}

test "opcode memory: absent family slots are disabled" {
    var main = [_]QM31{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
    const absent = try accessFromMain(.lui, &main, 1, QM31.one());
    try std.testing.expect(absent.enabler.isZero());
    try std.testing.expectEqual(@as(usize, 1), accessCount(.lui));
    try std.testing.expectEqual(@as(usize, 3), accessCount(.div));
}

test "opcode memory: access descriptors encode compact aliases exactly once" {
    const reg_rd = accessLayout(.base_alu_reg, 0).?;
    const reg_rs1 = accessLayout(.base_alu_reg, 1).?;
    const reg_rs2 = accessLayout(.base_alu_reg, 2).?;
    try std.testing.expectEqual(AccessMode.writable, reg_rd.mode);
    try std.testing.expectEqual(AccessMode.compact_read, reg_rs1.mode);
    try std.testing.expectEqual(AccessMode.compact_read, reg_rs2.mode);
    try std.testing.expectEqual(
        columnIndex(trace_columns.BaseAluRegColumns, "rs1_addr"),
        reg_rs1.addressColumn(),
    );
    try std.testing.expectEqual(
        columnIndex(trace_columns.BaseAluRegColumns, "rs2_addr"),
        reg_rs2.addressColumn(),
    );
    try std.testing.expectEqual(reg_rs1.previousColumns(), reg_rs1.nextColumns());
    try std.testing.expectEqual(reg_rs2.previousColumns(), reg_rs2.nextColumns());

    const load_rs1 = accessLayout(.load_store, 1).?;
    const load_src = accessLayout(.load_store, 2).?;
    try std.testing.expect(load_rs1.aliasesEmittedValue());
    try std.testing.expect(load_src.aliasesEmittedValue());
    try std.testing.expectEqual(
        columnIndex(trace_columns.LoadStoreColumns, "rs1_addr"),
        load_rs1.addressColumn(),
    );
    try std.testing.expectEqual(
        columnIndex(trace_columns.LoadStoreColumns, "src_addr"),
        load_src.addressColumn(),
    );

    const imm_rs1 = accessLayout(.base_alu_imm, 1).?;
    try std.testing.expectEqual(AccessMode.read_only, imm_rs1.mode);
    try std.testing.expect(!imm_rs1.aliasesEmittedValue());
    const imm_previous = imm_rs1.previousColumns();
    const imm_next = imm_rs1.nextColumns();
    try std.testing.expect(!std.mem.eql(usize, &imm_previous, &imm_next));
}

test "opcode memory: every descriptor is bounded and invalid coordinates fail closed" {
    for (0..trace_mod.N_FAMILIES) |family_index| {
        const family: trace_mod.OpcodeFamily = @enumFromInt(family_index);
        const description = familyAccessLayout(family);
        const width = trace_mod.nColumnsForFamily(family);
        for (description.accesses[0..description.count]) |access| {
            try std.testing.expect(access.fits(width));
            try std.testing.expect(access.previousLimbColumn(4) == null);
            try std.testing.expect(access.nextLimbColumn(4) == null);
        }
        try std.testing.expect(accessLayout(family, description.count) == null);
    }

    var short = [_]QM31{QM31.zero()} ** 34;
    try std.testing.expectError(
        error.InvalidOracleTraceShape,
        accessFromMain(.base_alu_reg, &short, 0, QM31.one()),
    );
}
