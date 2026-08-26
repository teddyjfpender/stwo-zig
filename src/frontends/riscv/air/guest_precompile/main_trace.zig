//! Transactional main-trace construction for the Poseidon2 guest extension.
//!
//! Cold preflight consumes the admitted C-006 statement authority and the two
//! frozen execution logs before storage exists. Successful construction owns
//! one column-major allocation already in committed circle bit-reversed order.

const std = @import("std");
const core_utils = @import("stwo_core").utils;
const m31 = @import("stwo_core").fields.m31;
const access_clock = @import("../../access_clock.zig");
const custom0 = @import("../../isa/custom0.zig");
const isa_profile = @import("../../isa/profile.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const guest_runner = @import("../../runner/guest_precompile/poseidon2_v1.zig");
const state_chain = @import("../../runner/state_chain.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const riscv_statement = @import("../statement.zig");
const components = @import("component_registry.zig");
const statement_mod = @import("statement.zig");
const poseidon_work = @import("../../prover/poseidon_witness_work.zig");

const M31 = m31.M31;
const RiscVStatement = riscv_statement.RiscVStatement;
const ExtensionStatement = statement_mod.ExtensionStatement;
const FrozenCalls = call_buffer.Frozen;
const FrozenExecutionRows = guest_runner.FrozenExecutionRows;

pub const selector_columns_per_component: usize = 2;
pub const component_count: usize = components.extension_component_count;
pub const preprocessed_column_count: usize =
    selector_columns_per_component * component_count;
pub const caller_main_column_count: usize = components.caller_layout.main_columns;
pub const provider_main_column_count: usize = components.provider_main_columns;
pub const main_column_count: usize =
    caller_main_column_count + provider_main_column_count;
pub const total_column_count: usize =
    preprocessed_column_count + main_column_count;
pub const caller_relation_source_column_count: usize =
    components.caller_layout.canonical_materializations;
pub const provider_relation_source_column_count: usize = 1 + 16 + 16;
pub const relation_source_column_count: usize =
    caller_relation_source_column_count + provider_relation_source_column_count;

const caller_preprocessed_start: usize = 0;
const provider_preprocessed_start: usize =
    caller_preprocessed_start + selector_columns_per_component;
const caller_main_start: usize =
    provider_preprocessed_start + selector_columns_per_component;
const provider_main_start: usize = caller_main_start + caller_main_column_count;

pub const Error = statement_mod.Error || custom0.DecodeError ||
    isa_profile.ProgramAddressError || error{
    OutOfMemory,
    TraceSizeOverflow,
    CallCountOutOfRange,
    CallIndexMismatch,
    ExecutionClockMismatch,
    ExecutionClockOutOfRange,
    ExecutionOrderMismatch,
    PcMismatch,
    PointerRegisterMismatch,
    PrecompileAddressMisaligned,
    PrecompileSpanOutOfRange,
    PointerPreviousClockInvalid,
    MemoryPreviousClockInvalid,
    NonCanonicalPrecompileWord,
    ProviderOutputMismatch,
    ProviderModeMismatch,
    InvalidDestinationShape,
    OverlappingDestinations,
};

/// Additive R-008 research seam. Production still calls `generate` or
/// `generateMainInto`; neither function dispatches through this split path.
pub const SPLIT_MAIN_TRACE_SHADOW_ONLY = true;

pub const CallerMainDestinations = [caller_main_column_count][]M31;
pub const ProviderMainDestinations = [provider_main_column_count][]M31;

/// Caller-owned final Tree-1 storage. All slices are validated, including
/// pairwise disjointness, before the first cell is changed.
pub const MainDestinations = struct {
    caller: CallerMainDestinations,
    provider: ProviderMainDestinations,
};

/// The minimal post-Tree-1 projection needed to derive guest interactions.
///
/// The caller needs columns 0..158. The provider needs only its enabler,
/// sixteen inputs, and sixteen outputs. Retaining 191 columns instead of all
/// 731 keeps challenge-dependent Tree-2 generation byte-identical to the
/// committed witness without doubling the wide compatibility trace.
pub const RelationSource = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,

    pub fn capture(
        allocator: std.mem.Allocator,
        destinations: *const MainDestinations,
        log_size: u32,
        n_rows: u32,
    ) Error!RelationSource {
        if (log_size >= @bitSizeOf(usize)) return error.TraceSizeOverflow;
        const domain_size = @as(usize, 1) << @intCast(log_size);
        try validateDestinations(destinations, domain_size);
        const cells = std.math.mul(
            usize,
            relation_source_column_count,
            domain_size,
        ) catch return error.TraceSizeOverflow;
        _ = std.math.mul(usize, cells, @sizeOf(M31)) catch
            return error.TraceSizeOverflow;
        const storage = try allocator.alloc(M31, cells);
        errdefer allocator.free(storage);

        var storage_column: usize = 0;
        for (destinations.caller[0..caller_relation_source_column_count]) |source_values| {
            @memcpy(storage[storage_column * domain_size ..][0..domain_size], source_values);
            storage_column += 1;
        }
        @memcpy(
            storage[storage_column * domain_size ..][0..domain_size],
            destinations.provider[0],
        );
        storage_column += 1;
        for (destinations.provider[1..17]) |source_values| {
            @memcpy(storage[storage_column * domain_size ..][0..domain_size], source_values);
            storage_column += 1;
        }
        const provider_output_start = 1 + poseidon2_air.N_TEMPORARIES;
        for (destinations.provider[provider_output_start..][0..16]) |source_values| {
            @memcpy(storage[storage_column * domain_size ..][0..domain_size], source_values);
            storage_column += 1;
        }
        std.debug.assert(storage_column == relation_source_column_count);
        return .{
            .allocator = allocator,
            .storage = storage,
            .log_size = log_size,
            .n_rows = n_rows,
            .domain_size = domain_size,
        };
    }

    pub fn deinit(self: *RelationSource) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn domainSize(self: *const RelationSource) usize {
        return self.domain_size;
    }

    pub fn committedCells(self: *const RelationSource) []const M31 {
        return self.storage;
    }

    pub fn callerMain(self: *const RelationSource, index: usize) []const M31 {
        std.debug.assert(index < caller_relation_source_column_count);
        return self.column(index);
    }

    pub fn providerMain(self: *const RelationSource, index: usize) []const M31 {
        const source_index = if (index == 0)
            caller_relation_source_column_count
        else if (index >= 1 and index < 17)
            caller_relation_source_column_count + index
        else if (index >= 1 + poseidon2_air.N_TEMPORARIES and
            index < 1 + poseidon2_air.N_TEMPORARIES + 16)
            caller_relation_source_column_count + 17 +
                index - (1 + poseidon2_air.N_TEMPORARIES)
        else
            unreachable;
        return self.column(source_index);
    }

    fn column(self: *const RelationSource, index: usize) []const M31 {
        const start = index * self.domain_size;
        return self.storage[start..][0..self.domain_size];
    }
};

/// One allocation containing all extension selector and main columns.
///
/// Column accessors return committed-order storage. Logical row `r` is at
/// `committedRow(r, log_size)` in every returned column.
pub const Result = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,

    pub fn deinit(self: *Result) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn domainSize(self: *const Result) usize {
        return self.domain_size;
    }

    pub fn committedCells(self: *const Result) []const M31 {
        return self.storage;
    }

    pub fn callerPreprocessed(self: *const Result, index: usize) []const M31 {
        std.debug.assert(index < selector_columns_per_component);
        return self.column(caller_preprocessed_start + index);
    }

    pub fn providerPreprocessed(self: *const Result, index: usize) []const M31 {
        std.debug.assert(index < selector_columns_per_component);
        return self.column(provider_preprocessed_start + index);
    }

    pub fn callerMain(self: *const Result, index: usize) []const M31 {
        std.debug.assert(index < caller_main_column_count);
        return self.column(caller_main_start + index);
    }

    pub fn providerMain(self: *const Result, index: usize) []const M31 {
        std.debug.assert(index < provider_main_column_count);
        return self.column(provider_main_start + index);
    }

    pub fn mutableMainDestinations(self: *Result) MainDestinations {
        var destinations: MainDestinations = undefined;
        for (&destinations.caller, 0..) |*destination, index| {
            destination.* = @constCast(self.callerMain(index));
        }
        for (&destinations.provider, 0..) |*destination, index| {
            destination.* = @constCast(self.providerMain(index));
        }
        return destinations;
    }

    fn column(self: *const Result, index: usize) []const M31 {
        const start = index * self.domain_size;
        return self.storage[start..][0..self.domain_size];
    }

    fn write(self: *Result, column_index: usize, row: usize, value: M31) void {
        self.storage[column_index * self.domain_size + row] = value;
    }
};

/// Validate both frozen authorities, then materialize exact C-007 main traces.
pub fn generate(
    allocator: std.mem.Allocator,
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    calls: *const FrozenCalls,
    execution_rows: *const FrozenExecutionRows,
) Error!Result {
    const prepared = try prepare(core, extension, calls, execution_rows);
    const total_cells = std.math.mul(
        usize,
        total_column_count,
        prepared.domain_size,
    ) catch return error.TraceSizeOverflow;
    _ = std.math.mul(usize, total_cells, @sizeOf(M31)) catch
        return error.TraceSizeOverflow;

    const storage = try allocator.alloc(M31, total_cells);
    errdefer allocator.free(storage);
    @memset(storage, M31.zero());
    var result = Result{
        .allocator = allocator,
        .storage = storage,
        .log_size = prepared.log_size,
        .n_rows = prepared.n_rows,
        .domain_size = prepared.domain_size,
    };

    const first = committedRow(0, prepared.log_size);
    result.write(caller_preprocessed_start, first, M31.one());
    result.write(provider_preprocessed_start, first, M31.one());
    for (prepared.records, 0..) |_, logical_row| {
        const destination = committedRow(logical_row, prepared.log_size);
        if (logical_row == 0) {
            std.debug.assert(destination == first);
        }
        result.write(caller_preprocessed_start + 1, destination, M31.one());
        result.write(provider_preprocessed_start + 1, destination, M31.one());
    }
    var destinations = result.mutableMainDestinations();
    fillMain(prepared, &destinations);
    return result;
}

pub const GuestWorkReceipts = struct {
    preflight: poseidon_work.ProducerReceipt,
    materialization: poseidon_work.ProducerReceipt,

    pub fn publishInto(
        self: GuestWorkReceipts,
        authority: *const poseidon_work.Authority,
        shard: *poseidon_work.Shard,
    ) !void {
        var next = shard.*;
        try next.observe(authority, self.preflight);
        try next.observe(authority, self.materialization);
        shard.* = next;
    }
};

pub const GeneratedWithWorkReceipt = struct {
    result: Result,
    work: GuestWorkReceipts,
};

/// Allocation-owning exact-work route.  `prepare` evaluates one provider row
/// per call to authenticate its output, then `fillMain` evaluates it again for
/// the committed witness; those schedules remain independently visible.
pub fn generateWithWorkReceipt(
    allocator: std.mem.Allocator,
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    calls: *const FrozenCalls,
    execution_rows: *const FrozenExecutionRows,
    authority: *const poseidon_work.Authority,
) !GeneratedWithWorkReceipt {
    var result = try generate(allocator, core, extension, calls, execution_rows);
    errdefer result.deinit();
    return .{
        .result = result,
        .work = try guestWorkReceipts(authority, calls.len()),
    };
}

/// Validate the frozen authorities and write directly into final Tree-1
/// column storage. The hot row loop allocates nothing and performs no dynamic
/// dispatch. All authority and destination checks complete before mutation.
pub fn generateMainInto(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    calls: *const FrozenCalls,
    execution_rows: *const FrozenExecutionRows,
    destinations: *const MainDestinations,
) Error!void {
    const prepared = try prepare(core, extension, calls, execution_rows);
    try validateDestinations(destinations, prepared.domain_size);
    for (destinations.caller) |destination| @memset(destination, M31.zero());
    for (destinations.provider) |destination| @memset(destination, M31.zero());
    fillMain(prepared, destinations);
}

/// Caller-owned exact-work route.  The ordinary function keeps its allocation-
/// free, branch-free provider loop; receipts are constructed only after every
/// destination has been written successfully.
pub fn generateMainIntoWithWorkReceipt(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    calls: *const FrozenCalls,
    execution_rows: *const FrozenExecutionRows,
    destinations: *const MainDestinations,
    authority: *const poseidon_work.Authority,
) !GuestWorkReceipts {
    try generateMainInto(core, extension, calls, execution_rows, destinations);
    return guestWorkReceipts(authority, calls.len());
}

fn guestWorkReceipts(
    authority: *const poseidon_work.Authority,
    call_count: usize,
) !GuestWorkReceipts {
    const completed = std.math.cast(u64, call_count) orelse
        return error.PoseidonWorkOverflow;
    return .{
        .preflight = try poseidon_work.complete(
            authority,
            .guest_provider_preflight,
            completed,
        ),
        .materialization = try poseidon_work.complete(
            authority,
            .guest_provider_materialization,
            completed,
        ),
    };
}

const Prepared = struct {
    records: []const call_buffer.Record,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,
};

/// Immutable, allocation-free authority for detached caller/provider fills.
/// It borrows the frozen call storage accepted by `prepareShadowSplitMainV1`;
/// that storage must remain alive and immutable until both role fills finish.
pub const ShadowSplitMainAuthorityV1 = struct {
    records: []const call_buffer.Record,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,
};

/// Repeat the exact production construction and row preflight before either
/// split destination is allocated or mutated. This is intentionally detached
/// from production dispatch and exists only as R-008 differential substrate.
pub fn prepareShadowSplitMainV1(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    calls: *const FrozenCalls,
    execution_rows: *const FrozenExecutionRows,
) Error!ShadowSplitMainAuthorityV1 {
    const prepared = try prepare(core, extension, calls, execution_rows);
    return .{
        .records = prepared.records,
        .log_size = prepared.log_size,
        .n_rows = prepared.n_rows,
        .domain_size = prepared.domain_size,
    };
}

/// Infallible caller fill after a split orchestrator has admitted every role
/// destination. The caller and provider functions touch disjoint slices and
/// may therefore execute concurrently against one immutable authority.
pub fn fillShadowCallerMainAssumeAdmittedV1(
    authority: ShadowSplitMainAuthorityV1,
    destinations: *const CallerMainDestinations,
) void {
    for (authority.records, 0..) |record, logical_row| {
        const destination = committedRow(logical_row, authority.log_size);
        const row = fillCaller(record);
        for (row, destinations.*) |value, destination_column| {
            destination_column[destination] = value;
        }
    }
}

/// Infallible provider fill after pair-wide destination admission.
pub fn fillShadowProviderMainAssumeAdmittedV1(
    authority: ShadowSplitMainAuthorityV1,
    destinations: *const ProviderMainDestinations,
) void {
    for (authority.records, 0..) |record, logical_row| {
        const destination = committedRow(logical_row, authority.log_size);
        const row = poseidon2_air.fill(.{
            .input = record.input,
            .wide = false,
            .io = true,
        });
        for (row, destinations.*) |value, destination_column| {
            destination_column[destination] = value;
        }
    }
}

fn prepare(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    calls: *const FrozenCalls,
    execution_rows: *const FrozenExecutionRows,
) Error!Prepared {
    const records = calls.records();
    const rows = execution_rows.rows();
    const frozen_call_count = std.math.cast(u32, records.len) orelse
        return error.CallCountOutOfRange;
    const custom_retirements = std.math.cast(u32, rows.len) orelse
        return error.CallCountOutOfRange;
    try extension.validateConstruction(core, .{
        .custom_retirements = custom_retirements,
        .frozen_call_count = frozen_call_count,
    });
    try validateConstructionAuthority(extension);
    const log_size = extension.components[0].log_size;
    if (log_size >= @bitSizeOf(usize)) return error.TraceSizeOverflow;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    try preflightRows(core, extension, records, rows);
    return .{
        .records = records,
        .log_size = log_size,
        .n_rows = frozen_call_count,
        .domain_size = domain_size,
    };
}

fn fillMain(prepared: Prepared, destinations: *const MainDestinations) void {
    for (prepared.records, 0..) |record, logical_row| {
        const destination = committedRow(logical_row, prepared.log_size);
        const caller_row = fillCaller(record);
        for (caller_row, destinations.caller) |value, destination_column| {
            destination_column[destination] = value;
        }
        const provider_row = poseidon2_air.fill(.{
            .input = record.input,
            .wide = false,
            .io = true,
        });
        for (provider_row, destinations.provider) |value, destination_column| {
            destination_column[destination] = value;
        }
    }
}

fn validateDestinations(
    destinations: *const MainDestinations,
    domain_size: usize,
) Error!void {
    for (0..main_column_count) |index| {
        const current = destinationAt(destinations, index);
        if (current.len != domain_size) return error.InvalidDestinationShape;
        for (0..index) |prior_index| {
            if (overlap(current, destinationAt(destinations, prior_index)))
                return error.OverlappingDestinations;
        }
    }
}

fn destinationAt(destinations: *const MainDestinations, index: usize) []M31 {
    return if (index < caller_main_column_count)
        destinations.caller[index]
    else
        destinations.provider[index - caller_main_column_count];
}

fn overlap(lhs: []const M31, rhs: []const M31) bool {
    const lhs_start = @intFromPtr(lhs.ptr);
    const rhs_start = @intFromPtr(rhs.ptr);
    const lhs_end = lhs_start + lhs.len * @sizeOf(M31);
    const rhs_end = rhs_start + rhs.len * @sizeOf(M31);
    return lhs_start < rhs_end and rhs_start < lhs_end;
}

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

fn validateConstructionAuthority(extension: *const ExtensionStatement) Error!void {
    const registry = components.Registry.forProfile(extension.profile);
    const caller = try registry.verifierConstruction(extension.components[0]);
    switch (caller) {
        .caller => |authority| try authority.validate(),
        else => return error.ConstructionAuthorityMismatch,
    }
    const provider = try registry.verifierConstruction(extension.components[1]);
    switch (provider) {
        .provider => |authority| try authority.validate(),
        else => return error.ConstructionAuthorityMismatch,
    }
}

fn preflightRows(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    records: []const call_buffer.Record,
    rows: []const guest_runner.ExecutionRow,
) Error!void {
    var previous_execution_clock: u32 = 0;
    for (records, rows, 0..) |record, row, index| {
        if (row.call_index != @as(u32, @intCast(index)))
            return error.CallIndexMismatch;
        if (row.execution_clock != record.execution_clock)
            return error.ExecutionClockMismatch;
        if (row.pc != record.pc) return error.PcMismatch;
        if (record.execution_clock == 0 or
            record.execution_clock > core.total_steps or
            access_clock.maximum(record.execution_clock) > std.math.maxInt(u32))
        {
            return error.ExecutionClockOutOfRange;
        }
        if (index != 0 and record.execution_clock <= previous_execution_clock)
            return error.ExecutionOrderMismatch;
        previous_execution_clock = record.execution_clock;

        try isa_profile.requireProgramWordAddress(record.pc);
        const decoded = try custom0.decode(extension.profile, row.inst_word);
        if (decoded.rs1 != record.pointer_register)
            return error.PointerRegisterMismatch;
        try validatePointer(record.state_ptr);

        const pointer_clock = access_clock.encode(record.execution_clock, .first);
        try validatePreviousClock(
            record.pointer_previous_clock,
            pointer_clock,
            error.PointerPreviousClockInvalid,
        );
        const memory_clock = access_clock.encode(record.execution_clock, .second);
        for (record.memory_previous_clocks) |previous_clock| {
            try validatePreviousClock(
                previous_clock,
                memory_clock,
                error.MemoryPreviousClockInvalid,
            );
        }

        for (record.input) |word| {
            if (word >= m31.Modulus) return error.NonCanonicalPrecompileWord;
        }
        for (record.output) |word| {
            if (word >= m31.Modulus) return error.NonCanonicalPrecompileWord;
        }

        // This is intentionally before allocation: a provider/runner drift
        // cannot partially construct or retain a trace owner.
        const provider_row = poseidon2_air.fill(.{
            .input = record.input,
            .wide = false,
            .io = true,
        });
        if (!provider_row[0].isOne() or
            !provider_row[provider_main_column_count - 2].isZero() or
            !provider_row[provider_main_column_count - 1].isOne())
        {
            return error.ProviderModeMismatch;
        }
        const provider_output = poseidon2_air.output(provider_row);
        for (provider_output, record.output) |actual, expected| {
            if (actual.toU32() != expected) return error.ProviderOutputMismatch;
        }
    }
}

fn validatePointer(state_ptr: u32) Error!void {
    if (state_ptr & (isa_profile.instruction_alignment - 1) != 0)
        return error.PrecompileAddressMisaligned;
    const span_end = @as(u64, state_ptr) +
        call_buffer.lane_count * @sizeOf(u32);
    if (span_end > isa_profile.program_commitment_size)
        return error.PrecompileSpanOutOfRange;
}

fn validatePreviousClock(
    previous: u32,
    current: u32,
    comptime invalid: Error,
) Error!void {
    if (previous >= state_chain.CLOCK_PREV_BOUND or previous >= current)
        return invalid;
    const shifted_gap = current - previous - 1;
    if (shifted_gap > state_chain.MAX_CLOCK_DIFF) return invalid;
}

fn fillCaller(record: call_buffer.Record) [caller_main_column_count]M31 {
    const layout = components.caller_layout;
    var row = [_]M31{M31.zero()} ** caller_main_column_count;
    row[layout.enabler] = M31.one();
    row[layout.execution_clock] = M31.fromCanonical(record.execution_clock);
    row[layout.pc] = M31.fromCanonical(record.pc);
    row[layout.pointer_register] = M31.fromCanonical(record.pointer_register);
    row[layout.pointer_previous_clock] =
        M31.fromCanonical(record.pointer_previous_clock);
    writeBytes(&row, layout.pointer_bytes, record.state_ptr);

    const word_index = record.state_ptr / @sizeOf(u32);
    row[layout.pointer_word_index] = M31.fromCanonical(word_index);
    const span_end_word = word_index +
        @as(u32, @intCast(call_buffer.lane_count - 1));
    row[layout.span_end_limbs] = byteFelt(span_end_word, 0);
    row[layout.span_end_limbs + 1] = byteFelt(span_end_word, 8);
    row[layout.span_end_limbs + 2] = byteFelt(span_end_word, 16);
    row[layout.span_end_limbs + 3] = M31.fromCanonical(
        @intCast((span_end_word >> 24) & 0x0f),
    );

    var inverse_prefixes: [32]M31 = undefined;
    var canonical_product = M31.one();
    var canonical_index: usize = 0;
    for (record.input, 0..) |word, lane| {
        writeBytes(&row, layout.inputByte(@intCast(lane), 0), word);
        inverse_prefixes[canonical_index] = canonical_product;
        canonical_product = canonical_product.mul(writeCanonicalBase(
            &row,
            false,
            @intCast(lane),
            word,
        ));
        canonical_index += 1;
    }
    for (record.output, 0..) |word, lane| {
        writeBytes(&row, layout.outputByte(@intCast(lane), 0), word);
        inverse_prefixes[canonical_index] = canonical_product;
        canonical_product = canonical_product.mul(writeCanonicalBase(
            &row,
            true,
            @intCast(lane),
            word,
        ));
        canonical_index += 1;
    }
    std.debug.assert(canonical_index == inverse_prefixes.len);

    // Montgomery's trick: all 32 canonicality inverses cost one field
    // inversion and a fixed number of multiplications, with no row allocation.
    var inverse_suffix = canonical_product.invUncheckedNonZero();
    while (canonical_index != 0) {
        canonical_index -= 1;
        const output = canonical_index >= call_buffer.lane_count;
        const lane: u8 = @intCast(canonical_index % call_buffer.lane_count);
        const nz_column = layout.canonicalMaterialization(output, lane, 2);
        const inverse_column = layout.canonicalMaterialization(output, lane, 3);
        row[inverse_column] = inverse_suffix.mul(inverse_prefixes[canonical_index]);
        inverse_suffix = inverse_suffix.mul(row[nz_column]);
    }
    std.debug.assert(inverse_suffix.isOne());
    for (record.memory_previous_clocks, 0..) |clock, lane| {
        row[layout.previousClock(@intCast(lane))] = M31.fromCanonical(clock);
    }
    return row;
}

fn writeBytes(
    row: *[caller_main_column_count]M31,
    start: usize,
    word: u32,
) void {
    inline for (0..4) |byte| {
        row[start + byte] = byteFelt(word, @intCast(byte * 8));
    }
}

inline fn byteFelt(word: u32, shift: u5) M31 {
    return M31.fromCanonical(@intCast((word >> shift) & 0xff));
}

fn writeCanonicalBase(
    row: *[caller_main_column_count]M31,
    output: bool,
    lane: u8,
    word: u32,
) M31 {
    const values = canonicalBase(word);
    inline for (0..3) |index| {
        row[
            components.caller_layout.canonicalMaterialization(
                output,
                lane,
                index,
            )
        ] = values[index];
    }
    return values[2];
}

fn canonicalBase(word: u32) [3]M31 {
    const bytes = [4]M31{
        byteFelt(word, 0),
        byteFelt(word, 8),
        byteFelt(word, 16),
        byteFelt(word, 24),
    };
    const d0 = bytes[0].sub(M31.fromCanonical(255));
    const d1 = bytes[1].sub(M31.fromCanonical(255));
    const d2 = bytes[2].sub(M31.fromCanonical(255));
    const d3 = bytes[3].sub(M31.fromCanonical(127));
    const s0 = d0.square().add(d1.square());
    const s1 = d2.square().add(d3.square());
    const nz = s0.square().add(s1.square());
    std.debug.assert(!nz.isZero());
    return .{ s0, s1, nz };
}

comptime {
    if (components.preprocessed_columns != selector_columns_per_component or
        components.extension_component_count != 2)
    {
        @compileError("guest selector geometry drifted");
    }
    if (caller_main_column_count != 286 or
        provider_main_column_count != poseidon2_air.N_MAIN_COLUMNS or
        provider_main_column_count != 445)
    {
        @compileError("guest main-trace geometry drifted");
    }
    if (caller_preprocessed_start != 0 or provider_preprocessed_start != 2 or
        caller_main_start != 4 or provider_main_start != 290 or
        total_column_count != 735 or
        provider_main_start + provider_main_column_count != total_column_count)
    {
        @compileError("guest contiguous column offsets overlap or drifted");
    }
}
