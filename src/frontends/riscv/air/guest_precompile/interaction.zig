//! Shared-challenge LogUp interaction generation for guest Poseidon2.
//!
//! Every tuple is reconstructed from the committed C-007 main trace. Frozen
//! runner records are unavailable here: caller and provider claims can balance
//! only through committed columns and the profile-scoped guest challenge pair.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const logup = @import("../logup.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const riscv_statement = @import("../statement.zig");
const components = @import("component_registry.zig");
const main_trace = @import("main_trace.zig");
const challenges = @import("relation_challenges.zig");
const interaction_plan = @import("interaction_plan.zig");
const statement_mod = @import("statement.zig");

const RiscVStatement = riscv_statement.RiscVStatement;
const ExtensionStatement = statement_mod.ExtensionStatement;
const Relations = challenges.Poseidon2V1Relations;

pub const caller_event_count = interaction_plan.caller_event_count;
pub const caller_batch_count = interaction_plan.caller_batch_count;
pub const provider_event_count = interaction_plan.provider_event_count;
pub const provider_batch_count = interaction_plan.provider_batch_count;
pub const caller_column_count = interaction_plan.caller_column_count;
pub const provider_column_count = interaction_plan.provider_column_count;
pub const total_batch_count = interaction_plan.total_batch_count;
pub const total_column_count = interaction_plan.total_column_count;
pub const chunk_rows: usize = 256;

const caller_column_start: usize = 0;
const provider_column_start: usize = caller_column_count;
const caller_relation_source_columns =
    interaction_plan.caller_relation_source_columns;
const provider_input_start: usize = 1;
const provider_output_start: usize = 1 + poseidon2_air.N_TEMPORARIES;
const provider_wide_column: usize = poseidon2_air.N_MAIN_COLUMNS - 2;
const provider_io_column: usize = poseidon2_air.N_MAIN_COLUMNS - 1;
const output_column_starts = interaction_plan.output_column_starts;

pub const Error = statement_mod.Error || interaction_plan.Error || error{
    OutOfMemory,
    TraceSizeOverflow,
    MainTraceSelectorMismatch,
    UnbalancedGuestRelation,
    InvalidDestinationShape,
    OverlappingDestinations,
};

pub const Entry = interaction_plan.Entry;

pub const Destinations = struct {
    caller: [caller_column_count][]M31,
    provider: [provider_column_count][]M31,
};

pub const Claims = struct {
    caller: [caller_batch_count]QM31,
    provider: [provider_batch_count]QM31,

    pub fn callerTotal(self: *const Claims) QM31 {
        return sumClaims(&self.caller);
    }

    pub fn providerTotal(self: *const Claims) QM31 {
        return sumClaims(&self.provider);
    }

    pub fn guestRelationTotal(self: *const Claims) QM31 {
        return self.caller[caller_batch_count - 1]
            .add(self.provider[provider_batch_count - 1]);
    }

    pub fn verifyGuestCancellation(self: *const Claims) Error!void {
        if (!self.guestRelationTotal().isZero())
            return error.UnbalancedGuestRelation;
    }
};

/// One allocation containing caller then provider committed interaction rows.
pub const Result = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,
    caller_claims: [caller_batch_count]QM31,
    provider_claims: [provider_batch_count]QM31,

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

    pub fn callerColumn(self: *const Result, index: usize) []const M31 {
        std.debug.assert(index < caller_column_count);
        return self.column(caller_column_start + index);
    }

    pub fn providerColumn(self: *const Result, index: usize) []const M31 {
        std.debug.assert(index < provider_column_count);
        return self.column(provider_column_start + index);
    }

    pub fn mutableDestinations(self: *Result) Destinations {
        var destinations: Destinations = undefined;
        for (&destinations.caller, 0..) |*destination, index| {
            destination.* = @constCast(self.callerColumn(index));
        }
        for (&destinations.provider, 0..) |*destination, index| {
            destination.* = @constCast(self.providerColumn(index));
        }
        return destinations;
    }

    pub fn callerTotal(self: *const Result) QM31 {
        return sumClaims(&self.caller_claims);
    }

    pub fn providerTotal(self: *const Result) QM31 {
        return sumClaims(&self.provider_claims);
    }

    pub fn guestRelationTotal(self: *const Result) QM31 {
        return self.caller_claims[caller_batch_count - 1]
            .add(self.provider_claims[provider_batch_count - 1]);
    }

    pub fn verifyGuestCancellation(self: *const Result) Error!void {
        if (!self.guestRelationTotal().isZero())
            return error.UnbalancedGuestRelation;
    }

    fn column(self: *const Result, index: usize) []const M31 {
        const start = index * self.domain_size;
        return self.storage[start..][0..self.domain_size];
    }

    fn write(self: *Result, column_index: usize, row: usize, value: M31) void {
        self.storage[column_index * self.domain_size + row] = value;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    main: *const main_trace.Result,
    relations: *const Relations,
) Error!Result {
    try extension.validate(core);
    try validateConstructionAuthority(extension);
    const geometry = try preflightGeometry(extension, main);

    const output_cells = std.math.mul(
        usize,
        total_column_count,
        geometry.domain_size,
    ) catch return error.TraceSizeOverflow;
    _ = std.math.mul(usize, output_cells, @sizeOf(M31)) catch
        return error.TraceSizeOverflow;
    const storage = try allocator.alloc(M31, output_cells);
    errdefer allocator.free(storage);
    var result = Result{
        .allocator = allocator,
        .storage = storage,
        .log_size = geometry.log_size,
        .n_rows = main.n_rows,
        .domain_size = geometry.domain_size,
        .caller_claims = .{QM31.zero()} ** caller_batch_count,
        .provider_claims = .{QM31.zero()} ** provider_batch_count,
    };
    var destinations = result.mutableDestinations();
    const claims = try generatePreparedInto(
        allocator,
        main,
        relations,
        geometry,
        &destinations,
    );
    result.caller_claims = claims.caller;
    result.provider_claims = claims.provider;
    return result;
}

/// Generate Tree-2 values directly into final owned column storage from the
/// compact post-Tree-1 projection. Destination validation and scratch sizing
/// finish before the first output cell is written.
pub fn generateFromRelationSourceInto(
    allocator: std.mem.Allocator,
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    main: *const main_trace.RelationSource,
    relations: *const Relations,
    destinations: *const Destinations,
) Error!Claims {
    try extension.validate(core);
    try validateConstructionAuthority(extension);
    const geometry = try preflightRelationSource(extension, main);
    try validateDestinations(destinations, geometry.domain_size);
    return generatePreparedInto(
        allocator,
        main,
        relations,
        geometry,
        destinations,
    );
}

fn generatePreparedInto(
    allocator: std.mem.Allocator,
    main: anytype,
    relations: *const Relations,
    geometry: Geometry,
    output_destinations: *const Destinations,
) Error!Claims {
    try validateDestinations(output_destinations, geometry.domain_size);
    const chunk_capacity = @min(chunk_rows, geometry.domain_size);
    const scratch_rows = @min(chunk_rows, @as(usize, main.n_rows));
    const term_capacity = std.math.mul(
        usize,
        total_batch_count,
        scratch_rows,
    ) catch return error.TraceSizeOverflow;
    const scratch_cells = std.math.mul(usize, term_capacity, 3) catch
        return error.TraceSizeOverflow;
    _ = std.math.mul(usize, scratch_cells, @sizeOf(QM31)) catch
        return error.TraceSizeOverflow;
    const scratch = try allocator.alloc(QM31, scratch_cells);
    defer allocator.free(scratch);
    const numerators = scratch[0..term_capacity];
    const denominators = scratch[term_capacity..][0..term_capacity];
    const inverses = scratch[2 * term_capacity ..][0..term_capacity];

    var accumulators = [_]QM31{QM31.zero()} ** total_batch_count;
    var row_destinations: [chunk_rows]usize = undefined;

    var row_start: usize = 0;
    while (row_start < main.n_rows) {
        const chunk_len = @min(chunk_capacity, main.n_rows - row_start);
        const term_len = total_batch_count * chunk_len;
        for (0..chunk_len) |local_row| {
            row_destinations[local_row] = main_trace.committedRow(
                row_start + local_row,
                geometry.log_size,
            );
            setActiveTerms(
                main,
                relations,
                row_destinations[local_row],
                numerators,
                denominators,
                chunk_len,
                local_row,
            );
        }
        fields.batchInverseInPlace(
            QM31,
            denominators[0..term_len],
            inverses[0..term_len],
        ) catch return error.ZeroDenominator;

        for (0..total_batch_count) |batch| {
            const output_column = output_column_starts[batch];
            for (0..chunk_len) |local_row| {
                const term_index = batch * chunk_len + local_row;
                accumulators[batch] = accumulators[batch].add(
                    numerators[term_index].mul(inverses[term_index]),
                );
                const coordinates = accumulators[batch].toM31Array();
                for (coordinates, 0..) |coordinate, index| {
                    writeDestination(
                        output_destinations,
                        output_column + index,
                        row_destinations[local_row],
                        coordinate,
                    );
                }
            }
        }
        row_start += chunk_len;
    }

    // Padding extends final prefixes directly and never evaluates a relation
    // denominator or enters the batch-inversion hot path.
    while (row_start < geometry.domain_size) {
        const chunk_len = @min(chunk_capacity, geometry.domain_size - row_start);
        for (0..chunk_len) |local_row| {
            row_destinations[local_row] = main_trace.committedRow(
                row_start + local_row,
                geometry.log_size,
            );
        }
        for (0..total_batch_count) |batch| {
            const coordinates = accumulators[batch].toM31Array();
            const output_column = output_column_starts[batch];
            for (0..chunk_len) |local_row| {
                for (coordinates, 0..) |coordinate, index| {
                    writeDestination(
                        output_destinations,
                        output_column + index,
                        row_destinations[local_row],
                        coordinate,
                    );
                }
            }
        }
        row_start += chunk_len;
    }

    return .{
        .caller = accumulators[0..caller_batch_count].*,
        .provider = accumulators[caller_batch_count..][0..provider_batch_count].*,
    };
}

pub const callerEntry = interaction_plan.callerEntry;
pub const providerEntry = interaction_plan.providerEntry;
pub const callerRowPairs = interaction_plan.callerRowPairs;
pub const providerRowPairs = interaction_plan.providerRowPairs;

pub fn callerInteractionConstraints(
    main: []const QM31,
    is_first: QM31,
    sums: [caller_batch_count]QM31,
    previous: [caller_batch_count]QM31,
    claims: [caller_batch_count]QM31,
    relations: *const Relations,
) Error![caller_batch_count]QM31 {
    const pairs = try callerRowPairs(main, relations);
    var result: [caller_batch_count]QM31 = undefined;
    for (&result, pairs, sums, previous, claims) |*constraint, pair, sum, prev, claim| {
        constraint.* = logup.pairConstraint(sum, prev, is_first, claim, pair);
    }
    return result;
}

pub fn providerInteractionConstraints(
    main: []const QM31,
    is_first: QM31,
    sums: [provider_batch_count]QM31,
    previous: [provider_batch_count]QM31,
    claims: [provider_batch_count]QM31,
    relations: *const Relations,
) Error![provider_batch_count]QM31 {
    const pairs = try providerRowPairs(main, relations);
    var result: [provider_batch_count]QM31 = undefined;
    for (&result, pairs, sums, previous, claims) |*constraint, pair, sum, prev, claim| {
        constraint.* = logup.pairConstraint(sum, prev, is_first, claim, pair);
    }
    return result;
}

const Geometry = struct { log_size: u32, domain_size: usize };

fn preflightGeometry(
    extension: *const ExtensionStatement,
    main: *const main_trace.Result,
) Error!Geometry {
    const log_size = extension.components[0].log_size;
    if (log_size >= @bitSizeOf(usize)) return error.TraceSizeOverflow;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    const expected_cells = std.math.mul(
        usize,
        main_trace.total_column_count,
        domain_size,
    ) catch return error.TraceSizeOverflow;
    if (extension.components[1].log_size != log_size or
        main.log_size != log_size or
        main.n_rows != extension.counts.n_guest or
        main.domainSize() != domain_size or
        main.committedCells().len != expected_cells)
    {
        return error.InvalidMainTraceShape;
    }
    for (0..domain_size) |logical_row| {
        const dst = main_trace.committedRow(logical_row, log_size);
        const first = M31.fromCanonical(@intFromBool(logical_row == 0));
        const active = M31.fromCanonical(@intFromBool(logical_row < main.n_rows));
        if (!main.callerPreprocessed(0)[dst].eql(first) or
            !main.providerPreprocessed(0)[dst].eql(first) or
            !main.callerPreprocessed(1)[dst].eql(active) or
            !main.providerPreprocessed(1)[dst].eql(active))
        {
            return error.MainTraceSelectorMismatch;
        }
    }
    return .{ .log_size = log_size, .domain_size = domain_size };
}

fn preflightRelationSource(
    extension: *const ExtensionStatement,
    main: *const main_trace.RelationSource,
) Error!Geometry {
    const log_size = extension.components[0].log_size;
    if (log_size >= @bitSizeOf(usize)) return error.TraceSizeOverflow;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    const expected_cells = std.math.mul(
        usize,
        main_trace.relation_source_column_count,
        domain_size,
    ) catch return error.TraceSizeOverflow;
    if (extension.components[1].log_size != log_size or
        main.log_size != log_size or
        main.n_rows != extension.counts.n_guest or
        main.domainSize() != domain_size or
        main.committedCells().len != expected_cells)
    {
        return error.InvalidMainTraceShape;
    }
    return .{ .log_size = log_size, .domain_size = domain_size };
}

fn validateDestinations(
    destinations: *const Destinations,
    domain_size: usize,
) Error!void {
    for (0..total_column_count) |index| {
        const current = destinationAt(destinations, index);
        if (current.len != domain_size) return error.InvalidDestinationShape;
        for (0..index) |prior_index| {
            if (overlap(current, destinationAt(destinations, prior_index)))
                return error.OverlappingDestinations;
        }
    }
}

fn destinationAt(destinations: *const Destinations, index: usize) []M31 {
    return if (index < caller_column_count)
        destinations.caller[index]
    else
        destinations.provider[index - caller_column_count];
}

fn writeDestination(
    destinations: *const Destinations,
    column_index: usize,
    row: usize,
    value: M31,
) void {
    destinationAt(destinations, column_index)[row] = value;
}

fn overlap(lhs: []const M31, rhs: []const M31) bool {
    const lhs_start = @intFromPtr(lhs.ptr);
    const rhs_start = @intFromPtr(rhs.ptr);
    const lhs_end = lhs_start + lhs.len * @sizeOf(M31);
    const rhs_end = rhs_start + rhs.len * @sizeOf(M31);
    return lhs_start < rhs_end and rhs_start < lhs_end;
}

fn validateConstructionAuthority(extension: *const ExtensionStatement) Error!void {
    const authority = components.Registry.forProfile(extension.profile);
    const caller = try authority.verifierConstruction(extension.components[0]);
    switch (caller) {
        .caller => |value| try value.validate(),
        else => return error.ConstructionAuthorityMismatch,
    }
    const provider = try authority.verifierConstruction(extension.components[1]);
    switch (provider) {
        .provider => |value| try value.validate(),
        else => return error.ConstructionAuthorityMismatch,
    }
}

fn setActiveTerms(
    main: anytype,
    relations: *const Relations,
    committed_row: usize,
    numerators: []QM31,
    denominators: []QM31,
    chunk_len: usize,
    local_row: usize,
) void {
    var caller_source: [caller_relation_source_columns]M31 = undefined;
    for (&caller_source, 0..) |*value, column| {
        value.* = main.callerMain(column)[committed_row];
    }
    interaction_plan.writeCallerGenerationTerms(
        &caller_source,
        relations,
        numerators,
        denominators,
        chunk_len,
        local_row,
    );

    var provider_input: [16]M31 = undefined;
    var provider_output: [16]M31 = undefined;
    for (&provider_input, &provider_output, 0..) |*input, *output, lane| {
        input.* = main.providerMain(provider_input_start + lane)[committed_row];
        output.* = main.providerMain(provider_output_start + lane)[committed_row];
    }
    const provider_term = interaction_plan.providerGuestGenerationTerm(
        main.providerMain(0)[committed_row],
        provider_input,
        provider_output,
        relations,
    );
    const zero_batch = caller_batch_count + components.provider_batches[0].ordinal;
    const guest_batch = caller_batch_count + components.provider_batches[1].ordinal;
    const zero_index = zero_batch * chunk_len + local_row;
    numerators[zero_index] = QM31.zero();
    denominators[zero_index] = QM31.one();
    interaction_plan.writeNormalizedTerm(
        logup.RowPair.single(provider_term.numerator, provider_term.denominator),
        &numerators[guest_batch * chunk_len + local_row],
        &denominators[guest_batch * chunk_len + local_row],
    );
}

fn sumClaims(claims: []const QM31) QM31 {
    var result = QM31.zero();
    for (claims) |claim| result = result.add(claim);
    return result;
}

comptime {
    if (caller_event_count != 153 or caller_batch_count != 77 or
        provider_event_count != 4 or provider_batch_count != 2 or
        caller_column_count != 308 or provider_column_count != 8 or
        total_column_count != 316)
    {
        @compileError("guest interaction geometry drifted");
    }
    if (caller_relation_source_columns != 158 or provider_input_start != 1 or
        provider_output_start != 427 or provider_wide_column != 443 or
        provider_io_column != 444)
    {
        @compileError("guest interaction source placement drifted");
    }
    if (components.caller_batches[caller_batch_count - 1].first_event != 152 or
        components.caller_batches[caller_batch_count - 1].second_event != null or
        components.provider_batches[1].first_event != 2 or
        components.provider_batches[1].second_event != 3)
    {
        @compileError("guest source/supply claim wiring drifted");
    }
}
