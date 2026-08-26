//! Challenge-independent tuple-closure diagnosis for the 38-row SegmentV2
//! outer cohort.
//!
//! The proof path first identifies non-zero relation domains algebraically.
//! This cold tool then groups the exact authenticated tuples in only those
//! domains. It never inserts a balancing tuple: every contribution must name
//! a committed cohort row or the single committed row-34 shared provider.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const air = frontend.recursion.air;
const relation_interaction = air.relation_interaction;
const roster = air.universal_roster;

pub const TupleLedger = relation_interaction.TupleLedger;
pub const TupleContribution = relation_interaction.TupleContribution;
pub const TupleClosureReport = relation_interaction.TupleClosureReport;
pub const RelationDomain = @TypeOf(@as(TupleContribution, undefined).domain);
pub const RelationRole = @TypeOf(@as(TupleContribution, undefined).role);

pub const COMPONENT_COUNT: usize = 38;
pub const VERBOSE_ENV = "STWO_RECURSION_OUTER_TUPLE_VERBOSE";
pub const RED_DOMAIN_MASK: u64 =
    domainBit(.poseidon2_io) |
    domainBit(.recursion_wire) |
    domainBit(.recursion_step) |
    domainBit(.recursion_transcript_digest_state) |
    domainBit(.recursion_verifier_input_word) |
    domainBit(.recursion_verifier_randomness_word);

pub const AuthorityClass = enum(u8) {
    transcript_rows,
    statement_rows,
    public_rows,
    verifier_core_rows,
    shared_poseidon_provider,
    range_provider,
    statement_boundary,
    public_logup_boundary,
};

pub const ResidualKind = enum(u8) {
    missing_emitter,
    missing_consumer,
    multiplicity_mismatch,
};

/// The protocol seam that must supply the absent side of an unmatched group.
/// This is deliberately a domain-level classification. `Provenance` retains
/// the exact rows and events already present, so callers can distinguish a
/// genuinely absent authority from a tuple/multiplicity drift between two
/// authorities without the diagnostic inventing a repair.
pub const ExpectedCounterpart = enum(u8) {
    poseidon_provider,
    poseidon_request,
    wire_emitter,
    wire_consumer,
    step_emitter,
    step_consumer,
    transcript_digest_state_peer,
    verifier_input_publisher,
    verifier_input_consumer,
    verifier_randomness_publisher,
    verifier_randomness_consumer,
    cross_authority_multiplicity,
};

pub const Provenance = struct {
    component: u8,
    event: u8,
    role: RelationRole,
    authority: AuthorityClass,
    signed_weight: QM31,
};

pub const UnmatchedGroup = struct {
    domain: RelationDomain,
    arity: u8,
    tuple_prefix: [relation_interaction.TUPLE_DIAGNOSTIC_PREFIX_ARITY]QM31,
    tuple_hash: [32]u8,
    residual: QM31,
    kind: ResidualKind,
    expected_counterpart: ExpectedCounterpart,
    component_mask: u64,
    provenance_offset: usize,
    provenance_count: usize,
};

pub const Report = struct {
    allocator: std.mem.Allocator,
    domain_mask: u64,
    closure: TupleClosureReport,
    groups: []UnmatchedGroup,
    provenance: []Provenance,

    pub fn deinit(self: *Report) void {
        self.allocator.free(self.provenance);
        self.allocator.free(self.groups);
        self.* = undefined;
    }

    /// Concise authority-level classifier. Classes deliberately ignore tuple
    /// hashes and field multiplicities while retaining the exact ordered
    /// row/event/role provenance signature. This turns thousands of concrete
    /// tuple failures into the small set of authority seams that can fix them.
    /// Set `STWO_RECURSION_OUTER_TUPLE_VERBOSE=1` to append every tuple group.
    pub fn print(self: *const Report) void {
        self.printConcise();
        if (std.process.hasEnvVarConstant(VERBOSE_ENV)) self.printVerbose();
    }

    pub fn printConcise(self: *const Report) void {
        std.debug.print(
            "SegmentV2 exact tuple closure: mask=0x{x} contributions={d} unmatched={d} red_domains={d}\n",
            .{
                self.domain_mask,
                self.closure.contribution_count,
                self.closure.unmatched_tuple_count,
                self.closure.redDomainCount(),
            },
        );

        var class_count: usize = 0;
        for (self.groups, 0..) |group, index| {
            if (hasPriorClass(self, index)) continue;
            class_count += 1;
            var group_count: usize = 0;
            var contribution_count: usize = 0;
            var net_residual = QM31.zero();
            var emit_total = QM31.zero();
            var demand_total = QM31.zero();
            var representative_count: usize = 0;
            var representatives: [3][32]u8 = undefined;
            for (self.groups[index..]) |candidate| {
                if (!sameClass(self, &group, &candidate)) continue;
                group_count += 1;
                contribution_count += candidate.provenance_count;
                net_residual = net_residual.add(candidate.residual);
                const first = candidate.provenance_offset;
                const end = first + candidate.provenance_count;
                for (self.provenance[first..end]) |item| switch (item.role) {
                    .emit => emit_total = emit_total.add(item.signed_weight),
                    .request, .consume => demand_total = demand_total.sub(
                        item.signed_weight,
                    ),
                };
                if (representative_count < representatives.len) {
                    representatives[representative_count] = candidate.tuple_hash;
                    representative_count += 1;
                }
            }
            std.debug.print(
                "  class domain={s} kind={s} expected={s} rows=0x{x} groups={d} contributions={d} emit={any} demand={any} net={any}\n",
                .{
                    @tagName(group.domain),
                    @tagName(group.kind),
                    @tagName(group.expected_counterpart),
                    group.component_mask,
                    group_count,
                    contribution_count,
                    emit_total.toM31Array(),
                    demand_total.toM31Array(),
                    net_residual.toM31Array(),
                },
            );
            std.debug.print("    provenance=", .{});
            printProvenanceSignature(self, &group);
            std.debug.print("\n    representative_hashes=", .{});
            for (representatives[0..representative_count], 0..) |
                tuple_hash,
                representative_index,
            | {
                if (representative_index != 0) std.debug.print(",", .{});
                const tuple_hex = std.fmt.bytesToHex(tuple_hash, .lower);
                std.debug.print("{s}", .{&tuple_hex});
            }
            std.debug.print("\n", .{});
            if (group_count <= 3 and
                group.arity <= relation_interaction.TUPLE_DIAGNOSTIC_PREFIX_ARITY)
            {
                std.debug.print("    representative_tuples=", .{});
                var printed: usize = 0;
                for (self.groups[index..]) |candidate| {
                    if (!sameClass(self, &group, &candidate)) continue;
                    if (printed != 0) std.debug.print(";", .{});
                    printTuplePrefix(&candidate);
                    printed += 1;
                    if (printed == 3) break;
                }
                std.debug.print("\n", .{});
            }
        }
        std.debug.print(
            "SegmentV2 tuple authority classes: {d} (verbose: {s}=1)\n",
            .{ class_count, VERBOSE_ENV },
        );
    }

    pub fn printVerbose(self: *const Report) void {
        std.debug.print("SegmentV2 verbose unmatched tuple groups:\n", .{});
        for (self.groups) |group| {
            const tuple_hex = std.fmt.bytesToHex(group.tuple_hash, .lower);
            std.debug.print(
                "  domain={s} tuple={s} residual={any} class={s} expected={s} rows=0x{x}\n",
                .{
                    @tagName(group.domain),
                    &tuple_hex,
                    group.residual.toM31Array(),
                    @tagName(group.kind),
                    @tagName(group.expected_counterpart),
                    group.component_mask,
                },
            );
            const first = group.provenance_offset;
            const end = first + group.provenance_count;
            for (self.provenance[first..end]) |item| std.debug.print(
                "    row={d}:{s} authority={s} event={d} role={s} signed={any}\n",
                .{
                    item.component,
                    componentName(item.component),
                    @tagName(item.authority),
                    item.event,
                    @tagName(item.role),
                    item.signed_weight.toM31Array(),
                },
            );
        }
    }
};

fn hasPriorClass(report: *const Report, index: usize) bool {
    for (report.groups[0..index]) |prior|
        if (sameClass(report, &report.groups[index], &prior)) return true;
    return false;
}

fn sameClass(
    report: *const Report,
    lhs: *const UnmatchedGroup,
    rhs: *const UnmatchedGroup,
) bool {
    if (lhs.domain != rhs.domain or
        lhs.kind != rhs.kind or
        lhs.expected_counterpart != rhs.expected_counterpart or
        lhs.component_mask != rhs.component_mask or
        lhs.provenance_count != rhs.provenance_count)
    {
        return false;
    }
    const lhs_items = report.provenance[lhs.provenance_offset .. lhs.provenance_offset + lhs.provenance_count];
    const rhs_items = report.provenance[rhs.provenance_offset .. rhs.provenance_offset + rhs.provenance_count];
    for (lhs_items, rhs_items) |left, right| {
        if (left.component != right.component or
            left.event != right.event or left.role != right.role)
        {
            return false;
        }
    }
    return true;
}

fn printProvenanceSignature(
    report: *const Report,
    group: *const UnmatchedGroup,
) void {
    const first = group.provenance_offset;
    const end = first + group.provenance_count;
    const items = report.provenance[first..end];
    var cursor: usize = 0;
    while (cursor < items.len) {
        var run_end = cursor + 1;
        while (run_end < items.len and
            items[run_end].component == items[cursor].component and
            items[run_end].event == items[cursor].event and
            items[run_end].role == items[cursor].role)
        {
            run_end += 1;
        }
        if (cursor != 0) std.debug.print(",", .{});
        std.debug.print(
            "{d}:{s}/e{d}/{s}",
            .{
                items[cursor].component,
                componentName(items[cursor].component),
                items[cursor].event,
                @tagName(items[cursor].role),
            },
        );
        if (run_end - cursor != 1)
            std.debug.print("*{d}", .{run_end - cursor});
        cursor = run_end;
    }
}

/// Sorts `ledger` in-place, then copies only unmatched groups and their exact
/// row/event provenance into an owned report. The ledger is intentionally
/// supplied by the cohort owner so this function has no path to detached or
/// caller-fabricated AIR rows.
pub fn classify(
    allocator: std.mem.Allocator,
    ledger: *TupleLedger,
    domain_mask: u64,
) !Report {
    if (domain_mask == 0 or domain_mask & ~RED_DOMAIN_MASK != 0)
        return error.InvalidDiagnosticDomainMask;
    const closure = ledger.classify();
    const items = ledger.contributions.items;

    var group_count: usize = 0;
    var provenance_count: usize = 0;
    var cursor: usize = 0;
    while (cursor < items.len) {
        const end = groupEnd(items, cursor);
        if (!groupResidual(items[cursor..end]).isZero()) {
            group_count += 1;
            provenance_count = try std.math.add(
                usize,
                provenance_count,
                end - cursor,
            );
        }
        cursor = end;
    }
    if (group_count != closure.unmatched_tuple_count)
        return error.TupleClassifierMismatch;

    const groups = try allocator.alloc(UnmatchedGroup, group_count);
    errdefer allocator.free(groups);
    const provenance = try allocator.alloc(Provenance, provenance_count);
    errdefer allocator.free(provenance);

    cursor = 0;
    var group_index: usize = 0;
    var provenance_index: usize = 0;
    while (cursor < items.len) {
        const end = groupEnd(items, cursor);
        const entries = items[cursor..end];
        const residual = groupResidual(entries);
        if (!residual.isZero()) {
            var has_emit = false;
            var has_consumer = false;
            var component_mask: u64 = 0;
            const provenance_offset = provenance_index;
            for (entries) |entry| {
                if (entry.component >= COMPONENT_COUNT)
                    return error.InvalidDiagnosticComponent;
                component_mask |= componentBit(entry.component);
                switch (entry.role) {
                    .emit => has_emit = true,
                    .request, .consume => has_consumer = true,
                }
                provenance[provenance_index] = .{
                    .component = entry.component,
                    .event = entry.event,
                    .role = entry.role,
                    .authority = authorityForComponent(entry.component),
                    .signed_weight = entry.signed_weight,
                };
                provenance_index += 1;
            }
            const kind: ResidualKind = if (!has_emit)
                .missing_emitter
            else if (!has_consumer)
                .missing_consumer
            else
                .multiplicity_mismatch;
            groups[group_index] = .{
                .domain = entries[0].domain,
                .arity = entries[0].arity,
                .tuple_prefix = entries[0].tuple_prefix,
                .tuple_hash = entries[0].tuple_hash,
                .residual = residual,
                .kind = kind,
                .expected_counterpart = expectedCounterpart(
                    entries[0].domain,
                    kind,
                ),
                .component_mask = component_mask,
                .provenance_offset = provenance_offset,
                .provenance_count = entries.len,
            };
            group_index += 1;
        }
        cursor = end;
    }
    if (group_index != groups.len or provenance_index != provenance.len)
        return error.TupleClassifierMismatch;
    return .{
        .allocator = allocator,
        .domain_mask = domain_mask,
        .closure = closure,
        .groups = groups,
        .provenance = provenance,
    };
}

fn printTuplePrefix(group: *const UnmatchedGroup) void {
    std.debug.print("[", .{});
    for (group.tuple_prefix[0..group.arity], 0..) |value, index| {
        if (index != 0) std.debug.print(",", .{});
        const limbs = value.toM31Array();
        if (limbs[1].isZero() and limbs[2].isZero() and limbs[3].isZero()) {
            std.debug.print("{d}", .{limbs[0].toU32()});
        } else {
            std.debug.print(
                "({d}/{d}/{d}/{d})",
                .{
                    limbs[0].toU32(),
                    limbs[1].toU32(),
                    limbs[2].toU32(),
                    limbs[3].toU32(),
                },
            );
        }
    }
    std.debug.print("] net={any}", .{group.residual.toM31Array()});
}

fn groupEnd(items: []const TupleContribution, first: usize) usize {
    var end = first + 1;
    while (end < items.len and
        items[end].domain == items[first].domain and
        std.mem.eql(u8, &items[end].tuple_hash, &items[first].tuple_hash))
    {
        end += 1;
    }
    return end;
}

fn groupResidual(items: []const TupleContribution) QM31 {
    var result = QM31.zero();
    for (items) |entry| result = result.add(entry.signed_weight);
    return result;
}

fn expectedCounterpart(
    domain: RelationDomain,
    kind: ResidualKind,
) ExpectedCounterpart {
    if (kind == .multiplicity_mismatch)
        return .cross_authority_multiplicity;
    return switch (domain) {
        .poseidon2_io => if (kind == .missing_emitter)
            .poseidon_provider
        else
            .poseidon_request,
        .recursion_wire => if (kind == .missing_emitter)
            .wire_emitter
        else
            .wire_consumer,
        .recursion_step => if (kind == .missing_emitter)
            .step_emitter
        else
            .step_consumer,
        .recursion_transcript_digest_state => .transcript_digest_state_peer,
        .recursion_verifier_input_word => if (kind == .missing_emitter)
            .verifier_input_publisher
        else
            .verifier_input_consumer,
        .recursion_verifier_randomness_word => if (kind == .missing_emitter)
            .verifier_randomness_publisher
        else
            .verifier_randomness_consumer,
        else => unreachable,
    };
}

fn authorityForComponent(component: u8) AuthorityClass {
    return switch (component) {
        0...9 => .transcript_rows,
        10, 11 => .statement_rows,
        12...17 => .public_rows,
        18...33 => .verifier_core_rows,
        34 => .shared_poseidon_provider,
        35 => .range_provider,
        36 => .statement_boundary,
        37 => .public_logup_boundary,
        else => unreachable,
    };
}

fn componentName(component: u8) []const u8 {
    if (component < roster.COMPONENT_COUNT)
        return roster.DESCRIPTORS[component].name;
    return switch (component) {
        36 => "statement_source_v2",
        37 => "public_logup_source_v2",
        else => "invalid",
    };
}

fn domainBit(comptime domain: RelationDomain) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(domain)));
}

fn componentBit(component: u8) u64 {
    return @as(u64, 1) << @as(u6, @intCast(component));
}

comptime {
    if (COMPONENT_COUNT != roster.COMPONENT_COUNT + 2)
        @compileError("SegmentV2 diagnostic roster drifted");
    if (RED_DOMAIN_MASK & domainBit(.range_check_8_8) != 0)
        @compileError("red-domain tuple diagnostic unexpectedly includes row 35");
}

test "SegmentV2 tuple classifier preserves exact unmatched provenance" {
    var ledger = TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    const one = QM31.one();
    const two = QM31.fromBase(M31.fromCanonical(2));
    const missing_emit = [_]QM31{QM31.fromBase(M31.fromCanonical(11))};
    const missing_emit_peer = [_]QM31{QM31.fromBase(M31.fromCanonical(14))};
    const missing_consume = [_]QM31{QM31.fromBase(M31.fromCanonical(12))};
    const mismatch = [_]QM31{QM31.fromBase(M31.fromCanonical(13))};
    try ledger.append(
        .recursion_wire,
        18,
        0,
        .consume,
        one.neg(),
        &missing_emit,
    );
    try ledger.append(
        .recursion_wire,
        18,
        0,
        .consume,
        one.neg(),
        &missing_emit_peer,
    );
    try ledger.append(
        .recursion_wire,
        30,
        0,
        .emit,
        one,
        &missing_consume,
    );
    try ledger.append(
        .recursion_wire,
        31,
        0,
        .consume,
        two.neg(),
        &mismatch,
    );
    try ledger.append(
        .recursion_wire,
        32,
        0,
        .emit,
        one,
        &mismatch,
    );

    var report = try classify(
        std.testing.allocator,
        &ledger,
        domainBit(.recursion_wire),
    );
    defer report.deinit();
    try std.testing.expectEqual(@as(usize, 4), report.groups.len);
    try std.testing.expectEqual(@as(usize, 5), report.provenance.len);
    try std.testing.expectEqual(@as(usize, 4), report.closure.unmatched_tuple_count);
    var saw_missing_emitter = false;
    var saw_missing_consumer = false;
    var saw_mismatch = false;
    for (report.groups) |group| switch (group.kind) {
        .missing_emitter => saw_missing_emitter = true,
        .missing_consumer => saw_missing_consumer = true,
        .multiplicity_mismatch => saw_mismatch = true,
    };
    try std.testing.expect(saw_missing_emitter);
    try std.testing.expect(saw_missing_consumer);
    try std.testing.expect(saw_mismatch);
    var matching_missing_emitter_pairs: usize = 0;
    for (report.groups, 0..) |left, left_index| {
        if (left.kind != .missing_emitter) continue;
        for (report.groups[left_index + 1 ..]) |right|
            matching_missing_emitter_pairs += @intFromBool(sameClass(
                &report,
                &left,
                &right,
            ));
    }
    try std.testing.expectEqual(
        @as(usize, 1),
        matching_missing_emitter_pairs,
    );
}
