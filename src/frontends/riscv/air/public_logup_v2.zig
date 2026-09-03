//! LogUp public compensation for authenticated resumed-execution boundaries.
//!
//! `public_data_v2` emits transition-facing events: entry consumes and exit
//! produces.  Native instruction rows have the same orientation, so the
//! verifier-side public compensation computed here deliberately uses the
//! opposite signs: `+1/entry - 1/exit`.  Adjacent segment compensation then
//! cancels at the shared authenticated boundary, leaving only the complete
//! execution's outer edges.
//!
//! Full sparse RW state replaces V1's role-filtered public-I/O special cases.
//! A zero value and a nonzero predecessor clock remains an explicit tuple;
//! omission means exactly `(value=0, predecessor_clock=0)`.  Continuation roots
//! are the pinned scalar roots recomputed by the segment-wire authenticator.
//!
//! This is allocation-free protocol substrate.  It does not activate V2 in the
//! native prover or claim proof soundness for resumed execution.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const public_data_v2 = @import("public_data_v2.zig");
const program_decode = @import("program/decode.zig");
const relation_challenges = @import("relation_challenges.zig");

pub const Error = public_data_v2.Error || error{
    NonScalarProgramRoot,
    ZeroDenominator,
};

pub const Sums = struct {
    registers_state: QM31,
    memory_access: QM31,
    program_access: QM31,
    merkle: QM31,

    pub fn total(self: Sums) QM31 {
        return self.registers_state
            .add(self.memory_access)
            .add(self.program_access)
            .add(self.merkle);
    }
};

/// Trace-facing sums over only the entry-consume/exit-produce transition.
/// These are useful for composition audits; verifier public compensation is
/// their negation and is returned by `relationSums`.
pub const TransitionSums = struct {
    registers_state: QM31,
    memory_access: QM31,
};

pub fn sum(
    data: *const public_data_v2.PublicDataV2,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    return (try relationSums(data, relations)).total();
}

/// Exact verifier-side public compensation, split by independent relation
/// domain so no forged cross-domain cancellation can be accepted.
pub fn relationSums(
    data: *const public_data_v2.PublicDataV2,
    relations: *const relation_challenges.Relations,
) Error!Sums {
    var cursor = try data.eventCursor();
    const metadata = cursor.metadata();
    var result = Sums{
        .registers_state = QM31.zero(),
        .memory_access = QM31.zero(),
        .program_access = QM31.zero(),
        .merkle = QM31.zero(),
    };

    while (cursor.next()) |event| switch (event) {
        .registers_state => |state| try addBoundaryInverse(
            &result.registers_state,
            relations.registers_state.combineBase(.{
                base(state.pc),
                base(state.clock),
            }),
            state.direction,
            .compensation,
        ),
        .memory_access => |memory| try addBoundaryInverse(
            &result.memory_access,
            relations.memory_access.combineBase(memoryTuple(memory)),
            memory.direction,
            .compensation,
        ),
    };

    // Program and continuation-root anchors are direct public events, not the
    // inverse of an entry/exit transition.
    const program_root = try scalarProgramRoot(metadata.program);
    inline for (.{
        program_root,
        metadata.entry_continuation_root,
        metadata.exit_continuation_root,
    }) |root| {
        try addDirectInverse(
            &result.merkle,
            relations.merkle.combineBase(.{
                M31.zero(), M31.zero(), base(root), base(root),
            }),
            .produce,
        );
    }

    if (metadata.completion) |completion| {
        if (completion.kind == .unretired_self_loop) {
            const values = program_decode.decodeProgramWord(completion.value) catch
                unreachable;
            try addDirectInverse(
                &result.program_access,
                relations.program_access.combineBase(.{
                    base(completion.address),
                    base(values[0]),
                    base(values[1]),
                    base(values[2]),
                    base(values[3]),
                }),
                .consume,
            );
        }
    }
    return result;
}

/// V2 compensation contributed only by the full sparse RW-memory transition.
/// Register memory endpoints are deliberately excluded. Incremental V3 keeps
/// the V2 CPU/register authority but replaces this member with role-aware V1
/// public-I/O terms because its committed full-state boundary owns all other
/// RW endpoints.
pub fn rwMemoryAccessSum(
    data: *const public_data_v2.PublicDataV2,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    var cursor = try data.eventCursor();
    var result = QM31.zero();
    while (cursor.next()) |event| switch (event) {
        .registers_state => {},
        .memory_access => |memory| {
            if (memory.address_space != 1) continue;
            try addBoundaryInverse(
                &result,
                relations.memory_access.combineBase(memoryTuple(memory)),
                memory.direction,
                .compensation,
            );
        },
    };
    return result;
}

/// Failure-atomic pointer form for orchestration code that keeps a reusable
/// output slot.  A malformed wire or zero denominator leaves `destination`
/// byte-for-byte unchanged.
pub fn writeRelationSums(
    data: *const public_data_v2.PublicDataV2,
    relations: *const relation_challenges.Relations,
    destination: *Sums,
) Error!void {
    const result = try relationSums(data, relations);
    destination.* = result;
}

pub fn transitionSums(
    data: *const public_data_v2.PublicDataV2,
    relations: *const relation_challenges.Relations,
) Error!TransitionSums {
    var cursor = try data.eventCursor();
    var result = TransitionSums{
        .registers_state = QM31.zero(),
        .memory_access = QM31.zero(),
    };
    while (cursor.next()) |event| switch (event) {
        .registers_state => |state| try addBoundaryInverse(
            &result.registers_state,
            relations.registers_state.combineBase(.{
                base(state.pc),
                base(state.clock),
            }),
            state.direction,
            .transition,
        ),
        .memory_access => |memory| try addBoundaryInverse(
            &result.memory_access,
            relations.memory_access.combineBase(memoryTuple(memory)),
            memory.direction,
            .transition,
        ),
    };
    return result;
}

const Convention = enum { transition, compensation };

fn addBoundaryInverse(
    result: *QM31,
    denominator: QM31,
    direction: public_data_v2.Direction,
    convention: Convention,
) Error!void {
    const inverse = denominator.inv() catch return error.ZeroDenominator;
    const positive = switch (convention) {
        .transition => direction == .produce,
        .compensation => direction == .consume,
    };
    result.* = if (positive) result.add(inverse) else result.sub(inverse);
}

fn addDirectInverse(
    result: *QM31,
    denominator: QM31,
    direction: public_data_v2.Direction,
) Error!void {
    const inverse = denominator.inv() catch return error.ZeroDenominator;
    result.* = switch (direction) {
        .consume => result.sub(inverse),
        .produce => result.add(inverse),
    };
}

fn scalarProgramRoot(program: public_data_v2.Digest) Error!u32 {
    for (program[1..]) |word| {
        if (word != 0) return error.NonScalarProgramRoot;
    }
    return program[0];
}

fn memoryTuple(event: public_data_v2.MemoryAccessEvent) [7]M31 {
    return .{
        base(event.address_space),
        base(event.address),
        base(event.predecessor_clock),
        base(@as(u8, @truncate(event.value))),
        base(@as(u8, @truncate(event.value >> 8))),
        base(@as(u8, @truncate(event.value >> 16))),
        base(@as(u8, @truncate(event.value >> 24))),
    };
}

fn base(value: anytype) M31 {
    return M31.fromU64(@as(u64, value));
}
