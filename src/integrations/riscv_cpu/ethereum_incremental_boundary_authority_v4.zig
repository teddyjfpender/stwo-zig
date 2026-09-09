//! Exact host contract for a composable incremental RW-memory boundary.
//!
//! V1's role-filtered sparse trees are not a continuation authority: adjacent
//! segments need the raw entry/exit memory state to compose.  V4 therefore
//! opens both raw word values in the full-state Merkle transition.  Public I/O
//! roles affect only the memory-access multiplicity.  The future boundary AIR
//! must keep every opened Merkle side active while independently constraining
//! the memory multiplicity to `-1`, `0`, or `+1`.
//!
//! This module is deliberately host-side contract substrate.  It neither
//! supplies the missing AIR component nor activates a native proof profile.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const m31 = @import("stwo_core").fields.m31;
const access_clock = frontend.access_clock;
const memory_state = frontend.runner.memory_state;
const public_data_mod = frontend.air.public_data;
const sparse_merkle = frontend.air.memory_commitment.sparse_merkle;

pub const PRODUCTION_ACTIVE = false;
pub const SCHEMA = "stwo.ethereum.incremental-boundary-authority.v4";

var validation_call_count = std.atomic.Value(u64).init(0);

pub const Error = public_data_mod.ValidationError || error{
    AmbiguousPublicMemoryRole,
    BoundaryRowMismatch,
    CompletionOutsideRwMemory,
    DuplicateOpenedWord,
    FullStateRootMismatch,
    InputCapacityMismatch,
    InputWordMissing,
    InvalidFullStateRoot,
    InvalidMemoryLayout,
    InvalidSegmentPosition,
    InvalidSegmentRole,
    InvalidTransitionClock,
    InvalidWordAddress,
    MissingFullStateRoot,
    MissingPublicMemoryTuple,
    OpenedInventoryMismatch,
    OutputLengthMismatch,
    OutputWordMissing,
    PublicMemoryClockMismatch,
    PublicMemoryValueMismatch,
    PublicRoleMismatch,
    TransitionCoordinateMismatch,
    TransitionPolicyMismatch,
    UnsupportedStatementFamily,
    ValueChangedWithoutAccess,
};

/// V4 is intentionally incompatible with the legacy role-filtered root
/// family.  Adding another family requires another exhaustive branch here.
pub const StatementFamilyV4 = enum(u32) {
    segment_full_state_v4 = 2,
};

pub const BoundaryPolicyV4 = enum(u32) {
    /// Both raw Merkle sides are active.  A typed public input owns the entry
    /// side, while the boundary always emits its authenticated exit tuple.
    /// For an untouched input that tuple is `(clock=0,value=input)`, closing
    /// public LogUp without inventing an opcode access.
    full_state_split_public_input_exit = 2,
};

/// Sign used by the future split boundary component's memory-access entry.
/// Merkle activity is not represented by this value and is always enabled for
/// both rows of every opened transition.
pub const MemoryMultiplicityV4 = enum(i8) {
    exit = -1,
    none = 0,
    entry = 1,
};

pub const CoordinateV4 = struct {
    segment_index: u32,
    segment_count: u32,
};

pub const FullStateRootsV4 = struct {
    entry: u32,
    exit: u32,
};

/// Process-local typed inputs.  A future statement owner must construct this
/// from an authenticated segment wire plus its ELF-derived layout.  Merely
/// possessing these host fields is not proof admission.
pub const SegmentPublicAuthorityV4 = struct {
    statement_family: StatementFamilyV4 = .segment_full_state_v4,
    coordinate: CoordinateV4,
    segment_role: memory_state.SegmentRole,
    layout: memory_state.MemoryLayout,
    public_data: *const public_data_mod.PublicData,
    continuation_roots: FullStateRootsV4,

    pub fn validate(self: SegmentPublicAuthorityV4) Error!void {
        if (builtin.is_test) _ = validation_call_count.fetchAdd(1, .monotonic);
        if (self.statement_family != .segment_full_state_v4)
            return error.UnsupportedStatementFamily;
        if (self.coordinate.segment_count == 0 or
            self.coordinate.segment_index >= self.coordinate.segment_count)
        {
            return error.InvalidSegmentPosition;
        }
        const expected_segment_role = memory_state.SegmentRole{
            .is_first = self.coordinate.segment_index == 0,
            .is_last = self.coordinate.segment_index ==
                self.coordinate.segment_count - 1,
        };
        if (!std.meta.eql(self.segment_role, expected_segment_role))
            return error.InvalidSegmentRole;

        try self.public_data.validate();
        const initial_root = self.public_data.initial_rw_root orelse
            return error.MissingFullStateRoot;
        const final_root = self.public_data.final_rw_root orelse
            return error.MissingFullStateRoot;
        if (initial_root >= m31.Modulus or final_root >= m31.Modulus)
            return error.InvalidFullStateRoot;
        if (initial_root != self.continuation_roots.entry or
            final_root != self.continuation_roots.exit)
        {
            return error.FullStateRootMismatch;
        }

        const layout = self.layout;
        const io = self.public_data.io_entries;
        if (layout.input_base > layout.input_end or
            layout.io_base > layout.io_end or
            (layout.input_base & 3) != 0 or
            layout.input_base != io.input_start or
            layout.output_len_addr != io.output_len_addr or
            layout.output_data_addr != io.output_data_addr)
        {
            return error.InvalidMemoryLayout;
        }
        const input_end = std.math.add(u32, io.input_start, io.input_len) catch
            return error.InputCapacityMismatch;
        if (input_end > layout.input_end) return error.InputCapacityMismatch;
        for (io.input_words, 0..) |_, index| {
            const address = try io.inputWordAddress(index);
            if (!layout.isRwAddr(address) or !layout.isInputAddr(address))
                return error.InvalidMemoryLayout;
        }
        for (io.output_words) |word| {
            if (!layout.isRwAddr(word.addr) or
                !layout.isPublicOutputAddr(word.addr, io.output_len))
            {
                return error.InvalidMemoryLayout;
            }
        }
        if (self.public_data.completion) |completion| {
            if (completion.kind == .halt_flag and
                !layout.isRwAddr(completion.address))
            {
                return error.CompletionOutsideRwMemory;
            }
        }
    }

    pub fn expectedRole(
        self: SegmentPublicAuthorityV4,
        address: u32,
    ) Error!memory_state.WordRole {
        const validated = try ValidatedSegmentPublicAuthorityV4.init(self);
        return validated.expectedRole(address);
    }

    /// Exact public-input word lookup.  Layout capacity is not semantic input:
    /// padding outside the canonical packed word list must never acquire a
    /// public role merely because it lies in the reserved input mapping.
    pub fn publicInputWord(
        self: SegmentPublicAuthorityV4,
        address: u32,
    ) Error!?u32 {
        const validated = try ValidatedSegmentPublicAuthorityV4.init(self);
        return validated.publicInputWord(address);
    }
};

/// Process-local proof that the complete role-aware authority has been
/// validated once.  It is never serialized and carries no proof/freshness
/// authority.  Per-word consumers must use this token so the exact large input
/// inventory is not rescanned inside an execution-boundary loop.
pub const ValidatedSegmentPublicAuthorityV4 = struct {
    value: SegmentPublicAuthorityV4,

    pub fn init(value: SegmentPublicAuthorityV4) Error!ValidatedSegmentPublicAuthorityV4 {
        try value.validate();
        return .{ .value = value };
    }

    pub fn authority(self: ValidatedSegmentPublicAuthorityV4) SegmentPublicAuthorityV4 {
        return self.value;
    }

    pub fn expectedRole(
        self: ValidatedSegmentPublicAuthorityV4,
        address: u32,
    ) Error!memory_state.WordRole {
        return expectedRoleAssumeValidated(self.value, address);
    }

    pub fn publicInputWord(
        self: ValidatedSegmentPublicAuthorityV4,
        address: u32,
    ) ?u32 {
        return publicInputWordAssumeValidated(self.value, address);
    }

    pub fn validateInventory(
        self: ValidatedSegmentPublicAuthorityV4,
        sources: []const WordBoundarySourceV4,
    ) Error!void {
        return validateInventoryAssumeValidated(self, sources);
    }

    pub fn writeOpenedTransitions(
        self: ValidatedSegmentPublicAuthorityV4,
        sources: []const WordBoundarySourceV4,
        destination: []OpenedTransitionV4,
    ) Error!void {
        try validateInventoryAssumeValidated(self, sources);
        if (destination.len != sources.len) return error.OutputLengthMismatch;
        for (sources, destination) |source, *output|
            output.* = try deriveOpenedTransitionAssumeValidated(self, source);
    }

    pub fn writeBoundaryRows(
        self: ValidatedSegmentPublicAuthorityV4,
        transitions: []const OpenedTransitionV4,
        destination: []BoundaryRowContractV4,
    ) Error!void {
        try validateTransitionInventoryAssumeValidated(self, transitions);
        const expected_len = std.math.mul(usize, transitions.len, 2) catch
            return error.OutputLengthMismatch;
        if (destination.len != expected_len) return error.OutputLengthMismatch;
        for (transitions, 0..) |transition, index| {
            destination[index * 2] = rowFor(self.value, transition, .entry);
            destination[index * 2 + 1] = rowFor(self.value, transition, .exit);
        }
    }

    fn validateTransition(
        self: ValidatedSegmentPublicAuthorityV4,
        transition: OpenedTransitionV4,
    ) Error!void {
        if (transition.policy != .full_state_split_public_input_exit)
            return error.TransitionPolicyMismatch;
        if (!std.meta.eql(transition.coordinate, self.value.coordinate))
            return error.TransitionCoordinateMismatch;
        const expected = try deriveOpenedTransitionAssumeValidated(
            self,
            transition.source,
        );
        if (!std.meta.eql(transition, expected))
            return error.TransitionPolicyMismatch;
    }
};

fn expectedRoleAssumeValidated(
    authority: SegmentPublicAuthorityV4,
    address: u32,
) Error!memory_state.WordRole {
    if ((address & 3) != 0 or
        address > sparse_merkle.LEAF_COUNT - 4 or
        !authority.layout.isRwAddr(address))
    {
        return error.InvalidWordAddress;
    }
    const completion_address: ?u32 = if (authority.public_data.completion) |completion|
        if (completion.kind == .halt_flag) completion.address else null
    else
        null;
    const result = memory_state.WordRole{
        .is_public_input = authority.segment_role.is_first and
            publicInputWordAssumeValidated(authority, address) != null,
        .is_public_output = authority.segment_role.is_last and
            authority.layout.isPublicOutputAddr(
                address,
                authority.public_data.io_entries.output_len,
            ),
        .is_public_completion = authority.segment_role.is_last and
            completion_address != null and address == completion_address.?,
    };
    const role_count: u2 = @intFromBool(result.is_public_input) +
        @intFromBool(result.is_public_output) +
        @intFromBool(result.is_public_completion);
    if (role_count > 1) return error.AmbiguousPublicMemoryRole;
    return result;
}

fn publicInputWordAssumeValidated(
    authority: SegmentPublicAuthorityV4,
    address: u32,
) ?u32 {
    if (!authority.segment_role.is_first or
        address < authority.public_data.io_entries.input_start or
        (address & 3) != 0)
    {
        return null;
    }
    const offset = address - authority.public_data.io_entries.input_start;
    const index: usize = offset / 4;
    const words = authority.public_data.io_entries.input_words;
    if (index >= words.len) return null;
    const expected_address = authority.public_data.io_entries
        .inputWordAddress(index) catch return null;
    if (expected_address != address) return null;
    return words[index];
}

/// Exact entry clock is required for resumed segments.  `WordState` retains
/// only the exit clock, so treating every segment entry as clock zero would
/// break cross-segment memory chains.
pub const WordBoundarySourceV4 = struct {
    word: memory_state.WordState,
    entry_clock: u32,
};

pub const PublicMemoryTupleV4 = struct {
    address: u32,
    clock: u32,
    value: u32,
};

pub const PublicLinksV4 = struct {
    input_entry: ?PublicMemoryTupleV4 = null,
    output_exit: ?PublicMemoryTupleV4 = null,
    completion_exit: ?PublicMemoryTupleV4 = null,

    pub fn count(self: PublicLinksV4) u2 {
        return @intCast(@intFromBool(self.input_entry != null) +
            @intFromBool(self.output_exit != null) +
            @intFromBool(self.completion_exit != null));
    }
};

pub const RawMerkleWordsV4 = struct {
    entry: u32,
    exit: u32,
};

/// One word admitted into the opened transition inventory.  Inclusion is not
/// caller-selected: it is the exact union of a replay clock change and an
/// address present in the typed first/last public ABI.
pub const OpenedTransitionV4 = struct {
    policy: BoundaryPolicyV4 = .full_state_split_public_input_exit,
    coordinate: CoordinateV4,
    source: WordBoundarySourceV4,
    merkle_words: RawMerkleWordsV4,
    public_links: PublicLinksV4,

    pub fn validateAgainst(
        self: OpenedTransitionV4,
        authority: SegmentPublicAuthorityV4,
    ) Error!void {
        const validated = try ValidatedSegmentPublicAuthorityV4.init(authority);
        return validated.validateTransition(self);
    }
};

pub const BoundarySideV4 = enum(u32) { entry = 0, exit = 1 };

/// Structural input to the future split boundary AIR.  Every value is a raw
/// full-state Merkle word.  `memory_multiplicity == .none` suppresses only the
/// memory-access tuple; it must never suppress range checks or Merkle leaves.
pub const BoundaryRowContractV4 = struct {
    policy: BoundaryPolicyV4 = .full_state_split_public_input_exit,
    coordinate: CoordinateV4,
    side: BoundarySideV4,
    address: u32,
    clock: u32,
    word: u32,
    root: u32,
    role: memory_state.WordRole,
    memory_multiplicity: MemoryMultiplicityV4,

    pub fn validateAgainst(
        self: BoundaryRowContractV4,
        authority: SegmentPublicAuthorityV4,
        transition: OpenedTransitionV4,
    ) Error!void {
        const validated = try ValidatedSegmentPublicAuthorityV4.init(authority);
        try validated.validateTransition(transition);
        const expected = rowFor(validated.value, transition, self.side);
        if (!std.meta.eql(self, expected)) return error.BoundaryRowMismatch;
    }
};

pub fn validateInventory(
    authority: SegmentPublicAuthorityV4,
    sources: []const WordBoundarySourceV4,
) Error!void {
    const validated = try ValidatedSegmentPublicAuthorityV4.init(authority);
    return validated.validateInventory(sources);
}

fn validateInventoryAssumeValidated(
    validated: ValidatedSegmentPublicAuthorityV4,
    sources: []const WordBoundarySourceV4,
) Error!void {
    const authority = validated.value;
    var previous_address: ?u32 = null;
    for (sources) |source| {
        if (previous_address) |previous| {
            if (source.word.addr == previous) return error.DuplicateOpenedWord;
            if (source.word.addr < previous) return error.OpenedInventoryMismatch;
        }
        previous_address = source.word.addr;
        _ = try deriveOpenedTransitionAssumeValidated(validated, source);
    }

    if (authority.segment_role.is_first) {
        const io = authority.public_data.io_entries;
        for (io.input_words, 0..) |_, index| {
            const address = try io.inputWordAddress(index);
            if (findSource(sources, address) == null) return error.InputWordMissing;
        }
    }
    if (authority.segment_role.is_last) {
        for (authority.public_data.io_entries.output_words) |word| {
            if (findSource(sources, word.addr) == null) return error.OutputWordMissing;
        }
        if (authority.public_data.completion) |completion| {
            if (completion.kind == .halt_flag and
                findSource(sources, completion.address) == null)
            {
                return error.OutputWordMissing;
            }
        }
    }
}

pub fn writeOpenedTransitions(
    authority: SegmentPublicAuthorityV4,
    sources: []const WordBoundarySourceV4,
    destination: []OpenedTransitionV4,
) Error!void {
    const validated = try ValidatedSegmentPublicAuthorityV4.init(authority);
    return validated.writeOpenedTransitions(sources, destination);
}

pub fn writeBoundaryRows(
    authority: SegmentPublicAuthorityV4,
    transitions: []const OpenedTransitionV4,
    destination: []BoundaryRowContractV4,
) Error!void {
    const validated = try ValidatedSegmentPublicAuthorityV4.init(authority);
    return validated.writeBoundaryRows(transitions, destination);
}

fn deriveOpenedTransitionAssumeValidated(
    validated: ValidatedSegmentPublicAuthorityV4,
    source: WordBoundarySourceV4,
) Error!OpenedTransitionV4 {
    const authority = validated.value;
    const expected_role = try validated.expectedRole(source.word.addr);
    if (!std.meta.eql(source.word.role, expected_role))
        return error.PublicRoleMismatch;
    if (source.entry_clock > source.word.final_clock)
        return error.InvalidTransitionClock;
    if ((source.entry_clock != 0 and
        !access_clock.isWithinExecution(
            source.entry_clock,
            authority.public_data.clock,
            false,
        )) or !access_clock.isWithinExecution(
        source.word.final_clock,
        authority.public_data.clock,
        true,
    )) return error.InvalidTransitionClock;
    const replay_touched = source.entry_clock != source.word.final_clock;
    if (!replay_touched and source.word.initial_word != source.word.final_word)
        return error.ValueChangedWithoutAccess;

    const links = try publicLinksAssumeValidated(validated, source);
    if (!replay_touched and links.count() == 0)
        return error.OpenedInventoryMismatch;
    if (source.word.role.is_public_input and links.input_entry == null)
        return error.MissingPublicMemoryTuple;
    if (source.word.role.is_public_output and links.output_exit == null)
        return error.MissingPublicMemoryTuple;
    if (source.word.role.is_public_completion and links.completion_exit == null)
        return error.MissingPublicMemoryTuple;

    return .{
        .coordinate = authority.coordinate,
        .source = source,
        // Public roles never alter full-state continuation-tree membership.
        .merkle_words = .{
            .entry = source.word.initial_word,
            .exit = source.word.final_word,
        },
        .public_links = links,
    };
}

fn publicLinksAssumeValidated(
    validated: ValidatedSegmentPublicAuthorityV4,
    source: WordBoundarySourceV4,
) Error!PublicLinksV4 {
    const authority = validated.value;
    var result = PublicLinksV4{};
    const io = authority.public_data.io_entries;
    if (validated.publicInputWord(source.word.addr)) |value| {
        if (source.entry_clock != 0) return error.PublicMemoryClockMismatch;
        if (source.word.initial_word != value)
            return error.PublicMemoryValueMismatch;
        if (source.word.final_clock == 0 and
            source.word.final_word != source.word.initial_word)
        {
            return error.ValueChangedWithoutAccess;
        }
        result.input_entry = .{
            .address = source.word.addr,
            .clock = 0,
            .value = value,
        };
    }
    if (authority.segment_role.is_last) {
        for (io.output_words) |word| {
            if (word.addr != source.word.addr) continue;
            if (source.word.final_clock != word.clock)
                return error.PublicMemoryClockMismatch;
            if (source.word.final_word != word.value)
                return error.PublicMemoryValueMismatch;
            result.output_exit = .{
                .address = word.addr,
                .clock = word.clock,
                .value = word.value,
            };
        }
        if (authority.public_data.completion) |completion| {
            if (completion.kind == .halt_flag and
                completion.address == source.word.addr)
            {
                if (source.word.final_clock != completion.clock)
                    return error.PublicMemoryClockMismatch;
                if (source.word.final_word != completion.value)
                    return error.PublicMemoryValueMismatch;
                result.completion_exit = .{
                    .address = completion.address,
                    .clock = completion.clock,
                    .value = completion.value,
                };
            }
        }
    }
    if (result.count() > 1) return error.AmbiguousPublicMemoryRole;
    return result;
}

fn rowFor(
    authority: SegmentPublicAuthorityV4,
    transition: OpenedTransitionV4,
    side: BoundarySideV4,
) BoundaryRowContractV4 {
    const word = transition.source.word;
    return .{
        .coordinate = authority.coordinate,
        .side = side,
        .address = word.addr,
        .clock = if (side == .entry)
            transition.source.entry_clock
        else
            word.final_clock,
        .word = if (side == .entry)
            transition.merkle_words.entry
        else
            transition.merkle_words.exit,
        .root = if (side == .entry)
            authority.continuation_roots.entry
        else
            authority.continuation_roots.exit,
        .role = word.role,
        .memory_multiplicity = memoryMultiplicity(word, side),
    };
}

fn memoryMultiplicity(
    word: memory_state.WordState,
    side: BoundarySideV4,
) MemoryMultiplicityV4 {
    return switch (side) {
        .entry => if (word.includeInitial()) .entry else .none,
        // V4 deliberately does not change WordState.includeFinal(): that
        // predicate is legacy V1 protocol.  Policy 2 closes every typed public
        // input at its authenticated final clock, including untouched clock 0.
        .exit => if (word.role.is_public_input or word.includeFinal())
            .exit
        else
            .none,
    };
}

fn findSource(
    sources: []const WordBoundarySourceV4,
    address: u32,
) ?WordBoundarySourceV4 {
    var low: usize = 0;
    var high = sources.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const candidate = sources[middle];
        if (candidate.word.addr < address) {
            low = middle + 1;
        } else if (candidate.word.addr > address) {
            high = middle;
        } else {
            return candidate;
        }
    }
    return null;
}

fn validateTransitionInventoryAssumeValidated(
    validated: ValidatedSegmentPublicAuthorityV4,
    transitions: []const OpenedTransitionV4,
) Error!void {
    const authority = validated.value;
    var previous_address: ?u32 = null;
    for (transitions) |transition| {
        try validated.validateTransition(transition);
        if (previous_address) |previous| {
            if (transition.source.word.addr <= previous)
                return error.OpenedInventoryMismatch;
        }
        previous_address = transition.source.word.addr;
    }
    if (authority.segment_role.is_first) {
        const io = authority.public_data.io_entries;
        for (io.input_words, 0..) |_, index| {
            const address = try io.inputWordAddress(index);
            if (findTransition(transitions, address) == null)
                return error.InputWordMissing;
        }
    }
    if (authority.segment_role.is_last) {
        for (authority.public_data.io_entries.output_words) |word| {
            if (findTransition(transitions, word.addr) == null)
                return error.OutputWordMissing;
        }
        if (authority.public_data.completion) |completion| {
            if (completion.kind == .halt_flag and
                findTransition(transitions, completion.address) == null)
            {
                return error.OutputWordMissing;
            }
        }
    }
}

pub const testing = if (builtin.is_test) struct {
    pub fn resetValidationCallCount() void {
        validation_call_count.store(0, .monotonic);
    }

    pub fn validationCallCount() u64 {
        return validation_call_count.load(.monotonic);
    }
} else struct {};

fn findTransition(
    transitions: []const OpenedTransitionV4,
    address: u32,
) ?OpenedTransitionV4 {
    var low: usize = 0;
    var high = transitions.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const candidate = transitions[middle];
        if (candidate.source.word.addr < address) {
            low = middle + 1;
        } else if (candidate.source.word.addr > address) {
            high = middle;
        } else {
            return candidate;
        }
    }
    return null;
}
