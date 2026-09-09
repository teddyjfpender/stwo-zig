//! Exact host contract for a composable incremental RW-memory boundary.
//!
//! V1's role-filtered sparse trees are not a continuation authority: adjacent
//! segments need the raw entry/exit memory state to compose.  V3 therefore
//! opens both raw word values in the full-state Merkle transition.  Public I/O
//! roles affect only the memory-access multiplicity.  The future boundary AIR
//! must keep every opened Merkle side active while independently constraining
//! the memory multiplicity to `-1`, `0`, or `+1`.
//!
//! This module is deliberately host-side contract substrate.  It neither
//! supplies the missing AIR component nor activates a native proof profile.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const m31 = @import("stwo_core").fields.m31;
const access_clock = frontend.access_clock;
const memory_state = frontend.runner.memory_state;
const public_data_mod = frontend.air.public_data;
const sparse_merkle = frontend.air.memory_commitment.sparse_merkle;

pub const PRODUCTION_ACTIVE = false;
pub const SCHEMA = "stwo.ethereum.incremental-boundary-authority.v3";

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
    UnclosedPublicInput,
    UnsupportedStatementFamily,
    ValueChangedWithoutAccess,
};

/// V3 is intentionally incompatible with the legacy role-filtered root
/// family.  Adding another family requires another exhaustive branch here.
pub const StatementFamilyV3 = enum(u32) {
    segment_full_state_v3 = 1,
};

pub const BoundaryPolicyV3 = enum(u32) {
    /// Both raw Merkle sides are active.  The memory bus is independently
    /// suppressed on the side supplied by typed public compensation.
    full_state_split_memory_multiplicity = 1,
};

/// Sign used by the future split boundary component's memory-access entry.
/// Merkle activity is not represented by this value and is always enabled for
/// both rows of every opened transition.
pub const MemoryMultiplicityV3 = enum(i8) {
    exit = -1,
    none = 0,
    entry = 1,
};

pub const CoordinateV3 = struct {
    segment_index: u32,
    segment_count: u32,
};

pub const FullStateRootsV3 = struct {
    entry: u32,
    exit: u32,
};

/// Process-local typed inputs.  A future statement owner must construct this
/// from an authenticated segment wire plus its ELF-derived layout.  Merely
/// possessing these host fields is not proof admission.
pub const SegmentPublicAuthorityV3 = struct {
    statement_family: StatementFamilyV3 = .segment_full_state_v3,
    coordinate: CoordinateV3,
    segment_role: memory_state.SegmentRole,
    layout: memory_state.MemoryLayout,
    public_data: *const public_data_mod.PublicData,
    continuation_roots: FullStateRootsV3,

    pub fn validate(self: SegmentPublicAuthorityV3) Error!void {
        if (self.statement_family != .segment_full_state_v3)
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
        self: SegmentPublicAuthorityV3,
        address: u32,
    ) Error!memory_state.WordRole {
        try self.validate();
        if ((address & 3) != 0 or
            address > sparse_merkle.LEAF_COUNT - 4 or
            !self.layout.isRwAddr(address))
        {
            return error.InvalidWordAddress;
        }
        const completion_address: ?u32 = if (self.public_data.completion) |completion|
            if (completion.kind == .halt_flag) completion.address else null
        else
            null;
        const result = memory_state.WordRole{
            .is_public_input = self.segment_role.is_first and
                self.layout.isInputAddr(address),
            .is_public_output = self.segment_role.is_last and
                self.layout.isPublicOutputAddr(
                    address,
                    self.public_data.io_entries.output_len,
                ),
            .is_public_completion = self.segment_role.is_last and
                completion_address != null and address == completion_address.?,
        };
        const role_count: u2 = @intFromBool(result.is_public_input) +
            @intFromBool(result.is_public_output) +
            @intFromBool(result.is_public_completion);
        if (role_count > 1) return error.AmbiguousPublicMemoryRole;
        return result;
    }
};

/// Exact entry clock is required for resumed segments.  `WordState` retains
/// only the exit clock, so treating every segment entry as clock zero would
/// break cross-segment memory chains.
pub const WordBoundarySourceV3 = struct {
    word: memory_state.WordState,
    entry_clock: u32,
};

pub const PublicMemoryTupleV3 = struct {
    address: u32,
    clock: u32,
    value: u32,
};

pub const PublicLinksV3 = struct {
    input_entry: ?PublicMemoryTupleV3 = null,
    output_exit: ?PublicMemoryTupleV3 = null,
    completion_exit: ?PublicMemoryTupleV3 = null,

    pub fn count(self: PublicLinksV3) u2 {
        return @intCast(@intFromBool(self.input_entry != null) +
            @intFromBool(self.output_exit != null) +
            @intFromBool(self.completion_exit != null));
    }
};

pub const RawMerkleWordsV3 = struct {
    entry: u32,
    exit: u32,
};

/// One word admitted into the opened transition inventory.  Inclusion is not
/// caller-selected: it is the exact union of a replay clock change and an
/// address present in the typed first/last public ABI.
pub const OpenedTransitionV3 = struct {
    policy: BoundaryPolicyV3 = .full_state_split_memory_multiplicity,
    coordinate: CoordinateV3,
    source: WordBoundarySourceV3,
    merkle_words: RawMerkleWordsV3,
    public_links: PublicLinksV3,

    pub fn validateAgainst(
        self: OpenedTransitionV3,
        authority: SegmentPublicAuthorityV3,
    ) Error!void {
        if (self.policy != .full_state_split_memory_multiplicity)
            return error.TransitionPolicyMismatch;
        if (!std.meta.eql(self.coordinate, authority.coordinate))
            return error.TransitionCoordinateMismatch;
        const expected = try deriveOpenedTransition(authority, self.source);
        if (!std.meta.eql(self, expected)) return error.TransitionPolicyMismatch;
    }
};

pub const BoundarySideV3 = enum(u32) { entry = 0, exit = 1 };

/// Structural input to the future split boundary AIR.  Every value is a raw
/// full-state Merkle word.  `memory_multiplicity == .none` suppresses only the
/// memory-access tuple; it must never suppress range checks or Merkle leaves.
pub const BoundaryRowContractV3 = struct {
    policy: BoundaryPolicyV3 = .full_state_split_memory_multiplicity,
    coordinate: CoordinateV3,
    side: BoundarySideV3,
    address: u32,
    clock: u32,
    word: u32,
    root: u32,
    role: memory_state.WordRole,
    memory_multiplicity: MemoryMultiplicityV3,

    pub fn validateAgainst(
        self: BoundaryRowContractV3,
        authority: SegmentPublicAuthorityV3,
        transition: OpenedTransitionV3,
    ) Error!void {
        try transition.validateAgainst(authority);
        const expected = rowFor(authority, transition, self.side);
        if (!std.meta.eql(self, expected)) return error.BoundaryRowMismatch;
    }
};

pub fn validateInventory(
    authority: SegmentPublicAuthorityV3,
    sources: []const WordBoundarySourceV3,
) Error!void {
    try authority.validate();
    var previous_address: ?u32 = null;
    for (sources) |source| {
        if (previous_address) |previous| {
            if (source.word.addr == previous) return error.DuplicateOpenedWord;
            if (source.word.addr < previous) return error.OpenedInventoryMismatch;
        }
        previous_address = source.word.addr;
        _ = try deriveOpenedTransition(authority, source);
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
    authority: SegmentPublicAuthorityV3,
    sources: []const WordBoundarySourceV3,
    destination: []OpenedTransitionV3,
) Error!void {
    try validateInventory(authority, sources);
    if (destination.len != sources.len) return error.OutputLengthMismatch;
    for (sources, destination) |source, *output|
        output.* = try deriveOpenedTransition(authority, source);
}

pub fn writeBoundaryRows(
    authority: SegmentPublicAuthorityV3,
    transitions: []const OpenedTransitionV3,
    destination: []BoundaryRowContractV3,
) Error!void {
    try validateTransitionInventory(authority, transitions);
    const expected_len = std.math.mul(usize, transitions.len, 2) catch
        return error.OutputLengthMismatch;
    if (destination.len != expected_len) return error.OutputLengthMismatch;
    var previous_address: ?u32 = null;
    for (transitions, 0..) |transition, index| {
        if (previous_address) |previous| {
            if (transition.source.word.addr <= previous)
                return error.OpenedInventoryMismatch;
        }
        previous_address = transition.source.word.addr;
        destination[index * 2] = rowFor(authority, transition, .entry);
        destination[index * 2 + 1] = rowFor(authority, transition, .exit);
    }
}

fn deriveOpenedTransition(
    authority: SegmentPublicAuthorityV3,
    source: WordBoundarySourceV3,
) Error!OpenedTransitionV3 {
    try authority.validate();
    const expected_role = try authority.expectedRole(source.word.addr);
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

    const links = try publicLinks(authority, source);
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

fn publicLinks(
    authority: SegmentPublicAuthorityV3,
    source: WordBoundarySourceV3,
) Error!PublicLinksV3 {
    var result = PublicLinksV3{};
    const io = authority.public_data.io_entries;
    if (authority.segment_role.is_first) {
        for (io.input_words, 0..) |value, index| {
            const address = try io.inputWordAddress(index);
            if (address != source.word.addr) continue;
            if (source.entry_clock != 0) return error.PublicMemoryClockMismatch;
            if (source.word.initial_word != value)
                return error.PublicMemoryValueMismatch;
            if (source.word.final_clock == 0) return error.UnclosedPublicInput;
            result.input_entry = .{ .address = address, .clock = 0, .value = value };
        }
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
    authority: SegmentPublicAuthorityV3,
    transition: OpenedTransitionV3,
    side: BoundarySideV3,
) BoundaryRowContractV3 {
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
    side: BoundarySideV3,
) MemoryMultiplicityV3 {
    return switch (side) {
        .entry => if (word.includeInitial()) .entry else .none,
        .exit => if (word.includeFinal()) .exit else .none,
    };
}

fn findSource(
    sources: []const WordBoundarySourceV3,
    address: u32,
) ?WordBoundarySourceV3 {
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

fn validateTransitionInventory(
    authority: SegmentPublicAuthorityV3,
    transitions: []const OpenedTransitionV3,
) Error!void {
    try authority.validate();
    var previous_address: ?u32 = null;
    for (transitions) |transition| {
        try transition.validateAgainst(authority);
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

fn findTransition(
    transitions: []const OpenedTransitionV3,
    address: u32,
) ?OpenedTransitionV3 {
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
