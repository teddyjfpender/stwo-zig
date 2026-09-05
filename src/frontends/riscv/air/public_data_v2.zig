//! Authenticated public boundary for resumed RV32IM segment proofs.
//!
//! V1 describes only a complete execution whose predecessor clocks all begin
//! at zero.  This V2 boundary deliberately does not reinterpret or extend the
//! V1 type.  It consumes the canonical retained wire authenticated by
//! `recursion/segment_statement_v2.zig` and exposes the exact transition at a
//! segment edge:
//!
//! - global CPU cycles and entry/exit architectural state;
//! - every register value and its real predecessor clock;
//! - the zero-normalized sparse RW-memory values merged with their independent
//!   predecessor-clock maps;
//! - first-only input, final-only output and final-only completion custody;
//! - the session, job, position and boundary/segment lineage identities.
//!
//! Boundary events use the transition-facing convention: entry is consumed
//! and exit is produced.  `public_logup_v2.zig` reverses those signs when it
//! computes verifier-side public compensation.  Consequently adjacent segment
//! boundaries cancel directly while a standalone segment still cancels its
//! native trace against the public compensation.
//!
//! Authentication, validation, event counting, event iteration and transcript
//! mixing allocate no memory.  Caller-owned event output is fail-atomic: every
//! fallible check and the exact length preflight complete before the first
//! destination element is changed.
//!
//! This module is protocol substrate.  It does not claim that a native or
//! recursive proof currently constrains these events.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const profile = @import("../isa/profile.zig");
const segment_v2 = @import("../recursion/segment_statement_v2.zig");

pub const Digest = segment_v2.Digest;

/// A transcript namespace distinct from both V1 `"RVST"` and the retained
/// segment-wire namespace.  The retained wire is mixed in full after this
/// prefix, so every published identifier, count and tuple is transcript-bound.
pub const STATEMENT_TRANSCRIPT_DOMAIN: u32 = 0x5256_5332; // "RVS2"
pub const STATEMENT_TRANSCRIPT_VERSION: u32 = 2;
pub const STATEMENT_TRANSCRIPT_SCHEMA_VERSION: u32 = 1;

pub const HOT_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const EVENT_EMISSION_HEAP_ALLOCATIONS: usize = 0;
pub const EVENT_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const FIXED_BOUNDARY_EVENT_COUNT: usize = 2 + 2 * 32;
pub const MAX_MEMORY_ADDRESS_COUNT: usize =
    4 * @as(usize, segment_v2.MAX_SPARSE_BOUNDARY_ENTRIES);
pub const MAX_BOUNDARY_EVENT_COUNT: usize =
    FIXED_BOUNDARY_EVENT_COUNT + 2 * MAX_MEMORY_ADDRESS_COUNT;

comptime {
    if (STATEMENT_TRANSCRIPT_VERSION == 0 or
        STATEMENT_TRANSCRIPT_DOMAIN == 0 or
        STATEMENT_TRANSCRIPT_DOMAIN == STATEMENT_TRANSCRIPT_VERSION)
    {
        @compileError("public-data V2 transcript namespace must be nonzero and distinct");
    }
    if (STATEMENT_TRANSCRIPT_DOMAIN == @import("public_data.zig").STATEMENT_TRANSCRIPT_DOMAIN)
        @compileError("public-data V2 must not reuse the V1 transcript domain");
}

pub const Error = segment_v2.Error || error{
    CompletionBoundaryMismatch,
    MisalignedEntryPc,
    MisalignedExitPc,
    OutputLengthMismatch,
    TranscriptWordCountOverflow,
};

pub const Direction = enum(u1) {
    consume,
    produce,
};

pub const RegistersStateEvent = struct {
    direction: Direction,
    pc: u32,
    /// One-based architectural state-chain clock.  A segment whose global
    /// zero-based range is `[start,end)` consumes `start + 1` and produces
    /// `end + 1`.
    clock: u32,
};

pub const MemoryAccessEvent = struct {
    direction: Direction,
    /// Zero is the register address space; one is RW memory.
    address_space: u1,
    address: u32,
    predecessor_clock: u32,
    value: u32,
};

pub const BoundaryEvent = union(enum) {
    registers_state: RegistersStateEvent,
    memory_access: MemoryAccessEvent,
};

pub const CpuBoundary = struct {
    pc: u32,
    registers: [32]u32,
    predecessor_clocks: [32]u32,
};

/// Copyable public summary derived only after authenticating the retained V2
/// wire.  Digests stay in native Poseidon2-M31 words; no byte reinterpretation
/// or lossy field reduction occurs at this boundary.
pub const Metadata = struct {
    format_version: u16,
    schema_version: u16,
    session_id: Digest,
    job_id: Digest,
    position_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    lineage_id: Digest,
    base_statement_id: Digest,
    wire_id: Digest,
    program: Digest,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,
    global_cycle_end: u32,
    is_first: bool,
    is_final: bool,
    entry_cpu: CpuBoundary,
    exit_cpu: CpuBoundary,
    public_input: ?Digest,
    public_output: ?Digest,
    completion: ?segment_v2.CompletionV2,
};

pub const EventCounts = struct {
    registers_state: usize,
    register_memory: usize,
    rw_memory: usize,
    memory_address_count: usize,
    total: usize,
};

/// Authentication token over a canonical segment wire.
///
/// Ordinary borrowed values remain mutation-sensitive by re-authenticating on
/// every use. Values minted by `OwnedValidatedLeaseV2` instead point to one
/// privately owned immutable allocation and reuse its complete authenticated
/// view after constant-size pointer/value closure checks.
pub const PublicDataV2 = struct {
    canonical_words: []const M31,
    authenticated_wire_id: Digest,
    retained_snapshots: ?RetainedSnapshots = null,
    validated_lease: ?*const ValidatedLeaseV2 = null,

    const Self = @This();

    /// Opaque, process-local proof that one immutable owned wire has already
    /// crossed a complete authentication boundary. It has no wire encoding
    /// and cannot be reconstructed from a digest.
    pub const ValidatedLeaseV2 = opaque {};

    pub const RetainedSnapshots = struct {
        entry: segment_v2.SnapshotIdentity,
        exit: segment_v2.SnapshotIdentity,
    };

    pub const ValidationCounterSnapshotV2 = struct {
        retained_root_authentications: u64,
        retained_root_authentication_ns: u64,
        authority_validations: u64,
        authority_validation_ns: u64,
        cached_view_reuses: u64,
        legacy_full_authentications: u64,
    };

    pub const ValidationCountersV2 = struct {
        retained_root_authentications: std.atomic.Value(u64) = .init(0),
        retained_root_authentication_ns: std.atomic.Value(u64) = .init(0),
        authority_validations: std.atomic.Value(u64) = .init(0),
        authority_validation_ns: std.atomic.Value(u64) = .init(0),
        cached_view_reuses: std.atomic.Value(u64) = .init(0),
        legacy_full_authentications: std.atomic.Value(u64) = .init(0),

        pub fn snapshot(
            self: *const ValidationCountersV2,
        ) ValidationCounterSnapshotV2 {
            return .{
                .retained_root_authentications = self.retained_root_authentications.load(.acquire),
                .retained_root_authentication_ns = self.retained_root_authentication_ns.load(.acquire),
                .authority_validations = self.authority_validations.load(.acquire),
                .authority_validation_ns = self.authority_validation_ns.load(.acquire),
                .cached_view_reuses = self.cached_view_reuses.load(.acquire),
                .legacy_full_authentications = self.legacy_full_authentications.load(.acquire),
            };
        }

        pub fn recordAuthorityValidation(
            self: *ValidationCountersV2,
            elapsed_ns: u64,
        ) void {
            _ = self.authority_validations.fetchAdd(1, .monotonic);
            _ = self.authority_validation_ns.fetchAdd(elapsed_ns, .monotonic);
        }

        pub fn recordLegacyFullAuthentication(
            self: *ValidationCountersV2,
        ) void {
            _ = self.legacy_full_authentications.fetchAdd(1, .monotonic);
        }
    };

    /// Sole owner of one validated immutable wire. `adoptRetained` consumes
    /// `owned_words` on success; no mutable slice is exposed afterwards.
    pub const OwnedValidatedLeaseV2 = struct {
        storage: *ValidatedLeaseStorageV2,
        data_value: PublicDataV2,

        pub fn adoptRetained(
            allocator: std.mem.Allocator,
            owned_words: []M31,
            retained: RetainedSnapshots,
            counters: ?*ValidationCountersV2,
        ) !OwnedValidatedLeaseV2 {
            const validation_start = if (counters != null)
                std.time.nanoTimestamp()
            else
                0;
            const view = try segment_v2.authenticateCanonicalWireReusingRoots(
                owned_words,
                retained.entry,
                retained.exit,
            );
            _ = try metadataFromView(&view);
            const storage = allocator.create(ValidatedLeaseStorageV2) catch
                return error.OutOfMemory;
            errdefer allocator.destroy(storage);
            storage.* = .{
                .allocator = allocator,
                .owned_words = owned_words,
                .retained = retained,
                .view = view,
                .counters = counters,
            };
            if (counters) |value| {
                _ = value.retained_root_authentications.fetchAdd(1, .monotonic);
                _ = value.retained_root_authentication_ns.fetchAdd(
                    elapsedNanoseconds(validation_start),
                    .monotonic,
                );
            }
            const token: *const ValidatedLeaseV2 = @ptrCast(storage);
            return .{
                .storage = storage,
                .data_value = .{
                    .canonical_words = owned_words,
                    .authenticated_wire_id = view.wire_id,
                    .retained_snapshots = retained,
                    .validated_lease = token,
                },
            };
        }

        pub fn initRetained(
            allocator: std.mem.Allocator,
            source: *const PublicDataV2,
            retained: RetainedSnapshots,
            counters: ?*ValidationCountersV2,
        ) !OwnedValidatedLeaseV2 {
            const owned_copy = allocator.dupe(M31, source.words()) catch
                return error.OutOfMemory;
            var result = adoptRetained(
                allocator,
                owned_copy,
                retained,
                counters,
            ) catch |err| {
                allocator.free(owned_copy);
                return err;
            };
            errdefer result.deinit();
            if (!std.meta.eql(
                result.data_value.wireId(),
                source.wireId(),
            )) return error.SourceMutation;
            return result;
        }

        pub fn deinit(self: *OwnedValidatedLeaseV2) void {
            const storage = self.storage;
            const allocator = storage.allocator;
            allocator.free(storage.owned_words);
            allocator.destroy(storage);
            self.* = undefined;
        }

        pub fn data(self: *const OwnedValidatedLeaseV2) *const PublicDataV2 {
            return &self.data_value;
        }

        pub fn ownedWords(
            self: *const OwnedValidatedLeaseV2,
        ) []const M31 {
            return self.storage.owned_words;
        }
    };

    pub fn authenticate(canonical_words: []const M31) Error!Self {
        const view = try segment_v2.authenticateCanonicalWire(canonical_words);
        _ = try metadataFromView(&view);
        return .{
            .canonical_words = canonical_words,
            .authenticated_wire_id = view.wire_id,
        };
    }

    /// Authenticate a cold canonical wire against the exact snapshot
    /// authorities retained by STWESG31. Every sparse tuple, count, digest,
    /// clock map, and fixed statement field is still replayed. Only the two
    /// already-bound continuation roots avoid recomputation.
    pub fn authenticateReusingRoots(
        canonical_words: []const M31,
        retained: RetainedSnapshots,
    ) Error!Self {
        const view = try segment_v2.authenticateCanonicalWireReusingRoots(
            canonical_words,
            retained.entry,
            retained.exit,
        );
        _ = try metadataFromView(&view);
        return .{
            .canonical_words = canonical_words,
            .authenticated_wire_id = view.wire_id,
            .retained_snapshots = retained,
        };
    }

    pub fn words(self: *const Self) []const M31 {
        return self.canonical_words;
    }

    pub fn wireId(self: *const Self) Digest {
        return self.authenticated_wire_id;
    }

    pub fn validate(self: *const Self) Error!void {
        _ = try self.freshView();
    }

    pub fn metadata(self: *const Self) Error!Metadata {
        const view = try self.freshView();
        return metadataFromView(&view);
    }

    /// Create an allocation-free iterator over the exact canonical boundary
    /// events.  The unique sparse address count is preflighted once; `next`
    /// itself is infallible and visits every retained tuple at most once.
    pub fn eventCursor(self: *const Self) Error!EventCursor {
        const view = try self.freshView();
        const metadata_v2 = try metadataFromView(&view);
        return EventCursor.init(view, metadata_v2);
    }

    pub fn eventCounts(self: *const Self) Error!EventCounts {
        const cursor = try self.eventCursor();
        return cursor.counts;
    }

    /// Exact-size, fail-atomic materialization for consumers which need a flat
    /// array.  Streaming consumers should prefer `eventCursor`.
    pub fn writeBoundaryEvents(
        self: *const Self,
        destination: []BoundaryEvent,
    ) Error!EventCounts {
        var cursor = try self.eventCursor();
        if (destination.len != cursor.counts.total)
            return error.OutputLengthMismatch;

        var at: usize = 0;
        while (cursor.next()) |event| {
            destination[at] = event;
            at += 1;
        }
        std.debug.assert(at == destination.len);
        return cursor.counts;
    }

    /// Canonical V2 transcript frame.  All validation is complete before the
    /// channel is touched, preserving fail-atomicity for malformed input.
    pub fn mixInto(self: *const Self, transcript: anytype) Error!void {
        const view = try self.freshView();
        const word_count = std.math.cast(u32, view.words.len) orelse
            return error.TranscriptWordCountOverflow;
        transcript.mixU32s(&.{
            STATEMENT_TRANSCRIPT_DOMAIN,
            STATEMENT_TRANSCRIPT_VERSION,
            STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
            word_count,
        });
        transcript.mixU32s(&view.wire_id);
        view.mixInto(transcript);
    }

    /// Re-authenticate two immutable V2 tokens and return the canonical
    /// adjacent-span receipt.  Stored identity comparison rejects mutation of
    /// either backing allocation after its original authentication.
    pub fn authenticateAdjacent(
        left: *const Self,
        right: *const Self,
    ) Error!segment_v2.AdjacentReceiptV2 {
        const receipt = try segment_v2.authenticateAdjacentCanonicalWires(
            left.canonical_words,
            right.canonical_words,
        );
        if (!std.meta.eql(receipt.left_wire_id, left.authenticated_wire_id) or
            !std.meta.eql(receipt.right_wire_id, right.authenticated_wire_id))
        {
            return error.SourceMutation;
        }
        return receipt;
    }

    pub fn authenticatedView(
        self: *const Self,
    ) Error!segment_v2.CanonicalWireViewV2 {
        return self.freshView();
    }

    fn freshView(self: *const Self) Error!segment_v2.CanonicalWireViewV2 {
        if (self.validated_lease) |token| {
            const storage: *const ValidatedLeaseStorageV2 = @ptrCast(@alignCast(
                token,
            ));
            if (self.canonical_words.ptr != storage.owned_words.ptr or
                self.canonical_words.len != storage.owned_words.len or
                storage.view.words.ptr != storage.owned_words.ptr or
                storage.view.words.len != storage.owned_words.len or
                !std.meta.eql(self.authenticated_wire_id, storage.view.wire_id) or
                self.retained_snapshots == null or
                !std.meta.eql(self.retained_snapshots.?, storage.retained))
            {
                return error.SourceMutation;
            }
            if (storage.counters) |value| _ = value.cached_view_reuses
                .fetchAdd(1, .monotonic);
            return storage.view;
        }
        const view = if (self.retained_snapshots) |retained|
            try segment_v2.authenticateCanonicalWireReusingRoots(
                self.canonical_words,
                retained.entry,
                retained.exit,
            )
        else
            try segment_v2.authenticateCanonicalWire(self.canonical_words);
        if (!std.meta.eql(view.wire_id, self.authenticated_wire_id))
            return error.SourceMutation;
        _ = try metadataFromView(&view);
        return view;
    }
};

const ValidatedLeaseStorageV2 = struct {
    allocator: std.mem.Allocator,
    owned_words: []M31,
    retained: PublicDataV2.RetainedSnapshots,
    view: segment_v2.CanonicalWireViewV2,
    counters: ?*PublicDataV2.ValidationCountersV2,
};

fn elapsedNanoseconds(start: i128) u64 {
    const elapsed = std.time.nanoTimestamp() - start;
    if (elapsed <= 0) return 0;
    return std.math.cast(u64, elapsed) orelse std.math.maxInt(u64);
}

/// Infallible cursor after authentication and count preflight.
pub const EventCursor = struct {
    view: segment_v2.CanonicalWireViewV2,
    metadata_v2: Metadata,
    counts: EventCounts,
    fixed_at: usize = 0,
    memory_positions: [4]usize = .{0} ** 4,
    pending_memory: ?MemoryBoundary = null,

    fn init(
        view: segment_v2.CanonicalWireViewV2,
        metadata_v2: Metadata,
    ) Error!EventCursor {
        const memory_address_count = uniqueMemoryAddressCount(&view);
        const rw_events = std.math.mul(usize, memory_address_count, 2) catch
            return error.ExecutionRangeOutOfBounds;
        const total = std.math.add(
            usize,
            FIXED_BOUNDARY_EVENT_COUNT,
            rw_events,
        ) catch return error.ExecutionRangeOutOfBounds;
        if (total > MAX_BOUNDARY_EVENT_COUNT)
            return error.ExecutionRangeOutOfBounds;
        return .{
            .view = view,
            .metadata_v2 = metadata_v2,
            .counts = .{
                .registers_state = 2,
                .register_memory = 2 * 32,
                .rw_memory = rw_events,
                .memory_address_count = memory_address_count,
                .total = total,
            },
        };
    }

    pub fn metadata(self: *const EventCursor) Metadata {
        return self.metadata_v2;
    }

    pub fn next(self: *EventCursor) ?BoundaryEvent {
        if (self.fixed_at < FIXED_BOUNDARY_EVENT_COUNT) {
            const index = self.fixed_at;
            self.fixed_at += 1;
            if (index == 0) {
                return .{ .registers_state = .{
                    .direction = .consume,
                    .pc = self.metadata_v2.entry_cpu.pc,
                    .clock = self.metadata_v2.global_cycle_start + 1,
                } };
            }
            if (index == 1) {
                return .{ .registers_state = .{
                    .direction = .produce,
                    .pc = self.metadata_v2.exit_cpu.pc,
                    .clock = self.metadata_v2.global_cycle_end + 1,
                } };
            }

            const register_event = index - 2;
            const register = register_event / 2;
            const is_exit = register_event % 2 == 1;
            return .{ .memory_access = .{
                .direction = if (is_exit) .produce else .consume,
                .address_space = 0,
                .address = @intCast(register),
                .predecessor_clock = if (is_exit)
                    self.metadata_v2.exit_cpu.predecessor_clocks[register]
                else
                    self.metadata_v2.entry_cpu.predecessor_clocks[register],
                .value = if (is_exit)
                    self.metadata_v2.exit_cpu.registers[register]
                else
                    self.metadata_v2.entry_cpu.registers[register],
            } };
        }

        if (self.pending_memory) |boundary| {
            self.pending_memory = null;
            return .{ .memory_access = .{
                .direction = .produce,
                .address_space = 1,
                .address = boundary.address,
                .predecessor_clock = boundary.exit_clock,
                .value = boundary.exit_value,
            } };
        }

        const boundary = nextMemoryBoundary(
            &self.view,
            &self.memory_positions,
        ) orelse return null;
        self.pending_memory = boundary;
        return .{ .memory_access = .{
            .direction = .consume,
            .address_space = 1,
            .address = boundary.address,
            .predecessor_clock = boundary.entry_clock,
            .value = boundary.entry_value,
        } };
    }
};

fn metadataFromView(view: *const segment_v2.CanonicalWireViewV2) Error!Metadata {
    const base = try view.statement.base();
    const executed = switch (base.body) {
        .empty => return error.SegmentLeafRequired,
        .executed => |value| value,
    };
    if (executed.segment_count != 1 or base.slots.height != 0)
        return error.SegmentLeafRequired;
    if (!profile.isInstructionAligned(executed.entry.pc))
        return error.MisalignedEntryPc;
    if (!profile.isInstructionAligned(executed.exit.pc))
        return error.MisalignedExitPc;

    const end_u64 = std.math.add(
        u64,
        executed.first_cycle,
        executed.cycle_count,
    ) catch return error.ExecutionRangeOutOfBounds;
    if (executed.first_cycle > segment_v2.MAX_GLOBAL_CYCLES or
        end_u64 > segment_v2.MAX_GLOBAL_CYCLES)
    {
        return error.ExecutionRangeOutOfBounds;
    }
    const start: u32 = @intCast(executed.first_cycle);
    const end: u32 = @intCast(end_u64);
    const is_first = executed.first_segment == 0;
    const is_final = executed.endSegment() == base.job.segment_count;
    if ((executed.input.digest != null) != is_first)
        return error.InputCustodyMismatch;
    if ((executed.output.digest != null) != is_final)
        return error.OutputCustodyMismatch;
    if ((view.statement.completion != null) != is_final)
        return if (is_final) error.CompletionMissing else error.CompletionForbidden;

    if (view.statement.completion) |completion| {
        if (completion.kind == .halt_flag) {
            const value = sparseValueAt(
                view,
                view.exit_snapshot,
                completion.address,
            );
            const clock = predecessorClockAt(
                view,
                view.exit_memory_clocks,
                completion.address,
            );
            if (value != completion.value or clock != completion.clock)
                return error.CompletionBoundaryMismatch;
        }
    }

    return .{
        .format_version = view.statement.format_version,
        .schema_version = view.statement.schema_version,
        .session_id = view.statement.session_id,
        .job_id = view.statement.job_id,
        .position_id = view.statement.position_id,
        .entry_lineage_id = view.statement.entry_lineage_id,
        .exit_lineage_id = view.statement.exit_lineage_id,
        .lineage_id = view.statement.lineage_id,
        .base_statement_id = view.statement.base_statement_id,
        .wire_id = view.wire_id,
        .program = base.job.complete.program,
        .entry_continuation_root = view.statement.entry_continuation_root,
        .exit_continuation_root = view.statement.exit_continuation_root,
        .segment_index = executed.first_segment,
        .segment_count = base.job.segment_count,
        .global_cycle_start = start,
        .global_cycle_end = end,
        .is_first = is_first,
        .is_final = is_final,
        .entry_cpu = .{
            .pc = executed.entry.pc,
            .registers = executed.entry.registers,
            .predecessor_clocks = view.statement.entry_register_clocks,
        },
        .exit_cpu = .{
            .pc = executed.exit.pc,
            .registers = executed.exit.registers,
            .predecessor_clocks = view.statement.exit_register_clocks,
        },
        .public_input = executed.input.digest,
        .public_output = executed.output.digest,
        .completion = view.statement.completion,
    };
}

const MemoryBoundary = struct {
    address: u32,
    entry_value: u32,
    exit_value: u32,
    entry_clock: u32,
    exit_clock: u32,
};

fn uniqueMemoryAddressCount(view: *const segment_v2.CanonicalWireViewV2) usize {
    var positions = [_]usize{0} ** 4;
    var count: usize = 0;
    while (nextMemoryBoundary(view, &positions) != null) count += 1;
    return count;
}

/// Four-way ordered merge over entry/exit sparse values and entry/exit clock
/// maps.  Taking the union across both sides is essential: a newly written
/// zero-default address has no entry sparse tuple, but its entry-consume event
/// must still exist with `(clock=0,value=0)`.
fn nextMemoryBoundary(
    view: *const segment_v2.CanonicalWireViewV2,
    positions: *[4]usize,
) ?MemoryBoundary {
    const entry_value_address = sparseAddress(
        view,
        view.entry_snapshot,
        positions[0],
    );
    const exit_value_address = sparseAddress(
        view,
        view.exit_snapshot,
        positions[1],
    );
    const entry_clock_address = clockAddress(
        view,
        view.entry_memory_clocks,
        positions[2],
    );
    const exit_clock_address = clockAddress(
        view,
        view.exit_memory_clocks,
        positions[3],
    );

    var address: ?u32 = null;
    inline for (.{
        entry_value_address,
        exit_value_address,
        entry_clock_address,
        exit_clock_address,
    }) |candidate| {
        if (candidate) |value| {
            if (address == null or value < address.?) address = value;
        }
    }
    const selected = address orelse return null;

    var result = MemoryBoundary{
        .address = selected,
        .entry_value = 0,
        .exit_value = 0,
        .entry_clock = 0,
        .exit_clock = 0,
    };
    if (entry_value_address == selected) {
        result.entry_value = view.sparseEntry(
            view.entry_snapshot,
            positions[0],
        ).value;
        positions[0] += 1;
    }
    if (exit_value_address == selected) {
        result.exit_value = view.sparseEntry(
            view.exit_snapshot,
            positions[1],
        ).value;
        positions[1] += 1;
    }
    if (entry_clock_address == selected) {
        result.entry_clock = view.clockEntry(
            view.entry_memory_clocks,
            positions[2],
        ).clock;
        positions[2] += 1;
    }
    if (exit_clock_address == selected) {
        result.exit_clock = view.clockEntry(
            view.exit_memory_clocks,
            positions[3],
        ).clock;
        positions[3] += 1;
    }
    return result;
}

fn sparseAddress(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    index: usize,
) ?u32 {
    if (index >= section.count) return null;
    return view.sparseEntry(section, index).address;
}

fn clockAddress(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    index: usize,
) ?u32 {
    if (index >= section.count) return null;
    return view.clockEntry(section, index).address;
}

fn sparseValueAt(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    address: u32,
) u32 {
    var low: usize = 0;
    var high: usize = section.count;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const entry = view.sparseEntry(section, middle);
        if (entry.address < address) {
            low = middle + 1;
        } else if (entry.address > address) {
            high = middle;
        } else {
            return entry.value;
        }
    }
    return 0;
}

fn predecessorClockAt(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    address: u32,
) u32 {
    var low: usize = 0;
    var high: usize = section.count;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const entry = view.clockEntry(section, middle);
        if (entry.address < address) {
            low = middle + 1;
        } else if (entry.address > address) {
            high = middle;
        } else {
            return entry.clock;
        }
    }
    return 0;
}
