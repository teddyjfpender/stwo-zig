//! Replay geometry and pinned artifact loading for Pokemon checkpoint sessions.

const std = @import("std");
const cartridge = @import("cartridge/mod.zig");
const sameboy_checkpoint = @import("checkpoint/sameboy.zig");
const oracle = @import("sameboy_instruction_trace.zig");
const artifact = @import("pokemon_checkpoint_fixture_artifact.zig");
const fixture = @import("pokemon_checkpoint_fixture.zig");

pub const MAX_LOOKAHEAD_ROWS: usize = 1 << 15;
pub const DEFAULT_ROWS: usize = 1 << 17;
pub const MAX_ROWS: usize = 1 << 24;

pub const Profile = enum {
    visual,
    proof_fast,
};

pub const Options = struct {
    profile: Profile = .visual,
    rows: usize = DEFAULT_ROWS,

    pub fn validate(self: Options) !void {
        if (self.rows < 16 or
            self.rows > MAX_ROWS or
            !std.math.isPowerOfTwo(self.rows))
        {
            return error.InvalidChunkRows;
        }
    }
};

/// Optional pinned counts for one chunk. `next_instruction_rows` is the
/// number of rows after this chunk through the next instruction callback.
pub const Expectation = struct {
    callbacks: usize,
    mcycles: u32,
    dma_source_bytes: usize,
    actions: usize,
    next_instruction_rows: ?usize = null,
};

/// Visual-ROM prefix proven equivalent to SameBoy at 2^17 rows each.
pub const VERIFIED_PREFIX = [_]Expectation{
    .{
        .callbacks = 25_115,
        .mcycles = 163_027,
        .dma_source_bytes = 1_440,
        .actions = 1,
        .next_instruction_rows = 10_427,
    },
    .{
        .callbacks = 8_809,
        .mcycles = 142_224,
        .dma_source_bytes = 1_280,
        .actions = 0,
        .next_instruction_rows = 8_651,
    },
    .{
        .callbacks = 8_378,
        .mcycles = 141_631,
        .dma_source_bytes = 1_280,
        .actions = 1,
        .next_instruction_rows = 7_468,
    },
};

/// Proof-fast prefix proven equivalent to SameBoy at 2^17 rows each.
pub const PROOF_FAST_VERIFIED_PREFIX = [_]Expectation{
    .{
        .callbacks = 12_425,
        .mcycles = 146_040,
        .dma_source_bytes = 1_280,
        .actions = 0,
        .next_instruction_rows = 10_645,
    },
    .{
        .callbacks = 7_424,
        .mcycles = 141_366,
        .dma_source_bytes = 1_280,
        .actions = 1,
        .next_instruction_rows = 9_727,
    },
    .{
        .callbacks = 2_749,
        .mcycles = 135_677,
        .dma_source_bytes = 1_280,
        .actions = 1,
        .next_instruction_rows = 14_498,
    },
};

pub fn readRom(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    artifacts: fixture.Artifacts,
) ![]u8 {
    const bytes = try artifact.readPinned(
        allocator,
        directory,
        artifacts.rom_path,
        cartridge.header.ROM_SIZE,
        artifacts.rom_sha256,
    );
    errdefer allocator.free(bytes);
    if (bytes.len != cartridge.header.ROM_SIZE)
        return error.InvalidRomSize;
    return bytes;
}

pub fn readTrace(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    artifacts: fixture.Artifacts,
) ![]u8 {
    const bytes = try artifact.readPinned(
        allocator,
        directory,
        artifacts.trace_path,
        artifacts.trace_size,
        artifacts.trace_sha256,
    );
    errdefer allocator.free(bytes);
    const trace = try oracle.Trace.init(bytes);
    if (trace.count() != artifacts.trace_records)
        return error.InvalidTraceRecordCount;
    try trace.validateAll();
    if (try (try trace.record(0)).callbackMcycle() !=
        artifacts.initial_mcycle)
        return error.InvalidInitialClock;
    return bytes;
}

pub fn readCheckpoint(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    rom_bytes: []const u8,
    artifacts: fixture.Artifacts,
) !sameboy_checkpoint.Checkpoint {
    const bytes = try artifact.readPinned(
        allocator,
        directory,
        artifacts.checkpoint_path,
        sameboy_checkpoint.CHECKPOINT_SIZE,
        artifacts.checkpoint_sha256,
    );
    defer allocator.free(bytes);
    return sameboy_checkpoint.import(allocator, bytes, rom_bytes);
}

pub fn fixtureProfile(profile: Profile) fixture.Profile {
    return switch (profile) {
        .visual => .short,
        .proof_fast => .proof_fast_short,
    };
}

pub fn artifactsFor(profile: Profile) fixture.Artifacts {
    return fixture.artifactsFor(fixtureProfile(profile));
}

pub fn actionsFor(
    profile: Profile,
) []const @import("action_schedule.zig").Action {
    return fixture.actionsFor(fixtureProfile(profile));
}

pub fn normalizeCheckpoint(
    profile: Profile,
    checkpoint: *sameboy_checkpoint.Checkpoint,
) !void {
    if (profile == .proof_fast)
        try fixture.normalizeProofFastPpuBoundary(checkpoint);
}
