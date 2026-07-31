//! Pinned inputs and endpoint helpers for the Pokemon checkpoint fixture.

const std = @import("std");
const memory_image = @import("memory.zig");
const sameboy_checkpoint = @import("checkpoint/sameboy.zig");
const battle_actions = @import("pokemon_battle_actions.zig");
const profile_config = @import("pokemon_checkpoint_fixture_profile.zig");
const ram_observation = @import("ram_observation.zig");
const runner = @import("runner/mod.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");

pub const Artifacts = struct {
    rom_path: []const u8,
    rom_sha256: []const u8,
    checkpoint_path: []const u8,
    checkpoint_sha256: []const u8,
    trace_path: []const u8,
    trace_sha256: []const u8,
    trace_size: usize,
    trace_records: usize,
    initial_mcycle: u32,
    initial_pressed: u8,
};

pub const VISUAL_ARTIFACTS: Artifacts = .{
    .rom_path = "pokered_rogue_e2e.gbc",
    .rom_sha256 = "ebc21f5a683278aeb690a4cbad9576e33ee42fbe271d44e103047576d4108327",
    .checkpoint_path = "build/traces/battle-seed-1/boundary-000000.s1",
    .checkpoint_sha256 = "c4d99e64d7a08e1828af6bdc0d9e5f930bd7315f137eb1f8d518cd5a9c9f31ea",
    .trace_path = "build/traces/battle-seed-1/instructions.bin",
    .trace_sha256 = "58c4462e9370163a9714f3a9d9195fa8735b2496e04c1b5b6abf81760feec59d",
    .trace_size = 182_452_224,
    .trace_records = 6_291_456,
    .initial_mcycle = 13_312_966,
    // PE-AGI applies frame 760 before capture; 760 mod 40 presses START.
    .initial_pressed = runner.joypad.Key.start.mask(),
};

pub const PROOF_FAST_ARTIFACTS: Artifacts = .{
    .rom_path = "pokered_rogue_fast_e2e.gbc",
    .rom_sha256 = "fa7a4a2a0d2bc3a1911ae4cec883b382e2db7671a843248ff583fd408f6f9283",
    .checkpoint_path = "build/traces/battle-seed-1-fast/boundary-000000.s1",
    .checkpoint_sha256 = "1749ebdbd39ce73c0409be0ec8b3fb53df03f314d762f8116bbf5af879184190",
    .trace_path = "build/traces/battle-seed-1-fast/instructions.bin",
    .trace_sha256 = "83ca922367d3609ae9f63039452fc1eb16813edb4ad00fc6a4ff412654118e18",
    .trace_size = 30_408_704,
    .trace_records = 1_048_576,
    .initial_mcycle = 5_967_713,
    // PE-AGI applies frame 340 before capture; 340 mod 40 presses A.
    .initial_pressed = runner.joypad.Key.a.mask(),
};

pub const MAX_LOOKAHEAD_ROWS: usize = 1 << 15;
pub const LOOKAHEAD_ORACLE_RECORDS: usize = 1;
pub const FRAME_TICKS_8MHZ: u64 = 139_810;
pub const ENDPOINT_NORMALIZATION_MASK: u16 = 1 << 4;

pub const Profile = profile_config.Profile;
pub const profileSpec = profile_config.spec;

/// `wPartyDataStart` and `wPartyDataEnd` in the pinned ROM symbol file.
pub const PARTY_DATA_START: u16 = 0xd163;
pub const PARTY_DATA_END: u16 = 0xd2f7;
pub const PARTY_DATA_LENGTH: u32 = PARTY_DATA_END - PARTY_DATA_START;
pub const PARTY_COUNT_ADDRESS: u16 = PARTY_DATA_START;
pub const PARTY_SPECIES_ADDRESS: u16 = PARTY_DATA_START + 1;
pub const PINNED_PARTY_COUNT: u8 = 1;
pub const PINNED_FIRST_SPECIES: u8 = 0x84;

pub const OBSERVATION_REGIONS = [_]ram_observation.Region{.{
    .space = .system,
    .start = PARTY_DATA_START,
    .length = PARTY_DATA_LENGTH,
}};

pub fn images(
    system: *const [memory_lookup.SYSTEM_SIZE]u8,
    sram: *const [memory_lookup.SRAM_SIZE]u8,
) memory_lookup.Images {
    return .{
        .system = memory_image.Image.init(system) catch unreachable,
        .sram = memory_lookup.SramImage.init(sram) catch unreachable,
    };
}

pub fn ppuBindingState(ppu: runner.ppu_mmio.State) ppu_binding.State {
    return .{
        .timing = ppu.timing,
        .lcdc = ppu.lcdc,
        .scy = ppu.scy,
        .scx = ppu.scx,
        .wy = ppu.wy,
    };
}

pub fn artifactsFor(profile: Profile) Artifacts {
    return if (isProofFast(profile))
        PROOF_FAST_ARTIFACTS
    else
        VISUAL_ARTIFACTS;
}

pub fn actionsFor(
    profile: Profile,
) []const @import("action_schedule.zig").Action {
    return if (isProofFast(profile))
        &battle_actions.PROOF_FAST_ACTIONS
    else
        &battle_actions.ACTIONS;
}

pub fn isProofFast(profile: Profile) bool {
    return switch (profile) {
        .proof_fast_short, .proof_fast_dma_probe, .proof_fast_chunk_1, .proof_fast_chunk_2 => true,
        .short, .start_release, .battle_chunk_1, .battle_chunk_2 => false,
    };
}

pub fn normalizeProofFastPpuBoundary(
    checkpoint: *sameboy_checkpoint.Checkpoint,
) !void {
    const stat_address = runner.ppu_mmio.STAT_ADDRESS;
    if (checkpoint.timer.display_cycles != 374 or
        checkpoint.ppu.cycles_for_line != 89 or
        checkpoint.ppu.current_line != 1 or
        checkpoint.ppu.current_lcd_line != 1 or
        checkpoint.ppu.mode_for_interrupt != 3 or
        checkpoint.system[stat_address] != 0x83)
    {
        return error.UnpinnedProofFastPpuBoundary;
    }
    // SameBoy's variable mode-3 transfer is still active at canonical dot
    // 272. The current fixed PPU projection preserves that exact line/dot but
    // owns mode 0 there. Normalize only those two saved mode fields; the raw
    // checkpoint hash and every CPU callback remain independently pinned.
    try normalizeProofFastPpuMode(
        &checkpoint.ppu.mode_for_interrupt,
        &checkpoint.system[stat_address],
    );
}

pub fn normalizeProofFastPpuMode(mode: *u8, stat: *u8) !void {
    if (mode.* != 3 or stat.* != 0x83)
        return error.UnpinnedProofFastPpuBoundary;
    mode.* = 0;
    stat.* = 0x80;
}

pub fn partyObservations(mcycle: u32) [2]observation.Sample {
    return .{
        .{
            .mcycle = mcycle,
            .key = PARTY_COUNT_ADDRESS,
            .expected = PINNED_PARTY_COUNT,
        },
        .{
            .mcycle = mcycle,
            .key = PARTY_SPECIES_ADDRESS,
            .expected = PINNED_FIRST_SPECIES,
        },
    };
}

pub fn validateDmaSourceArity(actual: usize, expected: usize) !void {
    if (actual != expected)
        return error.DmaSourceArityMismatch;
}

pub fn validatePositiveCounts(
    spec: profile_config.Spec,
    oracle_start: usize,
    prefix_instructions: usize,
    prefix_mcycles: u32,
    lookahead_rows: usize,
    oracle_records: usize,
    require_lookahead: bool,
) !void {
    if (prefix_instructions == 0)
        return error.InvalidFixturePositiveCounts;
    if (prefix_instructions != spec.instructions or
        prefix_mcycles != spec.mcycles)
        return error.InvalidFixturePositiveCounts;
    const expected_records = oracle_start + prefix_instructions +
        @as(usize, @intFromBool(require_lookahead)) *
            LOOKAHEAD_ORACLE_RECORDS;
    if (oracle_records != expected_records)
        return error.InvalidFixturePositiveCounts;
    if (require_lookahead) {
        if (lookahead_rows == 0 or
            lookahead_rows != spec.lookahead_rows)
        {
            return error.InvalidFixturePositiveCounts;
        }
    } else if (lookahead_rows != 0) {
        return error.InvalidFixturePositiveCounts;
    }
}

pub fn validatePinnedParty(
    system: *const [memory_lookup.SYSTEM_SIZE]u8,
) !void {
    if (system[PARTY_COUNT_ADDRESS] != PINNED_PARTY_COUNT)
        return error.PinnedPartyCountMismatch;
    if (system[PARTY_SPECIES_ADDRESS] != PINNED_FIRST_SPECIES)
        return error.PinnedPartySpeciesMismatch;
}
