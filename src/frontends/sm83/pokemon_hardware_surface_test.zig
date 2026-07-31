const std = @import("std");
const surface = @import("pokemon_hardware_surface.zig");

test "SM83 Pokemon benchmark hardware surface is target admissible" {
    const corpus_root = std.posix.getenv("SM83_POKEMON_CORPUS") orelse
        return error.SkipZigTest;
    const report = try surface.auditBenchmark(std.testing.allocator, corpus_root);
    try std.testing.expectEqualDeep(surface.BENCHMARK_EXPECTED, report);
}

test "SM83 Pokemon hardware surface expected counts are fail closed" {
    var drifted = surface.EXPECTED;
    drifted.apu.accesses.writes -= 1;
    try std.testing.expectError(
        error.PokemonHardwareSurfaceDrift,
        surface.validateReport(drifted),
    );

    var invalid = surface.EXPECTED;
    invalid.vram.accesses.writes = 0;
    try std.testing.expectError(
        error.PokemonHardwareSurfaceDrift,
        surface.validatePositive(invalid),
    );

    var apu_count = surface.EXPECTED;
    apu_count.apu_semantics.events -= 1;
    try std.testing.expectError(
        error.PokemonHardwareSurfaceDrift,
        surface.validateReport(apu_count),
    );

    var apu_order = surface.EXPECTED;
    apu_order.apu_semantics.ordered_wave_bursts -= 1;
    try std.testing.expectError(
        error.PokemonHardwareSurfaceDrift,
        surface.validateReport(apu_order),
    );

    var stopped = surface.EXPECTED;
    stopped.unsupported_semantics.stopped_boundary_rows = 1;
    try std.testing.expectError(
        error.PokemonHardwareSurfaceDrift,
        surface.validateReport(stopped),
    );
}

test "SM83 Pokemon hardware surface pinned replay remains exact" {
    const corpus_root = std.posix.getenv("SM83_POKEMON_CORPUS") orelse
        return error.SkipZigTest;
    const report = try surface.audit(std.testing.allocator, corpus_root);
    try std.testing.expectEqualDeep(surface.EXPECTED, report);
}
