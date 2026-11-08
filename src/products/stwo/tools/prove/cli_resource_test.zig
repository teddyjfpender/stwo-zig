const std = @import("std");
const cli = @import("prove_cli");
const runner = @import("native_proof_runner");
const resource_admission = @import("native_resource_admission");

test "resource profile parser matches shared Native admission policy" {
    try std.testing.expectError(error.InvalidLogRows, cli.parse(&.{
        "prove",      "--air",      "xor",        "--backend",  "cpu",
        "--output",   "proof.json", "--log-size", "4294967295", "--log-step",
        "4294967295",
    }));
    try std.testing.expectError(error.CommittedCellBudgetExceeded, cli.parse(&.{
        "prove",    "--air",      "wide_fibonacci", "--backend", "cpu",
        "--output", "proof.json", "--log-n-rows",   "20",        "--sequence-len",
        "100",
    }));
    const large = (try cli.parse(&.{
        "prove",    "--air",              "wide_fibonacci", "--backend", "cpu",
        "--output", "proof.json",         "--log-n-rows",   "20",        "--sequence-len",
        "100",      "--resource-profile", "large",
    })).prove.run;
    try std.testing.expectEqual(cli.ResourceProfile.large, large.resource_profile);
    const admitted = try cli.admitWorkload(large.workload, large.resource_profile);
    try std.testing.expectEqual(@as(u64, 104_857_600), admitted.geometry.committed_cells);
    try std.testing.expectEqual(
        resource_admission.LARGE_MAX_ACCOUNTED_BYTES,
        admitted.limits.max_accounted_bytes,
    );
    try std.testing.expectError(error.CommittedCellBudgetExceeded, cli.parse(&.{
        "prove",    "--air",              "wide_fibonacci", "--backend", "cpu",
        "--output", "proof.json",         "--log-n-rows",   "22",        "--sequence-len",
        "100",      "--resource-profile", "large",
    }));
    try std.testing.expectError(error.InvalidResourceProfile, cli.parse(&.{
        "prove",              "--air",     "plonk", "--backend", "cpu", "--output", "proof.json",
        "--resource-profile", "unbounded",
    }));
    try std.testing.expectError(error.ResourceProfileExcludesElf, cli.parse(&.{
        "prove",              "--elf", "guest.elf", "--backend", "cpu", "--output", "proof.json",
        "--resource-profile", "large",
    }));
}

test "aggregate and focused parsers produce identical large-profile admission" {
    const focused = (try runner.config.parseArgs(.cpu_native, &.{
        "--example",          "wide_fibonacci",
        "--log-n-rows",       "20",
        "--sequence-len",     "100",
        "--resource-profile", "large",
    })).run;
    const aggregate = (try cli.parse(&.{
        "prove",    "--air",              "wide_fibonacci", "--backend", "cpu",
        "--output", "proof.json",         "--log-n-rows",   "20",        "--sequence-len",
        "100",      "--resource-profile", "large",
    })).prove.run;
    const focused_admission = try runner.config.admitWorkload(
        focused.workload(),
        focused.resource_profile,
    );
    const aggregate_admission = try cli.admitWorkload(
        aggregate.workload,
        aggregate.resource_profile,
    );
    try std.testing.expectEqual(focused_admission.profile, aggregate_admission.profile);
    try std.testing.expectEqual(focused_admission.geometry, aggregate_admission.geometry);
    try std.testing.expectEqual(focused_admission.limits, aggregate_admission.limits);
}
