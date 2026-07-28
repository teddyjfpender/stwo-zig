const std = @import("std");

pub const FusionMode = enum {
    capped,
    experimental_hybrid_source_diagnostic,
};

/// Which trace-indexing ABI the emitted library implements. Structural, because
/// the two ABIs read different arena shapes out of the same `EvalLayout`
/// offsets and their kernels are therefore named apart.
pub const TraceAbiSelector = enum {
    /// `eval-domain` (default): columns are indexed directly at
    /// evaluation-domain length. This is what every compiled library in the tree
    /// implements and what the host lift pass exists to feed.
    eval_domain,
    /// `stored-domain` (increment 3.7 §5 option B): the kernel applies the
    /// product's lifting map itself, reading each column's `shift_amt` out of the
    /// runtime base-parameter block, so no host lift is needed.
    stored_domain,
};

pub const Options = struct {
    trace_abi: TraceAbiSelector = .eval_domain,
    fusion_mode: FusionMode = .capped,
    fusion_cap: usize,
    selected_only: bool = false,
    component_limit: ?usize = null,
};

pub fn parse(
    arguments: []const []const u8,
    default_fusion_cap: usize,
    maximum_fusion_cap: usize,
) !Options {
    var options = Options{ .fusion_cap = default_fusion_cap };
    var fusion_cap_explicit = false;
    var fusion_mode_explicit = false;
    var trace_abi_explicit = false;
    var argument_index: usize = 0;

    // Preserve the historical positional cap while preferring --fusion-cap.
    if (argument_index < arguments.len and
        !std.mem.startsWith(u8, arguments[argument_index], "--"))
    {
        options.fusion_cap = try parseFusionCap(arguments[argument_index], maximum_fusion_cap);
        fusion_cap_explicit = true;
        argument_index += 1;
    }

    while (argument_index < arguments.len) : (argument_index += 1) {
        const argument = arguments[argument_index];
        if (std.mem.eql(u8, argument, "--fusion-cap")) {
            if (fusion_cap_explicit or argument_index + 1 >= arguments.len)
                return error.InvalidArguments;
            argument_index += 1;
            options.fusion_cap = try parseFusionCap(
                arguments[argument_index],
                maximum_fusion_cap,
            );
            fusion_cap_explicit = true;
        } else if (std.mem.eql(u8, argument, "--experimental-hybrid-source-diagnostic")) {
            if (fusion_mode_explicit) return error.InvalidArguments;
            options.fusion_mode = .experimental_hybrid_source_diagnostic;
            fusion_mode_explicit = true;
        } else if (std.mem.eql(u8, argument, "--trace-abi")) {
            if (trace_abi_explicit or argument_index + 1 >= arguments.len)
                return error.InvalidArguments;
            argument_index += 1;
            options.trace_abi = try parseTraceAbi(arguments[argument_index]);
            trace_abi_explicit = true;
        } else if (std.mem.eql(u8, argument, "--selected-only")) {
            if (options.selected_only) return error.InvalidArguments;
            options.selected_only = true;
        } else if (std.mem.eql(u8, argument, "--component-limit")) {
            if (options.component_limit != null or argument_index + 1 >= arguments.len)
                return error.InvalidArguments;
            argument_index += 1;
            options.component_limit = try std.fmt.parseUnsigned(
                usize,
                arguments[argument_index],
                10,
            );
            if (options.component_limit.? == 0) return error.InvalidComponentLimit;
        } else {
            return error.InvalidArguments;
        }
    }
    if (options.fusion_mode == .experimental_hybrid_source_diagnostic and fusion_cap_explicit)
        return error.HybridFusionConflictsWithCap;
    return options;
}

fn parseTraceAbi(encoded: []const u8) !TraceAbiSelector {
    if (std.mem.eql(u8, encoded, "eval-domain")) return .eval_domain;
    if (std.mem.eql(u8, encoded, "stored-domain")) return .stored_domain;
    return error.InvalidTraceAbi;
}

fn parseFusionCap(encoded: []const u8, maximum: usize) !usize {
    const cap = try std.fmt.parseUnsigned(usize, encoded, 10);
    if (cap == 0 or cap > maximum) return error.InvalidFusionInstructionCap;
    return cap;
}

test "Metal eval source options preserve the default and positional cap" {
    const defaults = try parse(&.{}, 512, 4096);
    try std.testing.expectEqual(TraceAbiSelector.eval_domain, defaults.trace_abi);
    try std.testing.expectEqual(FusionMode.capped, defaults.fusion_mode);
    try std.testing.expectEqual(@as(usize, 512), defaults.fusion_cap);
    try std.testing.expect(!defaults.selected_only);
    try std.testing.expectEqual(@as(?usize, null), defaults.component_limit);

    const positional = try parse(&.{ "2048", "--selected-only" }, 512, 4096);
    try std.testing.expectEqual(FusionMode.capped, positional.fusion_mode);
    try std.testing.expectEqual(@as(usize, 2048), positional.fusion_cap);
    try std.testing.expect(positional.selected_only);
}

test "Metal eval source options expose named capped and hybrid modes" {
    const capped = try parse(&.{ "--fusion-cap", "1024", "--component-limit", "8" }, 512, 4096);
    try std.testing.expectEqual(FusionMode.capped, capped.fusion_mode);
    try std.testing.expectEqual(@as(usize, 1024), capped.fusion_cap);
    try std.testing.expectEqual(@as(?usize, 8), capped.component_limit);

    const hybrid = try parse(&.{"--experimental-hybrid-source-diagnostic"}, 512, 4096);
    try std.testing.expectEqual(FusionMode.experimental_hybrid_source_diagnostic, hybrid.fusion_mode);
    try std.testing.expectEqual(@as(usize, 512), hybrid.fusion_cap);
}

test "Metal eval source options reject hybrid cap ambiguity" {
    try std.testing.expectError(
        error.HybridFusionConflictsWithCap,
        parse(&.{ "--experimental-hybrid-source-diagnostic", "--fusion-cap", "2048" }, 512, 4096),
    );
    try std.testing.expectError(
        error.HybridFusionConflictsWithCap,
        parse(&.{ "2048", "--experimental-hybrid-source-diagnostic" }, 512, 4096),
    );
}

test "Metal eval source options select the stored-domain trace ABI" {
    const stored = try parse(&.{ "--trace-abi", "stored-domain", "--fusion-cap", "1024" }, 512, 4096);
    try std.testing.expectEqual(TraceAbiSelector.stored_domain, stored.trace_abi);
    try std.testing.expectEqual(@as(usize, 1024), stored.fusion_cap);

    const explicit = try parse(&.{ "--trace-abi", "eval-domain" }, 512, 4096);
    try std.testing.expectEqual(TraceAbiSelector.eval_domain, explicit.trace_abi);

    try std.testing.expectError(error.InvalidTraceAbi, parse(&.{ "--trace-abi", "lifted" }, 512, 4096));
    try std.testing.expectError(
        error.InvalidArguments,
        parse(&.{ "--trace-abi", "stored-domain", "--trace-abi", "eval-domain" }, 512, 4096),
    );
}
