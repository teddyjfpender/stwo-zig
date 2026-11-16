//! Append-only diagnostics for the typed arena-plan origin; never arbitrary error names.
const std = @import("std");
const Entry = @import("stwo_core").error_codes.Entry;
pub const ArenaPlanError = @import("arena_plan.zig").Error || std.mem.Allocator.Error;

pub const table = [_]Entry{
    .{ .tag = "EmptySchedule", .code = 0x2001, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "DuplicateLogicalId", .code = 0x2002, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "UnsortedBindings", .code = 0x2003, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidAlignment", .code = 0x2004, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidTick", .code = 0x2005, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidUseOrder", .code = 0x2006, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "SizeOverflow", .code = 0x2007, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "BudgetExceeded", .code = 0x2008, .class = .resource_exhausted, .since = "1.0.0-rc.2" },
    .{ .tag = "AliasOverlap", .code = 0x2009, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "UnknownBinding", .code = 0x200a, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "BindingOutOfBounds", .code = 0x200b, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "NarrowAddressOverflow", .code = 0x200c, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "OutOfMemory", .code = 0x200d, .class = .resource_exhausted, .since = "1.0.0-rc.2" },
    .{ .tag = "DuplicateBuffer", .code = 0x2201, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "DuplicateColumn", .code = 0x2202, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyCommitmentSet", .code = 0x2203, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyConstraintSet", .code = 0x2204, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyExecutionGraph", .code = 0x2205, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyIdentity", .code = 0x2206, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyTrace", .code = 0x2207, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidBuffer", .code = 0x2208, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidCommitment", .code = 0x2209, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidConstraint", .code = 0x220a, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidDependency", .code = 0x220b, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidFriSchedule", .code = 0x220c, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidNode", .code = 0x220d, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidNativeAir", .code = 0x220e, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidQuotientSchedule", .code = 0x220f, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidTranscript", .code = 0x2210, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyIdentity", .code = 0x2301, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "GeometryOverflow", .code = 0x2302, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidGeometry", .code = 0x2303, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidIngress", .code = 0x2304, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidSampling", .code = 0x2305, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "UnsupportedVersion", .code = 0x2306, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "DuplicateRecipe", .code = 0x2401, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "MissingRecipe", .code = 0x2402, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "MissingSpillEntry", .code = 0x2403, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "SpillNotMaterialized", .code = 0x2404, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "SpillCorrupted", .code = 0x2405, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "BindingSizeMismatch", .code = 0x2406, .class = .invalid_input, .since = "1.0.0-rc.4" },
};

pub fn fromArena(err: ArenaPlanError) Entry {
    return switch (err) {
        error.EmptySchedule => table[0],
        error.DuplicateLogicalId => table[1],
        error.UnsortedBindings => table[2],
        error.InvalidAlignment => table[3],
        error.InvalidTick => table[4],
        error.InvalidUseOrder => table[5],
        error.SizeOverflow => table[6],
        error.BudgetExceeded => table[7],
        error.AliasOverlap => table[8],
        error.UnknownBinding => table[9],
        error.BindingOutOfBounds => table[10],
        error.NarrowAddressOverflow => table[11],
        error.OutOfMemory => table[12],
    };
}

pub fn fromProofProgram(err: @import("proof_program.zig").Error) Entry {
    return switch (err) {
        error.DuplicateBuffer => table[13],
        error.DuplicateColumn => table[14],
        error.EmptyCommitmentSet => table[15],
        error.EmptyConstraintSet => table[16],
        error.EmptyExecutionGraph => table[17],
        error.EmptyIdentity => table[18],
        error.EmptyTrace => table[19],
        error.InvalidBuffer => table[20],
        error.InvalidCommitment => table[21],
        error.InvalidConstraint => table[22],
        error.InvalidDependency => table[23],
        error.InvalidFriSchedule => table[24],
        error.InvalidNode => table[25],
        error.InvalidNativeAir => table[26],
        error.InvalidQuotientSchedule => table[27],
        error.InvalidTranscript => table[28],
    };
}
pub fn fromNativeAir(err: @import("proof_program_native_air.zig").Error) Entry {
    return switch (err) {
        error.EmptyIdentity => table[29],
        error.GeometryOverflow => table[30],
        error.InvalidGeometry => table[31],
        error.InvalidIngress => table[32],
        error.InvalidSampling => table[33],
        error.UnsupportedVersion => table[34],
    };
}

pub fn fromRecovery(err: @import("recovery.zig").RecoveryError) Entry {
    return switch (err) {
        error.DuplicateRecipe => table[35],
        error.MissingRecipe => table[36],
        error.MissingSpillEntry => table[37],
        error.SpillNotMaterialized => table[38],
        error.SpillCorrupted => table[39],
        error.BindingSizeMismatch => table[40],
    };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}
