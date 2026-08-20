//! Internal binary pair authority authority shard; use binary_pair_authority.zig publicly.

const dependency_0 = @import("binary_pair_authority_contract.zig");

const SHARED_RANGE_LOG_SIZE = dependency_0.SHARED_RANGE_LOG_SIZE;
const protocol = dependency_0.protocol;
const span_statement = dependency_0.span_statement;
const transcript_program = dependency_0.transcript_program;

comptime {
    if (SHARED_RANGE_LOG_SIZE != 16 or
        span_statement.SPAN_STATEMENT_CANONICAL_WORDS !=
            transcript_program.STATEMENT_WORD_COUNT)
    {
        @compileError("binary pair authority protocol geometry drifted");
    }
    if (@sizeOf(WireIdentitySentinel) != 0)
        @compileError("binary pair authority sentinel must remain zero-sized");
}

pub const WireIdentitySentinel = struct {};
