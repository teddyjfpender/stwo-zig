//! Stable source identities and spans for diagnostics and manifests.

const types = @import("types.zig");

pub const Source = struct {
    path: types.NameId,
};

pub const Position = struct {
    /// Zero-based byte offset in the source.
    byte_offset: u32,
    /// One-based human line for real sources; zero only for generated spans.
    line: u32,
    /// One-based human column for real sources; zero only for generated spans.
    column: u32,

    pub const generated = Position{
        .byte_offset = 0,
        .line = 0,
        .column = 0,
    };

    fn isGenerated(self: Position) bool {
        return self.byte_offset == 0 and self.line == 0 and self.column == 0;
    }

    fn precedes(lhs: Position, rhs: Position) bool {
        if (lhs.byte_offset > rhs.byte_offset) return false;
        if (lhs.line > rhs.line) return false;
        if (lhs.line == rhs.line and lhs.column > rhs.column) return false;
        return true;
    }
};

pub const SpanError = error{
    GeneratedSpanHasLocation,
    InvalidSourcePosition,
    ReversedSourceSpan,
};

pub const SourceSpan = struct {
    source: ?types.SourceId,
    start: Position,
    end: Position,

    pub fn generated() SourceSpan {
        return .{
            .source = null,
            .start = Position.generated,
            .end = Position.generated,
        };
    }

    pub fn init(
        source_id: types.SourceId,
        start: Position,
        end: Position,
    ) SpanError!SourceSpan {
        const result = SourceSpan{
            .source = source_id,
            .start = start,
            .end = end,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: SourceSpan) SpanError!void {
        if (self.source == null) {
            if (!self.start.isGenerated() or !self.end.isGenerated())
                return error.GeneratedSpanHasLocation;
            return;
        }
        if (self.start.line == 0 or self.start.column == 0 or
            self.end.line == 0 or self.end.column == 0)
            return error.InvalidSourcePosition;
        if (!Position.precedes(self.start, self.end))
            return error.ReversedSourceSpan;
    }
};
