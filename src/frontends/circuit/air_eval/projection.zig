//! Reader for `compiled_air_constraints_v1.bin`, the constraints-only
//! projection of the compiled Cairo and circuit AIRs.
//!
//! The format is written by `tools/stwo-circuit-oracle-rs/src/project_air.rs`
//! (its module doc is the grammar) and independently decoded by
//! `scripts/upstream_pins_lib/circuit_recursion.py`; this reader follows the
//! Python `_Reader` step for step. Every function record is authenticated by
//! the SHA-256 of its canonical form (format version 2: the record with every
//! string written inline as `u32:len utf8` instead of as a string-table
//! index), which the decoder hashes while it reads the record; a record is
//! used only once its digest matches. Any unknown tag, invalid flag or
//! out-of-range string index is an error.
//!
//! Strings borrow the input bytes. Expressions, steps and name lists are
//! decoded once into flat arrays owned by the returned `Projection`, so the
//! interpreter walks indices instead of re-parsing bytes per evaluation.
//!
//! The oracle already applied upstream's generator rules
//! (`remove_trailing_zeroes`, the sorted used-atom lists, the manual-component
//! exclusion). The reader asserts them and never recomputes them.

const std = @import("std");

pub const magic = "STWOCAIR";
pub const version: u32 = 2;
const modulus: u32 = 0x7fff_ffff;

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    StringIndexOutOfRange,
    InvalidUtf8,
    InvalidFlag,
    InvalidTag,
    NonCanonicalConstant,
    RecordDigestMismatch,
    RecordLengthMismatch,
    TrailingZeroFelt,
    UnsortedAtoms,
    UnknownCallee,
    CalleeNotInline,
    VerifierOutputMismatch,
    HandWrittenFunctionPresent,
    DuplicateFunction,
    TooLarge,
} || std.mem.Allocator.Error;

/// Index into `Projection.strings`.
pub const Str = u32;
/// Index into `Projection.exprs`.
pub const ExprId = u32;

/// A contiguous run of a flat projection array.
pub const Span = struct {
    start: u32,
    len: u32,

    pub fn slice(span: Span, comptime T: type, items: []const T) []const T {
        return items[span.start..][0..span.len];
    }
};

pub const UseOrYield = enum(u8) { use = 0, yield = 1 };
pub const BinaryOp = enum(u8) { add = 0, sub = 1, mul = 2 };

pub const Expr = union(enum) {
    /// Canonical M31 literal.
    constant: u32,
    /// A named value: an unpacked input limb or a bound intermediate felt.
    variable: Str,
    /// A named trace column (state).
    state: Str,
    binary: struct { op: BinaryOp, lhs: ExprId, rhs: ExprId },
    /// Unary minus, emitted as `sub(zero, operand)` after the operand.
    negate: ExprId,
    /// `callee` indexes the functions of the same source; `args` spans
    /// `Projection.expr_lists` (first-array items, then the other arguments).
    static_call: struct { callee: u32, args: Span },
    array: Span,
    external_state: Str,
    public_param: Str,
    enabler,
};

pub const Step = union(enum) {
    constraint: ExprId,
    /// `felt_names` spans `Projection.names`.
    intermediate: struct { felt_names: Span, value: ExprId },
    /// `felts` spans `Projection.expr_lists` and has no trailing `Const 0`.
    lookup_term: struct { relation: Str, use_or_yield: UseOrYield, felts: Span, multiplicity: ExprId },
};

pub const ConstraintLookup = struct { relation: Str, use_or_yield: UseOrYield };

pub const TraceType = enum { component, opcode, builtin, chain_round, memory, gate, inline_fn };

/// One compiled function whose in-circuit evaluator upstream generates.
/// Name lists span `Projection.names`.
pub const Function = struct {
    name: Str,
    trace_type: TraceType,
    log_height: ?u32,
    verifier_input_limbs: Span,
    state_names: Span,
    constraint_lookups: Span,
    external_states: Span,
    public_params: Span,
    used_external_states: Span,
    used_public_params: Span,
    steps: Span,
    verifier_output: ?ExprId,
};

pub const Source = struct {
    label: Str,
    /// Upstream evaluator slot order (`all_components` / `all_circuit_components`).
    slots: Span,
    /// Compiled functions with a hand-written evaluator, excluded from `functions`.
    hand_written: Span,
    /// Sorted by name (the oracle's order).
    functions: []const Function,

    /// Binary search by name; `functions` is sorted by byte order.
    pub fn findFunction(source: *const Source, projection: *const Projection, name: []const u8) ?u32 {
        var lo: usize = 0;
        var hi: usize = source.functions.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, projection.str(source.functions[mid].name), name)) {
                .eq => return @intCast(mid),
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return null;
    }
};

pub const Constant = struct { name: Str, value: u32 };

pub const Projection = struct {
    arena: std.heap.ArenaAllocator,
    strings: []const []const u8,
    revision: Str,
    inputs_sha256: Str,
    constants: []const Constant,
    sources: []const Source,
    exprs: []const Expr,
    expr_lists: []const ExprId,
    names: []const Str,
    steps: []const Step,
    lookups: []const ConstraintLookup,

    pub fn deinit(projection: *Projection) void {
        projection.arena.deinit();
        projection.* = undefined;
    }

    pub fn str(projection: *const Projection, index: Str) []const u8 {
        return projection.strings[index];
    }

    pub fn nameList(projection: *const Projection, span: Span) []const Str {
        return span.slice(Str, projection.names);
    }

    pub fn exprList(projection: *const Projection, span: Span) []const ExprId {
        return span.slice(ExprId, projection.expr_lists);
    }

    pub fn source(projection: *const Projection, label: []const u8) ?*const Source {
        for (projection.sources) |*candidate| {
            if (std.mem.eql(u8, projection.str(candidate.label), label)) return candidate;
        }
        return null;
    }

    pub fn constant(projection: *const Projection, name: []const u8) ?u32 {
        for (projection.constants) |entry| {
            if (std.mem.eql(u8, projection.str(entry.name), name)) return entry.value;
        }
        return null;
    }
};

/// Decodes and validates a projection. `bytes` must outlive the result, whose
/// strings borrow it.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) Error!Projection {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    var decoder: Decoder = .{ .bytes = bytes, .allocator = arena.allocator() };
    const header = try decoder.header();
    const sources = try decoder.sourcesSection();
    if (decoder.position != bytes.len) return error.TrailingBytes;

    var projection: Projection = .{
        .arena = undefined,
        .strings = decoder.strings,
        .revision = header.revision,
        .inputs_sha256 = header.inputs_sha256,
        .constants = header.constants,
        .sources = sources,
        .exprs = decoder.exprs.items,
        .expr_lists = decoder.expr_lists.items,
        .names = decoder.names.items,
        .steps = decoder.steps.items,
        .lookups = decoder.lookups.items,
    };
    for (sources, decoder.pending_calls.items) |*src, calls| {
        // Callee lookup is a binary search, so the name order is checked first.
        try checkSource(&projection, src);
        try resolveCallees(&projection, decoder.exprs.items, src, calls);
    }
    projection.arena = arena;
    return projection;
}

const Header = struct { revision: Str, inputs_sha256: Str, constants: []const Constant };

/// A `static_call` whose callee name is resolved after its source is read.
const PendingCall = struct { expr: ExprId, callee_name: Str };

const Decoder = struct {
    bytes: []const u8,
    position: usize = 0,
    allocator: std.mem.Allocator,
    strings: []const []const u8 = &.{},
    exprs: std.ArrayList(Expr) = .empty,
    expr_lists: std.ArrayList(ExprId) = .empty,
    names: std.ArrayList(Str) = .empty,
    steps: std.ArrayList(Step) = .empty,
    lookups: std.ArrayList(ConstraintLookup) = .empty,
    /// Per source, in source order.
    pending_calls: std.ArrayList([]const PendingCall) = .empty,
    calls: std.ArrayList(PendingCall) = .empty,
    /// While a function record is read: the hash of its canonical form.
    canonical: ?std.crypto.hash.sha2.Sha256 = null,

    fn takeRaw(d: *Decoder, len: usize) Error![]const u8 {
        if (len > d.bytes.len - d.position) return error.Truncated;
        defer d.position += len;
        return d.bytes[d.position..][0..len];
    }

    fn take(d: *Decoder, len: usize) Error![]const u8 {
        const chunk = try d.takeRaw(len);
        if (d.canonical) |*hasher| hasher.update(chunk);
        return chunk;
    }

    fn byte(d: *Decoder) Error!u8 {
        return (try d.take(1))[0];
    }

    fn word(d: *Decoder) Error!u32 {
        return std.mem.readInt(u32, (try d.take(4))[0..4], .little);
    }

    fn flag(d: *Decoder) Error!bool {
        return switch (try d.byte()) {
            0 => false,
            1 => true,
            else => error.InvalidFlag,
        };
    }

    fn string(d: *Decoder) Error!Str {
        const index = std.mem.readInt(u32, (try d.takeRaw(4))[0..4], .little);
        if (index >= d.strings.len) return error.StringIndexOutOfRange;
        if (d.canonical) |*hasher| {
            // Strings are table entries, so their length fits in a u32.
            var len: [4]u8 = undefined;
            std.mem.writeInt(u32, &len, @intCast(d.strings[index].len), .little);
            hasher.update(&len);
            hasher.update(d.strings[index]);
        }
        return index;
    }

    fn index32(len: usize) Error!u32 {
        return std.math.cast(u32, len) orelse error.TooLarge;
    }

    fn header(d: *Decoder) Error!Header {
        if (!std.mem.eql(u8, try d.take(magic.len), magic)) return error.BadMagic;
        if (try d.word() != version) return error.UnsupportedVersion;
        const count = try d.word();
        // Each entry takes at least four bytes, which bounds the allocation.
        if (count > (d.bytes.len - d.position) / 4) return error.Truncated;
        const strings = try d.allocator.alloc([]const u8, count);
        for (strings) |*entry| {
            entry.* = try d.take(try d.word());
            if (!std.unicode.utf8ValidateSlice(entry.*)) return error.InvalidUtf8;
        }
        d.strings = strings;
        const revision = try d.string();
        const inputs_sha256 = try d.string();
        const constant_count = try d.word();
        if (constant_count > (d.bytes.len - d.position) / 8) return error.Truncated;
        const constants = try d.allocator.alloc(Constant, constant_count);
        for (constants) |*entry| entry.* = .{ .name = try d.string(), .value = try d.word() };
        return .{ .revision = revision, .inputs_sha256 = inputs_sha256, .constants = constants };
    }

    fn sourcesSection(d: *Decoder) Error![]const Source {
        const count = try d.word();
        if (count > (d.bytes.len - d.position) / 16) return error.Truncated;
        const sources = try d.allocator.alloc(Source, count);
        for (sources) |*src| src.* = try d.sourceRecord();
        return sources;
    }

    fn sourceRecord(d: *Decoder) Error!Source {
        const label = try d.string();
        const slots = try d.nameSpan();
        const hand_written = try d.nameSpan();
        const count = try d.word();
        if (count > (d.bytes.len - d.position) / 36) return error.Truncated;
        const functions = try d.allocator.alloc(Function, count);
        d.calls = .empty;
        for (functions) |*function| {
            const len = try d.word();
            const digest = try d.take(32);
            const start = d.position;
            if (len > d.bytes.len - start) return error.Truncated;
            d.canonical = std.crypto.hash.sha2.Sha256.init(.{});
            function.* = try d.functionRecord();
            var actual: [32]u8 = undefined;
            d.canonical.?.final(&actual);
            d.canonical = null;
            if (d.position != start + len) return error.RecordLengthMismatch;
            if (!std.mem.eql(u8, &actual, digest)) return error.RecordDigestMismatch;
        }
        try d.pending_calls.append(d.allocator, try d.calls.toOwnedSlice(d.allocator));
        return .{ .label = label, .slots = slots, .hand_written = hand_written, .functions = functions };
    }

    fn nameSpan(d: *Decoder) Error!Span {
        const count = try d.word();
        if (count > (d.bytes.len - d.position) / 4) return error.Truncated;
        const start = try index32(d.names.items.len);
        try d.names.ensureUnusedCapacity(d.allocator, count);
        for (0..count) |_| d.names.appendAssumeCapacity(try d.string());
        return .{ .start = start, .len = count };
    }

    fn traceType(d: *Decoder) Error!TraceType {
        const text = d.strings[try d.string()];
        const table = [_]struct { []const u8, TraceType }{
            .{ "Component", .component }, .{ "Opcode", .opcode },
            .{ "Builtin", .builtin },     .{ "ChainRound", .chain_round },
            .{ "Memory", .memory },       .{ "Gate", .gate },
            .{ "Inline", .inline_fn },
        };
        for (table) |entry| if (std.mem.eql(u8, entry[0], text)) return entry[1];
        return error.InvalidTag;
    }

    fn useOrYield(d: *Decoder) Error!UseOrYield {
        return switch (try d.byte()) {
            0 => .use,
            1 => .yield,
            else => error.InvalidFlag,
        };
    }

    fn functionRecord(d: *Decoder) Error!Function {
        const name = try d.string();
        const trace_type = try d.traceType();
        const log_height: ?u32 = if (try d.flag()) try d.word() else null;
        const verifier_input_limbs = try d.nameSpan();
        const state_names = try d.nameSpan();
        const lookup_count = try d.word();
        if (lookup_count > (d.bytes.len - d.position) / 5) return error.Truncated;
        const lookups_start = try index32(d.lookups.items.len);
        for (0..lookup_count) |_| {
            try d.lookups.append(d.allocator, .{ .relation = try d.string(), .use_or_yield = try d.useOrYield() });
        }
        const external_states = try d.nameSpan();
        const public_params = try d.nameSpan();
        const used_external_states = try d.nameSpan();
        const used_public_params = try d.nameSpan();
        const step_count = try d.word();
        if (step_count > d.bytes.len - d.position) return error.Truncated;
        const steps_start = try index32(d.steps.items.len);
        for (0..step_count) |_| {
            const step = try d.stepRecord();
            try d.steps.append(d.allocator, step);
        }
        const verifier_output: ?ExprId = if (try d.flag()) try d.expr() else null;
        return .{
            .name = name,
            .trace_type = trace_type,
            .log_height = log_height,
            .verifier_input_limbs = verifier_input_limbs,
            .state_names = state_names,
            .constraint_lookups = .{ .start = lookups_start, .len = lookup_count },
            .external_states = external_states,
            .public_params = public_params,
            .used_external_states = used_external_states,
            .used_public_params = used_public_params,
            .steps = .{ .start = steps_start, .len = step_count },
            .verifier_output = verifier_output,
        };
    }

    fn stepRecord(d: *Decoder) Error!Step {
        return switch (try d.byte()) {
            0 => .{ .constraint = try d.expr() },
            1 => blk: {
                const felt_names = try d.nameSpan();
                break :blk .{ .intermediate = .{ .felt_names = felt_names, .value = try d.expr() } };
            },
            2 => blk: {
                const relation = try d.string();
                const use_or_yield = try d.useOrYield();
                const felts = try d.exprSpan();
                const multiplicity = try d.expr();
                break :blk .{ .lookup_term = .{
                    .relation = relation,
                    .use_or_yield = use_or_yield,
                    .felts = felts,
                    .multiplicity = multiplicity,
                } };
            },
            else => error.InvalidTag,
        };
    }

    /// Children are decoded before the list is appended, so a span stays
    /// contiguous even when its items contain nested lists.
    fn exprSpan(d: *Decoder) Error!Span {
        const count = try d.word();
        if (count > d.bytes.len - d.position) return error.Truncated;
        const items = try d.allocator.alloc(ExprId, count);
        defer d.allocator.free(items);
        for (items) |*item| item.* = try d.expr();
        const start = try index32(d.expr_lists.items.len);
        try d.expr_lists.appendSlice(d.allocator, items);
        return .{ .start = start, .len = count };
    }

    fn push(d: *Decoder, node: Expr) Error!ExprId {
        const id = try index32(d.exprs.items.len);
        try d.exprs.append(d.allocator, node);
        return id;
    }

    fn expr(d: *Decoder) Error!ExprId {
        return switch (try d.byte()) {
            0 => blk: {
                const value = try d.word();
                if (value >= modulus) return error.NonCanonicalConstant;
                break :blk d.push(.{ .constant = value });
            },
            1 => d.push(.{ .variable = try d.string() }),
            2 => d.push(.{ .state = try d.string() }),
            3 => blk: {
                const op: BinaryOp = switch (try d.byte()) {
                    0 => .add,
                    1 => .sub,
                    2 => .mul,
                    else => return error.InvalidTag,
                };
                const lhs = try d.expr();
                const rhs = try d.expr();
                break :blk d.push(.{ .binary = .{ .op = op, .lhs = lhs, .rhs = rhs } });
            },
            4 => blk: {
                if (try d.byte() != 1) return error.InvalidTag;
                break :blk d.push(.{ .negate = try d.expr() });
            },
            5 => blk: {
                const callee_name = try d.string();
                const args = try d.exprSpan();
                const id = try d.push(.{ .static_call = .{ .callee = undefined, .args = args } });
                try d.calls.append(d.allocator, .{ .expr = id, .callee_name = callee_name });
                break :blk id;
            },
            6 => d.push(.{ .array = try d.exprSpan() }),
            7 => d.push(.{ .external_state = try d.string() }),
            8 => d.push(.{ .public_param = try d.string() }),
            9 => d.push(.enabler),
            else => error.InvalidTag,
        };
    }
};

/// `exprs` is the decoder's mutable view of `projection.exprs`.
fn resolveCallees(projection: *const Projection, exprs: []Expr, src: *const Source, calls: []const PendingCall) Error!void {
    for (calls) |call| {
        const callee = src.findFunction(projection, projection.str(call.callee_name)) orelse
            return error.UnknownCallee;
        if (src.functions[callee].trace_type != .inline_fn) return error.CalleeNotInline;
        exprs[call.expr].static_call.callee = callee;
    }
}

/// Asserts the generator rules the oracle applied; never recomputes them.
fn checkSource(projection: *const Projection, src: *const Source) Error!void {
    for (src.functions, 0..) |function, i| {
        if (i > 0 and std.mem.order(u8, projection.str(src.functions[i - 1].name), projection.str(function.name)) != .lt)
            return error.DuplicateFunction;
        if ((function.trace_type == .inline_fn) != (function.verifier_output != null))
            return error.VerifierOutputMismatch;
        if (function.verifier_output) |output| {
            if (projection.exprs[output] != .array) return error.VerifierOutputMismatch;
        }
        try checkSorted(projection, function.used_external_states);
        try checkSorted(projection, function.used_public_params);
        for (function.steps.slice(Step, projection.steps)) |step| {
            if (step != .lookup_term) continue;
            const felts = projection.exprList(step.lookup_term.felts);
            if (felts.len > 0 and std.meta.eql(projection.exprs[felts[felts.len - 1]], Expr{ .constant = 0 }))
                return error.TrailingZeroFelt;
        }
    }
    for (projection.nameList(src.hand_written)) |name| {
        if (src.findFunction(projection, projection.str(name)) != null) return error.HandWrittenFunctionPresent;
    }
}

/// Upstream sorts `String`s, which is byte order; duplicates were removed by a set.
fn checkSorted(projection: *const Projection, span: Span) Error!void {
    const names = projection.nameList(span);
    for (names[0..names.len -| 1], names[@min(1, names.len)..]) |a, b| {
        if (std.mem.order(u8, projection.str(a), projection.str(b)) != .lt) return error.UnsortedAtoms;
    }
}
