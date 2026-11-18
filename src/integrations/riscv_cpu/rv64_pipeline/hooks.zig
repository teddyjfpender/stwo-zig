//! Product hook contract of the RV64 block pipeline. A product line supplies
//! one hooks module (`rv64_pipeline_hooks`) whose top-level declarations are
//! checked here at comptime, so the contract costs nothing at runtime.
//!
//! Every hook is statement-level: it decides which guest, input and output a
//! proof binds, never transcript order, AIR shape or proof bytes.
const std = @import("std");
const Profile = @import("stwo_riscv_rv64").execution.execution_profile.Profile;
const LoadedImage = @import("stwo_riscv_rv64").execution.elf.LoadedImage;

/// Declarations every hooks module provides, in contract order.
///
/// - `label: []const u8` short product label for receipts, CLI help and error
///   context only. It MUST NOT reach a transcript, domain separator or digest.
/// - `Symbols` guest ABI symbol set, decoded from the request JSON. It carries
///   the `symbol_fields` below as `u64` addresses.
/// - `OUTPUT_BYTES` public output bytes bound by the terminal AIR (43).
/// - `MAX_INPUT_BYTES` largest admitted input payload (window minus the
///   4-byte length prefix).
/// - `admitsProfile(Profile) bool` execution profiles this product proves.
///   The pipeline rejects every other profile before capture.
/// - `loadImage(Allocator, Symbols, elf, input) !LoadedImage` maps ELF and
///   input into the immutable initial image; no partial image escapes.
/// - `haltFlag(Symbols) u64` address of the halt flag; the output page
///   follows at +8 (terminal AIR spec).
/// - `service_families` extra service families (RFC-3). Must be empty until
///   that RFC is decided; the pipeline then uses the base roster unchanged.
pub const required_decls = [_][]const u8{ "label", "Symbols", "OUTPUT_BYTES", "MAX_INPUT_BYTES", "admitsProfile", "loadImage", "haltFlag", "service_families" };
/// Guest ABI addresses the pipeline hashes into work-packet identities.
pub const symbol_fields = [_][]const u8{ "input_start", "input_end", "halt_flag", "output_len", "output_data", "output_end", "stack_bottom", "stack_top", "heap_start", "heap_end" };
/// The terminal AIR (`rv64_air.memory.terminal_air.Spec`) binds 43 bytes.
pub const TERMINAL_OUTPUT_BYTES = 43;

/// Shape reserved for RFC-3 service families. S1 products declare none.
pub const ServiceFamily = struct { id: u16, name: []const u8 };

fn fnShape(comptime f: anytype) std.builtin.Type.Fn {
    return switch (@typeInfo(@TypeOf(f))) {
        .@"fn" => |info| info,
        else => @compileError("rv64 pipeline hook is not a function"),
    };
}

fn paramsAre(comptime info: std.builtin.Type.Fn, comptime types: []const type) bool {
    if (info.params.len != types.len) return false;
    for (info.params, types) |param, expected| if (param.type != expected) return false;
    return true;
}

/// First contract violation of a hooks type, or null when it is complete.
/// Comptime only; `assertHooks` turns a violation into a compile error.
pub fn violation(comptime H: type) ?[]const u8 {
    comptime {
        for (required_decls) |name| if (!@hasDecl(H, name)) return "missing hook `" ++ name ++ "`";
        if (@TypeOf(H.Symbols) != type) return "`Symbols` is not a type";
        for (symbol_fields) |name| {
            if (!@hasField(H.Symbols, name)) return "`Symbols` lacks field `" ++ name ++ "`";
            if (@FieldType(H.Symbols, name) != u64) return "`Symbols." ++ name ++ "` is not u64";
        }
        _ = @as([]const u8, H.label);
        if (H.OUTPUT_BYTES != TERMINAL_OUTPUT_BYTES) return "`OUTPUT_BYTES` differs from the terminal AIR output";
        if (H.MAX_INPUT_BYTES == 0 or H.MAX_INPUT_BYTES > 1 << 30) return "`MAX_INPUT_BYTES` is outside 1..1 GiB";
        const admits = fnShape(H.admitsProfile);
        if (!paramsAre(admits, &.{Profile}) or admits.return_type != bool) return "`admitsProfile` must be fn (Profile) bool";
        const halt = fnShape(H.haltFlag);
        if (!paramsAre(halt, &.{H.Symbols}) or halt.return_type != u64) return "`haltFlag` must be fn (Symbols) u64";
        const load = fnShape(H.loadImage);
        if (!paramsAre(load, &.{ std.mem.Allocator, H.Symbols, []const u8, []const u8 })) return "`loadImage` must take (Allocator, Symbols, elf, input)";
        const returned = load.return_type orelse return "`loadImage` has an inferred return type";
        switch (@typeInfo(returned)) {
            .error_union => |eu| if (eu.payload != LoadedImage) return "`loadImage` must return !LoadedImage",
            else => return "`loadImage` must return !LoadedImage",
        }
        if (H.service_families.len != 0) return "`service_families` must be empty until RFC-3 is decided";
        return null;
    }
}

/// Reject an incomplete hooks module at its single instantiation.
pub fn assertHooks(comptime H: type) void {
    if (comptime violation(H)) |message| @compileError("rv64 pipeline hooks " ++ @typeName(H) ++ ": " ++ message);
}
