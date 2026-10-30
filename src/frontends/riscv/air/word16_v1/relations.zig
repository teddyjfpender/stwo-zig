//! Complete event vocabulary, not a receipt and not a challenge registry.
//! All domains differ from released byte-based RISC-V relations.
const A = @import("abi.zig");
pub const VERSION: u32 = 1;
pub const Domain = enum(u32) {
    register_word = 0x57315247,
    ram_word = 0x5731524d,
    cpu = 0x57314350,
    rom_signed_imm = 0x57315052,
    range16 = 0x57315236,
    range8_8 = 0x57313838,
    bitwise_byte = 0x57314257,
    clock_order = 0x5731434b,
};
pub fn Tuple(comptime S: type) type {
    return struct {
        address: S,
        clock: S,
        value: A.Word(S),
        pub fn fields(self: @This()) [4]S {
            return .{ self.address, self.clock, self.value.lo, self.value.hi };
        }
    };
}
/// Sink access(domain, multiplicity, tuple), clock(previous,current,active).
/// A clock-order request is an OPEN proof obligation until a canonical bound
/// provider/AIR closes it. Host checks do not discharge it.
pub fn read(comptime S: type, sink: anytype, comptime domain: Domain, active: S, read_: A.Read(S), clock: S) void {
    if (domain != .register_word and domain != .ram_word) @compileError("wrong word access domain");
    sink.access(domain, active.neg(), Tuple(S){ .address = read_.address, .clock = read_.previous_clock, .value = read_.value });
    sink.access(domain, active, Tuple(S){ .address = read_.address, .clock = clock, .value = read_.value });
    sink.clock(read_.previous_clock, clock, active);
}
pub fn write(comptime S: type, sink: anytype, comptime domain: Domain, active: S, write_: A.Write(S), clock: S) void {
    if (domain != .register_word and domain != .ram_word) @compileError("wrong word access domain");
    sink.access(domain, active.neg(), Tuple(S){ .address = write_.address, .clock = write_.previous_clock, .value = write_.before });
    sink.access(domain, active, Tuple(S){ .address = write_.address, .clock = clock, .value = write_.after });
    sink.clock(write_.previous_clock, clock, active);
}
/// Legacy native/caller adapters preserve the byte source's proof authority.
/// They are affine expressions over the SAME authenticated byte wires; no
/// free replacement witness and no assertion that a host word was validated.
pub fn legacyTuple(comptime S: type, address: S, clock: S, bytes: [4]S) Tuple(S) {
    return .{ .address = address, .clock = clock, .value = A.Word(S).packedBytes(bytes) };
}
pub fn publicTuple(comptime S: type, address: u32, clock: u32, value: u32) Tuple(S) {
    return .{ .address = A.c(S, address), .clock = A.c(S, clock), .value = A.Word(S).fromU32(value) };
}
pub fn wordRange(comptime S: type, sink: anytype, active: S, word: A.Word(S)) void {
    sink.range16(active, word.lo);
    sink.range16(active, word.hi);
}
pub fn byteViewRange(comptime S: type, sink: anytype, active: S, bytes: [4]S) void {
    sink.range8_8(active, .{ bytes[0], bytes[1] });
    sink.range8_8(active, .{ bytes[2], bytes[3] });
}
/// ROM sink binds PC, fixed opcode, registers and signed immediate; its NEW
/// fixed-key factory must decode the ELF and reject noncanonical instructions.
/// CPU provider enforces a one-based bounded instruction clock and actual
/// register-file boundary, including initial x0 and all 32 final registers.
pub fn sequential(comptime S: type, sink: anytype, active: S, clock: S, pc: S) void {
    sink.cpu(active.neg(), .{ pc, clock });
    sink.cpu(active, .{ pc.add(A.c(S, 4)), clock.add(S.one()) });
}
