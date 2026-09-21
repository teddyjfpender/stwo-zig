//! Default host runtime implementing the standard syscall ABI.
//!
//! Provides HALT, WRITE, COMMIT, HINT_LEN, and HINT_READ syscalls.
//! The guest communicates via ECALL with syscall number in a7 (x17).

const std = @import("std");
const host_mod = @import("interface.zig");
const Cpu = @import("../runner/cpu.zig").Cpu;
const Memory = @import("../runner/memory.zig").Memory;

const SyscallNr = host_mod.SyscallNr;
const SyscallResult = host_mod.SyscallResult;
const HostInterface = host_mod.HostInterface;
const MemoryWrite = host_mod.MemoryWrite;
const HintOracle = @import("hint_oracle.zig").HintOracle;

/// File descriptor constants for WRITE syscall.
const FD_STDOUT: u32 = 1;
const FD_STDERR: u32 = 2;
const FD_HINT_REQUEST: u32 = 3;

/// Register indices (RISC-V ABI names).
const REG_A0: u5 = 10;
const REG_A1: u5 = 11;
const REG_A2: u5 = 12;
const REG_A7: u5 = 17;

pub const HostRuntime = struct {
    /// Hint oracle for preimage data.
    hint_oracle: HintOracle,

    /// Journal: collects guest public output from WRITE(fd=1) and COMMIT.
    journal: std.ArrayList(u8),

    /// Exit code set by HALT syscall.
    exit_code: ?u32,

    /// Temporary buffer for memory writes performed during the last syscall.
    /// The runner reads this to update the state chain tracker.
    mem_writes: std.ArrayList(MemoryWrite),

    /// Temporary buffer for reading guest memory during WRITE.
    scratch: std.ArrayList(u8),

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, hints: []const []const u8) HostRuntime {
        return .{
            .hint_oracle = HintOracle.init(hints),
            .journal = .{},
            .exit_code = null,
            .mem_writes = .{},
            .scratch = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HostRuntime) void {
        self.journal.deinit(self.allocator);
        self.mem_writes.deinit(self.allocator);
        self.scratch.deinit(self.allocator);
        self.* = undefined;
    }

    /// Get the collected journal output.
    pub fn journalData(self: *const HostRuntime) []const u8 {
        return self.journal.items;
    }

    /// Get the HostInterface vtable wrapper for passing to runWithHost.
    pub fn interface(self: *HostRuntime) HostInterface {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = HostInterface.VTable{
        .handleSyscall = handleSyscallErased,
        .lastMemoryWrites = lastMemoryWritesErased,
    };

    fn handleSyscallErased(ptr: *anyopaque, cpu: *Cpu, mem: *Memory) SyscallResult {
        const self: *HostRuntime = @ptrCast(@alignCast(ptr));
        return self.handleSyscall(cpu, mem);
    }

    fn lastMemoryWritesErased(ptr: *anyopaque) []const MemoryWrite {
        const self: *HostRuntime = @ptrCast(@alignCast(ptr));
        return self.mem_writes.items;
    }

    /// Dispatch a syscall based on the value in a7.
    pub fn handleSyscall(self: *HostRuntime, cpu: *Cpu, mem: *Memory) SyscallResult {
        // Clear previous memory write records.
        self.mem_writes.clearRetainingCapacity();

        const syscall_nr: SyscallNr = @enumFromInt(cpu.readReg(REG_A7));

        switch (syscall_nr) {
            .HALT => return self.sysHalt(cpu),
            .WRITE => {
                self.sysWrite(cpu, mem);
                return .Continue;
            },
            .COMMIT => {
                self.sysCommit(cpu, mem);
                return .Continue;
            },
            .HINT_LEN => {
                self.sysHintLen(cpu);
                return .Continue;
            },
            .HINT_READ => {
                self.sysHintRead(cpu, mem);
                return .Continue;
            },
            .KECCAK256 => {
                self.sysKeccak256(cpu, mem);
                return .Continue;
            },
            .SHA256 => {
                self.sysSha256(cpu, mem);
                return .Continue;
            },
            .ECRECOVER => {
                self.sysEcrecover(cpu, mem);
                return .Continue;
            },
            _ => {
                // Unknown syscall — treat as no-op, continue execution.
                return .Continue;
            },
        }
    }

    /// HALT (a7=0): Terminate with exit code in a0.
    fn sysHalt(self: *HostRuntime, cpu: *Cpu) SyscallResult {
        const exit_code = cpu.readReg(REG_A0);
        self.exit_code = exit_code;
        return .{ .Halt = exit_code };
    }

    /// WRITE (a7=2): Write guest buffer to host.
    /// a0=fd, a1=buf_ptr, a2=len. Sets a0=bytes_written.
    fn sysWrite(self: *HostRuntime, cpu: *Cpu, mem: *Memory) void {
        const fd = cpu.readReg(REG_A0);
        const buf_ptr = cpu.readReg(REG_A1);
        const len = cpu.readReg(REG_A2);

        // Read guest memory into scratch buffer.
        self.scratch.clearRetainingCapacity();
        self.scratch.resize(self.allocator, len) catch @panic("HostRuntime: scratch alloc failed");
        mem.readSlice(buf_ptr, self.scratch.items);

        switch (fd) {
            FD_STDOUT, FD_STDERR => {
                // Append to journal.
                self.journal.appendSlice(self.allocator, self.scratch.items) catch
                    @panic("HostRuntime: journal alloc failed");
            },
            FD_HINT_REQUEST => {
                // Hint request — the data is a hint request key.
                // For now, we ignore it (hints are pre-queued).
            },
            else => {},
        }

        // Return bytes written.
        cpu.writeReg(REG_A0, len);
    }

    /// COMMIT (a7=16): Commit public output.
    /// a0=buf_ptr, a1=len.
    fn sysCommit(self: *HostRuntime, cpu: *Cpu, mem: *Memory) void {
        const buf_ptr = cpu.readReg(REG_A0);
        const len = cpu.readReg(REG_A1);

        self.scratch.clearRetainingCapacity();
        self.scratch.resize(self.allocator, len) catch @panic("HostRuntime: scratch alloc failed");
        mem.readSlice(buf_ptr, self.scratch.items);

        self.journal.appendSlice(self.allocator, self.scratch.items) catch
            @panic("HostRuntime: journal alloc failed");
    }

    /// HINT_LEN (a7=240): Get length of the current hint.
    /// Returns length in a0.
    fn sysHintLen(self: *HostRuntime, cpu: *Cpu) void {
        const len = self.hint_oracle.currentLen();
        cpu.writeReg(REG_A0, @intCast(len));
    }

    /// HINT_READ (a7=241): Read hint bytes into guest memory.
    /// a0=buf_ptr, a1=len. Returns bytes read in a0.
    /// Records memory writes for state chain tracking.
    fn sysHintRead(self: *HostRuntime, cpu: *Cpu, mem: *Memory) void {
        const buf_ptr = cpu.readReg(REG_A0);
        const len = cpu.readReg(REG_A1);

        // Read from hint oracle into scratch.
        self.scratch.clearRetainingCapacity();
        self.scratch.resize(self.allocator, len) catch @panic("HostRuntime: scratch alloc failed");
        const bytes_read = self.hint_oracle.read(self.scratch.items);

        // Write into guest memory and record word-aligned writes.
        if (bytes_read > 0) {
            self.writeTracked(mem, buf_ptr, self.scratch.items[0..bytes_read]);
        }

        cpu.writeReg(REG_A0, @intCast(bytes_read));
    }

    /// KECCAK256 (a7=242): Accelerated keccak256 hash.
    /// a0=input_ptr, a1=input_len, a2=output_ptr (32 bytes).
    fn sysKeccak256(self: *HostRuntime, cpu: *Cpu, mem: *Memory) void {
        const input_ptr = cpu.readReg(REG_A0);
        const input_len = cpu.readReg(REG_A1);
        const output_ptr = cpu.readReg(REG_A2);

        // Read input from guest memory.
        self.scratch.clearRetainingCapacity();
        self.scratch.resize(self.allocator, input_len) catch @panic("HostRuntime: scratch alloc failed");
        mem.readSlice(input_ptr, self.scratch.items);

        // Compute keccak256.
        const Keccak256 = std.crypto.hash.sha3.Keccak256;
        var hash: [32]u8 = undefined;
        Keccak256.hash(self.scratch.items, &hash, .{});

        // Write result to guest memory.
        self.writeTracked(mem, output_ptr, &hash);
    }

    /// ECRECOVER (a7=243): Accelerated ECDSA public key recovery on secp256k1.
    /// a0=input_ptr (128 bytes: msg_hash[32] + v[32] + r[32] + s[32]),
    /// a1=output_ptr (32 bytes: zero-padded recovered address).
    /// Returns 1 in a0 on success, 0 on failure.
    fn sysEcrecover(self: *HostRuntime, cpu: *Cpu, mem: *Memory) void {
        const Secp256k1 = std.crypto.ecc.Secp256k1;
        const scalar = Secp256k1.scalar;
        const Fe = Secp256k1.Fe;
        const Keccak256 = std.crypto.hash.sha3.Keccak256;

        const input_ptr = cpu.readReg(REG_A0);
        const output_ptr = cpu.readReg(REG_A1);

        // Read 128 bytes: msg_hash[32] + v[32] + r[32] + s[32]
        var input: [128]u8 = undefined;
        mem.readSlice(input_ptr, &input);

        const msg_hash: [32]u8 = input[0..32].*;
        const v_byte = input[63]; // last byte of v[32] field
        const r_bytes: [32]u8 = input[64..96].*;
        const s_bytes: [32]u8 = input[96..128].*;

        // Recovery id: Ethereum uses v=27/28 or v=0/1
        const is_odd = if (v_byte >= 27) (v_byte - 27) & 1 == 1 else v_byte & 1 == 1;

        // 1. Construct point R from r (x-coordinate) and recovery_id (y parity)
        const r_fe = Fe.fromBytes(r_bytes, .big) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };
        const r_y = Secp256k1.recoverY(r_fe, is_odd) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };
        const R = Secp256k1.fromAffineCoordinates(.{ .x = r_fe, .y = r_y }) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };

        // 2. Validate r and s are canonical scalars
        scalar.rejectNonCanonical(r_bytes, .big) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };
        scalar.rejectNonCanonical(s_bytes, .big) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };

        // 3. Compute coeff_g = -msg_hash * r_inv, coeff_r = s * r_inv (mod n)
        // Using: r_inv * (-e * G + s * R) = r_inv*s*R - r_inv*e*G
        // We need scalar inversion of r. Use Scalar struct for that.
        const r_scalar = scalar.Scalar.fromBytes(r_bytes, .big) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };
        const r_inv = r_scalar.invert();
        const r_inv_bytes = r_inv.toBytes(.big);

        const neg_e = scalar.neg(msg_hash, .big) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };
        const coeff_g = scalar.mul(neg_e, r_inv_bytes, .big) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };
        const coeff_r = scalar.mul(s_bytes, r_inv_bytes, .big) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };

        // 4. Compute pub_key = coeff_g*G + coeff_r*R
        const pub_point = Secp256k1.mulDoubleBasePublic(
            Secp256k1.basePoint,
            coeff_g,
            R,
            coeff_r,
            .big,
        ) catch {
            cpu.writeReg(REG_A0, 0);
            return;
        };

        // 5. Serialize uncompressed public key (64 bytes, no prefix)
        const uncompressed = pub_point.toUncompressedSec1();
        const pub_key_bytes = uncompressed[1..65];

        // 6. Keccak256(pub_key) → take last 20 bytes as address
        var pub_hash: [32]u8 = undefined;
        Keccak256.hash(pub_key_bytes, &pub_hash, .{});

        // Write 32-byte output: 12 zero bytes + 20-byte address
        var output: [32]u8 = [_]u8{0} ** 32;
        @memcpy(output[12..32], pub_hash[12..32]);
        self.writeTracked(mem, output_ptr, &output);

        cpu.writeReg(REG_A0, 1); // Success
    }

    /// SHA256 (a7=244): Accelerated SHA-256 hash.
    /// a0=input_ptr, a1=input_len, a2=output_ptr (32 bytes).
    fn sysSha256(self: *HostRuntime, cpu: *Cpu, mem: *Memory) void {
        const input_ptr = cpu.readReg(REG_A0);
        const input_len = cpu.readReg(REG_A1);
        const output_ptr = cpu.readReg(REG_A2);

        self.scratch.clearRetainingCapacity();
        self.scratch.resize(self.allocator, input_len) catch @panic("HostRuntime: scratch alloc failed");
        mem.readSlice(input_ptr, self.scratch.items);

        const Sha256 = std.crypto.hash.sha2.Sha256;
        var hash: [32]u8 = undefined;
        Sha256.hash(self.scratch.items, &hash, .{});

        self.writeTracked(mem, output_ptr, &hash);
    }

    /// Capture old aligned words, apply one host write, then retain the new
    /// words so the runner can emit exact access-chain transitions.
    fn writeTracked(self: *HostRuntime, mem: *Memory, addr: u32, bytes: []const u8) void {
        if (bytes.len == 0) return;
        const first_write = self.mem_writes.items.len;
        const first_word = addr & ~@as(u32, 3);
        const end_addr = addr +% @as(u32, @intCast(bytes.len));
        const end_word = (end_addr +% 3) & ~@as(u32, 3);
        var word_addr = first_word;
        while (word_addr < end_word) : (word_addr +%= 4) {
            self.mem_writes.append(self.allocator, .{
                .addr = word_addr,
                .previous_value = mem.readU32(word_addr),
                .value = undefined,
            }) catch @panic("HostRuntime: mem_writes alloc failed");
        }
        mem.writeSlice(addr, bytes);
        for (self.mem_writes.items[first_write..]) |*write| {
            write.value = mem.readU32(write.addr);
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "HostRuntime: HALT syscall" {
    const hints = [_][]const u8{};
    var rt = HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var cpu = @import("../runner/cpu.zig").Cpu.init(0x10000, 0x7FFF0000);
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    // Set a7=0 (HALT), a0=42 (exit code).
    cpu.writeReg(REG_A7, 0);
    cpu.writeReg(REG_A0, 42);

    const result = rt.handleSyscall(&cpu, &mem);
    try std.testing.expectEqual(SyscallResult{ .Halt = 42 }, result);
    try std.testing.expectEqual(@as(?u32, 42), rt.exit_code);
}

test "HostRuntime: WRITE syscall appends to journal" {
    const hints = [_][]const u8{};
    var rt = HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var cpu = @import("../runner/cpu.zig").Cpu.init(0x10000, 0x7FFF0000);
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    // Place "hello" at 0x2000 in guest memory.
    mem.writeSlice(0x2000, "hello");

    // Set a7=2 (WRITE), a0=1 (stdout), a1=0x2000, a2=5.
    cpu.writeReg(REG_A7, 2);
    cpu.writeReg(REG_A0, 1);
    cpu.writeReg(REG_A1, 0x2000);
    cpu.writeReg(REG_A2, 5);

    const result = rt.handleSyscall(&cpu, &mem);
    try std.testing.expectEqual(SyscallResult.Continue, result);
    try std.testing.expectEqualSlices(u8, "hello", rt.journalData());
    try std.testing.expectEqual(@as(u32, 5), cpu.readReg(REG_A0));
}

test "HostRuntime: COMMIT syscall appends to journal" {
    const hints = [_][]const u8{};
    var rt = HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var cpu = @import("../runner/cpu.zig").Cpu.init(0x10000, 0x7FFF0000);
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    mem.writeSlice(0x3000, "output");

    cpu.writeReg(REG_A7, 16);
    cpu.writeReg(REG_A0, 0x3000);
    cpu.writeReg(REG_A1, 6);

    const result = rt.handleSyscall(&cpu, &mem);
    try std.testing.expectEqual(SyscallResult.Continue, result);
    try std.testing.expectEqualSlices(u8, "output", rt.journalData());
}

test "HostRuntime: HINT_LEN and HINT_READ" {
    const hint1 = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const hints = [_][]const u8{&hint1};
    var rt = HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var cpu = @import("../runner/cpu.zig").Cpu.init(0x10000, 0x7FFF0000);
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    // HINT_LEN: a7=240
    cpu.writeReg(REG_A7, 240);
    _ = rt.handleSyscall(&cpu, &mem);
    try std.testing.expectEqual(@as(u32, 4), cpu.readReg(REG_A0));

    // HINT_READ: a7=241, a0=0x4000, a1=4
    cpu.writeReg(REG_A7, 241);
    cpu.writeReg(REG_A0, 0x4000);
    cpu.writeReg(REG_A1, 4);
    _ = rt.handleSyscall(&cpu, &mem);

    // Verify data was written to guest memory.
    try std.testing.expectEqual(@as(u32, 4), cpu.readReg(REG_A0));
    try std.testing.expectEqual(@as(u8, 0xDE), mem.readByte(0x4000));
    try std.testing.expectEqual(@as(u8, 0xAD), mem.readByte(0x4001));
    try std.testing.expectEqual(@as(u8, 0xBE), mem.readByte(0x4002));
    try std.testing.expectEqual(@as(u8, 0xEF), mem.readByte(0x4003));

    // Verify memory writes were recorded.
    const writes = rt.mem_writes.items;
    try std.testing.expect(writes.len > 0);
    try std.testing.expectEqual(@as(u32, 0x4000), writes[0].addr);
    try std.testing.expectEqual(@as(u32, 0), writes[0].previous_value);
    try std.testing.expectEqual(@as(u32, 0xEFBE_ADDE), writes[0].value);
}

test "HostRuntime: unknown syscall is no-op" {
    const hints = [_][]const u8{};
    var rt = HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var cpu = @import("../runner/cpu.zig").Cpu.init(0x10000, 0x7FFF0000);
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    cpu.writeReg(REG_A7, 999);
    const result = rt.handleSyscall(&cpu, &mem);
    try std.testing.expectEqual(SyscallResult.Continue, result);
}

test "HostRuntime: multiple hints sequential" {
    const hint1 = "abc";
    const hint2 = "xyz";
    const hints = [_][]const u8{ hint1, hint2 };
    var rt = HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var cpu = @import("../runner/cpu.zig").Cpu.init(0x10000, 0x7FFF0000);
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    // Read first hint.
    cpu.writeReg(REG_A7, 240);
    _ = rt.handleSyscall(&cpu, &mem);
    try std.testing.expectEqual(@as(u32, 3), cpu.readReg(REG_A0));

    cpu.writeReg(REG_A7, 241);
    cpu.writeReg(REG_A0, 0x5000);
    cpu.writeReg(REG_A1, 3);
    _ = rt.handleSyscall(&cpu, &mem);

    var buf: [3]u8 = undefined;
    mem.readSlice(0x5000, &buf);
    try std.testing.expectEqualSlices(u8, "abc", &buf);

    // Read second hint.
    cpu.writeReg(REG_A7, 240);
    _ = rt.handleSyscall(&cpu, &mem);
    try std.testing.expectEqual(@as(u32, 3), cpu.readReg(REG_A0));

    cpu.writeReg(REG_A7, 241);
    cpu.writeReg(REG_A0, 0x6000);
    cpu.writeReg(REG_A1, 3);
    _ = rt.handleSyscall(&cpu, &mem);

    mem.readSlice(0x6000, &buf);
    try std.testing.expectEqualSlices(u8, "xyz", &buf);
}
