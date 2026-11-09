//! Execution-only host ABI. This contract has no proving dependencies.

const Cpu = @import("../runner/cpu.zig").Cpu;
const Memory = @import("../runner/memory.zig").Memory;

/// Syscall numbers matching the SP1/stark-v ABI.
/// Guest places the syscall number in register a7 (x17) before ECALL.
pub const SyscallNr = enum(u32) {
    /// Terminate with exit code in a0.
    HALT = 0,
    /// Write buffer to host: a0=fd, a1=buf_ptr, a2=len. Returns bytes written in a0.
    WRITE = 2,
    /// Commit public output: a0=buf_ptr, a1=len.
    COMMIT = 16,
    /// Get length of next available hint. Returns length in a0.
    HINT_LEN = 240,
    /// Read hint bytes into guest memory: a0=buf_ptr, a1=len. Returns bytes read in a0.
    HINT_READ = 241,
    /// Accelerated keccak256: a0=input_ptr, a1=input_len, a2=output_ptr.
    /// Writes 32-byte hash to output_ptr.
    KECCAK256 = 242,
    /// Accelerated ecrecover: a0=input_ptr (128 bytes: msg_hash[32] + v[32] + r[32] + s[32]),
    /// a1=output_ptr. Writes 32-byte recovered address (zero-padded) to output_ptr.
    /// Returns 1 in a0 on success, 0 on failure.
    ECRECOVER = 243,
    /// Accelerated SHA256: a0=input_ptr, a1=input_len, a2=output_ptr.
    /// Writes 32-byte hash to output_ptr.
    SHA256 = 244,
    /// Unknown / unsupported syscall.
    _,
};

/// Result of handling a syscall.
pub const SyscallResult = union(enum) {
    /// Continue execution (runner advances PC by 4).
    Continue,
    /// Halt execution with the given exit code.
    Halt: u32,
};

/// Memory write record for state chain tracking.
/// When a syscall writes to guest memory (e.g. HINT_READ), each written
/// word must be recorded in the state chain tracker.
pub const MemoryWrite = struct {
    addr: u32,
    previous_value: u32,
    value: u32,
};

/// Polymorphic interface that the runner calls on ECALL.
///
/// Implementations handle syscall dispatch based on registers and may
/// read/write guest memory and CPU registers.
pub const HostInterface = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Handle a syscall. The implementation reads a7 for the syscall
        /// number and a0-a6 for arguments, and may modify registers
        /// (e.g. set a0 for return values) and memory.
        handleSyscall: *const fn (ptr: *anyopaque, cpu: *Cpu, mem: *Memory) SyscallResult,

        /// Return memory writes performed by the last handleSyscall call.
        /// Used by the runner to record syscall-induced memory changes
        /// in the state chain tracker. Returns word-aligned (addr, u32) pairs.
        lastMemoryWrites: *const fn (ptr: *anyopaque) []const MemoryWrite,
    };

    pub fn handleSyscall(self: HostInterface, cpu: *Cpu, mem: *Memory) SyscallResult {
        return self.vtable.handleSyscall(self.ptr, cpu, mem);
    }

    pub fn lastMemoryWrites(self: HostInterface) []const MemoryWrite {
        return self.vtable.lastMemoryWrites(self.ptr);
    }
};
