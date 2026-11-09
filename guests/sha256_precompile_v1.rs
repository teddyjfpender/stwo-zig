//! Allocation-free SHA-256 framing over the two-pointer compression instruction.
//! Native entry points require an executable admitted for this capability.
//! Pattern: ZisK's aligned-block fast path and compression-only syscall; the
//! alignment and instruction ABI here are specific to the RV32/M31 prover.

pub const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
pub const COMPRESSION_WORD: u32 = 0x0c62_800b; // rs1=t0/x5, rs2=t1/x6

#[repr(align(4))]
struct AlignedBlock([u8; 64]);

/// The compressor receives disjoint, four-byte-aligned state/message spans.
/// Complete aligned input blocks are borrowed directly. Other blocks use one
/// reusable stack buffer; neither message length nor block count adds storage.
pub fn hash_with(mut input: &[u8], mut compress: impl FnMut(&mut [u32; 8], &[u8; 64])) -> [u8; 32] {
    let bit_length = (input.len() as u64)
        .checked_mul(8)
        .expect("SHA-256 input too long");
    let mut state = INITIAL_STATE;
    let mut scratch = AlignedBlock([0; 64]);
    while input.len() >= 64 {
        let block: &[u8; 64] = input[..64].try_into().unwrap();
        if (block.as_ptr() as usize) & 3 == 0 {
            compress(&mut state, block);
        } else {
            scratch.0.copy_from_slice(block);
            compress(&mut state, &scratch.0);
        }
        input = &input[64..];
    }
    scratch.0.fill(0);
    scratch.0[..input.len()].copy_from_slice(input);
    scratch.0[input.len()] = 0x80;
    if input.len() >= 56 {
        compress(&mut state, &scratch.0);
        scratch.0.fill(0);
    }
    scratch.0[56..].copy_from_slice(&bit_length.to_be_bytes());
    compress(&mut state, &scratch.0);
    let mut output = [0; 32];
    for (word, bytes) in state.iter().zip(output.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    output
}

// Selecting the module is insufficient to enable the instruction. The guest
// build must explicitly select the new admitted capability; there is no host
// hint or unproved native digest fallback.
#[cfg(all(
    any(stwo_sha256_precompile_v1, feature = "sha256-precompile"),
    not(all(target_arch = "riscv32", target_endian = "little"))
))]
compile_error!("the SHA compression capability requires little-endian RV32");

#[cfg(all(
    any(stwo_sha256_precompile_v1, feature = "sha256-precompile"),
    target_arch = "riscv32",
    target_endian = "little"
))]
pub fn hash(input: &[u8]) -> [u8; 32] {
    hash_with(input, |state, block| unsafe {
        core::arch::asm!(
            ".word {instruction}",
            instruction = const COMPRESSION_WORD,
            in("t0") state.as_mut_ptr(),
            in("t1") block.as_ptr(),
            options(nostack),
        );
    })
}
