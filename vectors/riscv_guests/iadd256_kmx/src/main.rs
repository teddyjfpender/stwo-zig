//! Fixed public iadd256.kmx, one 64-shot slice of the upstream SP1 fuzzer.
//!
//! The circuit bytes are supplied in the proof's public input and checked
//! against the fixture SHA-256. This binds the compiled gate table exactly,
//! but is not a private-circuit proof or a completed multi-batch reduction.

#![no_std]
#![no_main]

use core::{arch::global_asm, panic::PanicInfo, ptr, slice};
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const FIXTURE_SHA256: [u8; 32] = [
    0xeb, 0x85, 0xf1, 0xe6, 0x1b, 0x23, 0x5e, 0x2f, 0x59, 0x8d, 0x91, 0x0c, 0x93, 0x20, 0x8b, 0x81,
    0x3f, 0x97, 0x4a, 0xa0, 0x2b, 0x43, 0x49, 0x7b, 0x85, 0x9d, 0xac, 0x02, 0xd4, 0xb2, 0x14, 0x3d,
];
const FIXTURE_LEN: usize = 49_249;
const INPUT_HEADER_LEN: usize = 28;
const SHOTS_PER_BATCH: usize = 64;
const QUBITS: usize = 512;

#[derive(Clone, Copy)]
struct Gate {
    a: u16,
    b: u16,
    target: u16,
    ccx: bool,
}
include!(concat!(env!("OUT_DIR"), "/gates.rs"));

unsafe extern "C" {
    static __input_start: u8;
    static __halt_flag: u8;
    static __output_len: u8;
    static __output_data: u8;
}

global_asm!(
    r#"
    .section .text._start
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    call __zkvm_start
"#
);

#[inline(always)]
fn word(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn expected(target: [u32; 8], offset: [u32; 8], repetitions: u32) -> [u32; 8] {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let sum = (target[i] as u64) + (offset[i] as u64) * (repetitions as u64) + carry;
        out[i] = sum as u32;
        carry = sum >> 32;
    }
    out
}

#[no_mangle]
pub extern "C" fn __zkvm_start() -> ! {
    // Public input: reps, total shots, batch index, qubit cap, per-shot
    // non-Clifford cap, operation cap, KMX byte length, raw KMX bytes.
    let input = unsafe {
        slice::from_raw_parts(ptr::addr_of!(__input_start), INPUT_HEADER_LEN + FIXTURE_LEN)
    };
    let repetitions = word(input, 0);
    let total_shots = word(input, 4) as usize;
    let batch = word(input, 8) as usize;
    let qubit_cap = word(input, 12);
    let non_clifford_cap = word(input, 16);
    let operation_cap = word(input, 20);
    let circuit_len = word(input, 24) as usize;
    assert!(repetitions > 0 && repetitions <= 8_000);
    assert!(total_shots > 0 && total_shots <= 9_024);
    assert!(batch < total_shots.div_ceil(SHOTS_PER_BATCH));
    assert_eq!(circuit_len, FIXTURE_LEN);
    assert!(qubit_cap >= QUBITS as u32);
    assert!(non_clifford_cap >= 509 * repetitions);
    assert!(operation_cap >= 3061 * repetitions);
    let circuit = &input[INPUT_HEADER_LEN..INPUT_HEADER_LEN + circuit_len];
    let digest = Sha256::digest(circuit);
    assert_eq!(digest.as_slice(), FIXTURE_SHA256);

    // Upstream draws *all* target/offset pairs from SHAKE256(raw KMX bytes)
    // before running any shot. Since this fixed circuit has no RNG-consuming
    // gates, a batch needs only the exact XOF prefix through its own last
    // shot; later draws cannot affect its state or expected output.
    let mut shake = Shake256::default();
    Update::update(&mut shake, circuit);
    let mut xof = shake.finalize_xof();
    let mut qubits = [0u64; QUBITS];
    let mut targets = [[0u32; 8]; SHOTS_PER_BATCH];
    let mut offsets = [[0u32; 8]; SHOTS_PER_BATCH];
    let first = batch * SHOTS_PER_BATCH;
    let last = (first + SHOTS_PER_BATCH).min(total_shots);
    for shot in 0..last {
        let mut target_bytes = [0u8; 32];
        let mut offset_bytes = [0u8; 32];
        xof.read(&mut target_bytes);
        xof.read(&mut offset_bytes);
        if shot < first || shot >= last {
            continue;
        }
        let local = shot - first;
        for limb in 0..8 {
            targets[local][limb] = word(&target_bytes, limb * 4);
            offsets[local][limb] = word(&offset_bytes, limb * 4);
            for bit in 0..32 {
                let q = limb * 32 + bit;
                qubits[q] |= (((targets[local][limb] >> bit) & 1) as u64) << local;
                qubits[256 + q] |= (((offsets[local][limb] >> bit) & 1) as u64) << local;
            }
        }
    }

    for _ in 0..repetitions {
        for gate in GATES {
            let a = qubits[gate.a as usize];
            let mask = if gate.ccx {
                a & qubits[gate.b as usize]
            } else {
                a
            };
            qubits[gate.target as usize] ^= mask;
        }
    }

    for shot in 0..last - first {
        let local = shot as u32;
        let want = expected(targets[shot], offsets[shot], repetitions);
        for limb in 0..8 {
            let mut got_target = 0u32;
            let mut got_offset = 0u32;
            for bit in 0..32 {
                let q = limb * 32 + bit;
                got_target |= (((qubits[q] >> local) & 1) as u32) << bit;
                got_offset |= (((qubits[256 + q] >> local) & 1) as u32) << bit;
            }
            assert_eq!(got_target, want[limb]);
            assert_eq!(got_offset, offsets[shot][limb]);
        }
    }

    // The build script rejects every operation outside CX/CCX, validates all
    // qubit indexes are in the two registers, and therefore rules out both
    // phase changes and ancillary qubits for this pinned fixture.

    // Publish the circuit identity and exact batch parameters, followed by
    // the upstream success byte. The complete sequence requires a wrapper to
    // authenticate each distinct batch and its coverage.
    unsafe {
        let output = ptr::addr_of!(__output_data) as *mut u8;
        for (i, byte) in FIXTURE_SHA256.iter().enumerate() {
            ptr::write_volatile(output.add(i), *byte);
        }
        for (i, value) in [
            repetitions,
            total_shots as u32,
            batch as u32,
            qubit_cap,
            non_clifford_cap,
            operation_cap,
        ]
        .iter()
        .enumerate()
        {
            for (j, byte) in value.to_le_bytes().iter().enumerate() {
                ptr::write_volatile(output.add(32 + 4 * i + j), *byte);
            }
        }
        ptr::write_volatile(output.add(56), 42);
        ptr::write_volatile(ptr::addr_of!(__output_len) as *mut u32, 57);
        ptr::write_volatile(ptr::addr_of!(__halt_flag) as *mut u32, 1);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
