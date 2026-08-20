//! Byte-identical software/precompile benchmark guest for
//! `riscv.poseidon2_m31.permute.v1`.
//!
//! Input: `[call_count: u32 LE][call_count * 16 canonical M31 words]`.
//! Output: `call_count * 16` canonical M31 words in the same order.
//!
//! The default build executes portable RV32IM field arithmetic. The
//! `precompile` feature preserves the I/O loop and replaces one measured
//! permutation by the exact version-1 CUSTOM-0 instruction. Workload-shape
//! features add the same fixed portable permutations to both arms: zero for
//! Poseidon2-dominant, one for balanced, and fifteen for core-dominated. Both
//! arms therefore share one source and one public contract without pretending
//! the older sponge guest is an equivalent function.

#![no_main]
#![no_std]

#[cfg(feature = "precompile")]
use core::arch::asm;
use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr;

const MODULUS: u32 = 0x7fff_ffff;
const WIDTH: usize = 16;
const MAX_CALLS: usize = 4096;

#[cfg(all(feature = "shape-balanced", feature = "shape-core-only"))]
compile_error!("C-013 workload-shape features are mutually exclusive");

#[cfg(feature = "shape-core-only")]
const BACKGROUND_PERMUTATIONS_PER_CALL: usize = 15;
#[cfg(all(not(feature = "shape-core-only"), feature = "shape-balanced"))]
const BACKGROUND_PERMUTATIONS_PER_CALL: usize = 1;
#[cfg(not(any(feature = "shape-core-only", feature = "shape-balanced")))]
const BACKGROUND_PERMUTATIONS_PER_CALL: usize = 0;

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

// Load-time admission for the exact extension profile. The section is absent
// from the software arm, which remains the base RV32IM profile.
#[cfg(feature = "precompile")]
global_asm!(
    r#"
    .section .note.stwo.zkvm,"",@note
    .balign 4
    .long 5
    .long 56
    .long 1
    .ascii "STWO\0"
    .balign 4
    .ascii "STWZKVM\0"
    .short 1
    .short 1
    .quad 1
    .short 1
    .short 0
    .byte 0x9e,0x8c,0x3b,0x5a,0xcc,0xdc,0x2b,0xe3
    .byte 0x1c,0xf8,0xca,0x12,0x8b,0x5b,0x27,0xc8
    .byte 0x76,0x13,0xf6,0x91,0xee,0x8f,0xd2,0x5e
    .byte 0x03,0x1f,0x42,0x86,0xce,0xac,0x81,0xed
    .balign 4
"#
);

type State = [u32; WIDTH];

#[inline(always)]
fn add(lhs: u32, rhs: u32) -> u32 {
    let sum = lhs + rhs;
    if sum >= MODULUS { sum - MODULUS } else { sum }
}

#[inline(always)]
fn reduce_u32(value: u32) -> u32 {
    let folded = (value & MODULUS) + (value >> 31);
    if folded >= MODULUS {
        folded - MODULUS
    } else {
        folded
    }
}

#[inline(always)]
fn rotate31(value: u32, shift: u32) -> u32 {
    add((value << shift) & MODULUS, value >> (31 - shift))
}

/// M31 multiplication using only exact 16-bit partial products. This avoids a
/// compiler-runtime division and keeps all work inside the proof-bearing
/// RV32IM instruction set.
#[inline(always)]
fn multiply(lhs: u32, rhs: u32) -> u32 {
    let lhs_low = lhs & 0xffff;
    let lhs_high = lhs >> 16;
    let rhs_low = rhs & 0xffff;
    let rhs_high = rhs >> 16;
    let low = core::hint::black_box(lhs_low.wrapping_mul(rhs_low));
    let cross_a = core::hint::black_box(lhs_low.wrapping_mul(rhs_high));
    let cross_b = core::hint::black_box(lhs_high.wrapping_mul(rhs_low));
    let high = core::hint::black_box(lhs_high.wrapping_mul(rhs_high));
    let cross = add(reduce_u32(cross_a), reduce_u32(cross_b));
    let mut result = reduce_u32(low);
    result = add(result, rotate31(cross, 16));
    add(result, rotate31(reduce_u32(high), 1))
}

#[inline(always)]
fn fifth_power(value: u32) -> u32 {
    let square = multiply(value, value);
    multiply(multiply(square, square), value)
}

#[inline(always)]
fn m4(input: [u32; 4]) -> [u32; 4] {
    let t0 = add(input[0], input[1]);
    let t02 = add(t0, t0);
    let t1 = add(input[2], input[3]);
    let t12 = add(t1, t1);
    let t2 = add(add(input[1], input[1]), t1);
    let t3 = add(add(input[3], input[3]), t0);
    let t4 = add(add(t12, t12), t3);
    let t5 = add(add(t02, t02), t2);
    [add(t3, t5), t5, add(t2, t4), t4]
}

fn external_matrix(state: &mut State) {
    let mut block = 0;
    while block < 4 {
        let offset = 4 * block;
        let output = m4([
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        ]);
        state[offset..offset + 4].copy_from_slice(&output);
        block += 1;
    }
    let mut lane = 0;
    while lane < 4 {
        let sum = add(
            add(state[lane], state[lane + 4]),
            add(state[lane + 8], state[lane + 12]),
        );
        let mut block = 0;
        while block < 4 {
            let index = 4 * block + lane;
            state[index] = add(state[index], sum);
            block += 1;
        }
        lane += 1;
    }
}

fn internal_matrix(state: &mut State) {
    let mut sum = 0;
    let mut lane = 0;
    while lane < WIDTH {
        sum = add(sum, state[lane]);
        lane += 1;
    }
    let mut lane = 0;
    while lane < WIDTH {
        state[lane] = add(multiply(state[lane], INTERNAL_MATRIX[lane]), sum);
        lane += 1;
    }
}

fn full_round(state: &mut State, constants: &State) {
    let mut lane = 0;
    while lane < WIDTH {
        state[lane] = fifth_power(add(state[lane], constants[lane]));
        lane += 1;
    }
    external_matrix(state);
}

fn permute(state: &mut State) {
    external_matrix(state);
    let mut round = 0;
    while round < 4 {
        full_round(state, &EXTERNAL_ROUNDS[round]);
        round += 1;
    }
    let mut round = 0;
    while round < INTERNAL_ROUNDS.len() {
        state[0] = fifth_power(add(state[0], INTERNAL_ROUNDS[round]));
        internal_matrix(state);
        round += 1;
    }
    let mut round = 4;
    while round < EXTERNAL_ROUNDS.len() {
        full_round(state, &EXTERNAL_ROUNDS[round]);
        round += 1;
    }
}

/// Runs the shape's source-identical portable background work. The returned
/// word is written through a volatile guest-output address before the measured
/// permutation overwrites it, keeping the work proof-visible without changing
/// the public output contract.
#[inline(never)]
fn run_background(mut state: State) -> Option<u32> {
    if BACKGROUND_PERMUTATIONS_PER_CALL == 0 {
        return None;
    }
    let mut round = 0;
    while round < BACKGROUND_PERMUTATIONS_PER_CALL {
        permute(&mut state);
        // Break identical-round symmetry while retaining canonical M31 words.
        let lane = round & (WIDTH - 1);
        state[lane] = add(state[lane], (round + 1) as u32);
        round += 1;
    }
    Some(state[(BACKGROUND_PERMUTATIONS_PER_CALL - 1) & (WIDTH - 1)])
}

#[inline(always)]
unsafe fn input_word(index: usize) -> u32 {
    let base = ptr::addr_of!(__input_start) as *const u32;
    unsafe { ptr::read_volatile(base.add(index)) }
}

#[inline(always)]
unsafe fn output_word(index: usize, value: u32) {
    let base = ptr::addr_of!(__output_data) as *mut u32;
    unsafe { ptr::write_volatile(base.add(index), value) };
}

#[cfg(feature = "precompile")]
#[inline(always)]
unsafe fn invoke_precompile(state: *mut u32) {
    // Canonical encoding for rs1=x5: 0x0200_000b | (5 << 15).
    unsafe {
        asm!(
            ".word 0x0202800b",
            in("x5") state,
            options(nostack),
        )
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn __zkvm_start() -> ! {
    let call_count = unsafe { input_word(0) } as usize;
    if call_count > MAX_CALLS {
        panic!();
    }

    let mut call = 0;
    while call < call_count {
        let word_offset = call * WIDTH;
        let mut state = [0u32; WIDTH];
        let mut lane = 0;
        while lane < WIDTH {
            let value = unsafe { input_word(1 + word_offset + lane) };
            if value >= MODULUS {
                panic!();
            }
            state[lane] = value;
            lane += 1;
        }
        if let Some(background_word) = run_background(state) {
            // This is intentionally overwritten below. Volatility makes the
            // portable background computation an observable guest effect.
            unsafe { output_word(word_offset, background_word) };
        }
        #[cfg(not(feature = "precompile"))]
        {
            permute(&mut state);
            let mut lane = 0;
            while lane < WIDTH {
                unsafe { output_word(word_offset + lane, state[lane]) };
                lane += 1;
            }
        }
        #[cfg(feature = "precompile")]
        {
            let mut lane = 0;
            while lane < WIDTH {
                unsafe { output_word(word_offset + lane, state[lane]) };
                lane += 1;
            }
            let output = ptr::addr_of!(__output_data) as *mut u32;
            unsafe { invoke_precompile(output.add(word_offset)) };
        }
        call += 1;
    }

    unsafe {
        ptr::write_volatile(
            ptr::addr_of!(__output_len) as *mut u32,
            (call_count * WIDTH * 4) as u32,
        );
        ptr::write_volatile(ptr::addr_of!(__halt_flag) as *mut u32, 1);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

const EXTERNAL_ROUNDS: [State; 8] = [
    [
        1988864850, 1893772157, 1025928330, 1839472709, 1611656994, 1104858731, 1694088660,
        1564660990, 1991332205, 1875486487, 1890340790, 1658614, 582370530, 528029397, 1196956642,
        655401251,
    ],
    [
        1652877415, 26032894, 1576640243, 1277052539, 1450142396, 697623591, 1401580866,
        1568404175, 2145004971, 265835716, 1183985610, 1031234465, 436012490, 172735299, 352802897,
        1032863094,
    ],
    [
        757665783, 1082171296, 1507509996, 309929890, 1807683232, 43258895, 611592566, 1854193793,
        575164234, 894217817, 72613857, 1061659596, 8921166, 1617355017, 998001536, 1800758877,
    ],
    [
        1002748055, 1935405944, 1351462722, 411368491, 1913975372, 1956167178, 442558016,
        855898408, 699687798, 1553382248, 1708169125, 490049183, 1251643415, 1193594742, 880473871,
        511174042,
    ],
    [
        1460209171, 530850056, 398192464, 536338716, 75179210, 1309934197, 1335920373, 127611036,
        291093831, 1832379621, 123571662, 303176864, 2137685056, 1759609530, 1418928155, 71608334,
    ],
    [
        6616262, 1684515814, 1721194338, 720801691, 878392254, 460379263, 87930647, 940673483,
        1136203256, 551499412, 256220454, 2007034235, 796124985, 410436345, 1705042586, 1286336446,
    ],
    [
        1522340456, 1295296352, 309794713, 1772145068, 956898901, 2137070800, 988829146,
        2059451359, 1846491684, 1105442551, 1236497773, 1452000568, 549485016, 385992492,
        1987107948, 1514377269,
    ],
    [
        2090065934, 1444920141, 293113979, 41120774, 855319793, 1663284746, 1789994008, 1120509162,
        358222743, 1406256810, 735183687, 664485235, 1331641456, 38121324, 595810771, 1234594393,
    ],
];

const INTERNAL_ROUNDS: [u32; 14] = [
    2139014335, 69309039, 1368974953, 886780232, 1130937085, 1718115455, 2027103386, 1612216449,
    1994053242, 110146615, 514413329, 1088763546, 955319292, 488794657,
];

const INTERNAL_MATRIX: State = [
    129501892, 1809435443, 1223573407, 1331944729, 415581875, 1526242955, 1341275624, 1333308150,
    1404946132, 1549369918, 709303410, 1284988537, 1490838740, 115945821, 754131590, 800486749,
];
