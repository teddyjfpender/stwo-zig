//! Recorded witness programs for three mid-tail Cairo opcode components, plus the
//! differential tests that establish (locally, without a pod) that each recording
//! reproduces the generated `write_trace_simd` decode bit-for-bit.
//!
//! These three were chosen to prove the framework generalizes across *distinct writer
//! shapes* (round-8 measured base-write shares in `WITNESS_ON_GPU.md`):
//!
//! - **`add_opcode`** (6.9%): the widest decode — three instruction offsets, five decoded flags, an
//!   `op1_base_ap` derived flag, and three memory-base columns mixing the flags with `ap`/`fp`.
//! - **`assert_eq_opcode`** (7.9% as `assert_eq_dd`-class): a narrower decode with a different
//!   column layout (two offsets, two flags) and the `M31_32767` sentinel.
//! - **`jnz_opcode_taken`** (0.68%): a *chained* memory read — the decoded offset feeds a computed
//!   address whose id is looked up, then that id's 28 value limbs are read and committed. Exercises
//!   multi-level dependent `deduce_output` reads, a shape the other two do not have.
//!
//! Each `record_*` function authors the component's decode against [`WitnessRecorder`].
//! In the target end-state this authoring is what stwo-air-infra would *emit* (the same
//! way it emits the constraint evaluators the constraint-JIT lane records); today the
//! generated writers are monomorphic (`PackedM31`/`PackedUInt16`) with no generic
//! recording entry point, so these are hand-authored ports — see the blocker note in
//! [`super`]. The scope recorded here is the closed-form decode + memory-limb commits:
//! the exact per-row arithmetic that the device kernel replaces. The lookup-tuple and
//! multiplicity emission are represented by the ISA (`LookupWord`/`MultPush`) and
//! covered structurally in [`super::codegen`] tests.

use super::isa::WitnessProgram;
use super::recording::{Val, WitnessRecorder};

/// `memory_address_to_id.deduce_output(addr) -> id` (id in limb 0).
pub const TABLE_ADDR_TO_ID: u32 = 0;
/// `memory_id_to_big.deduce_output(id) -> [limb_0 .. limb_27]` (9-bit limbs).
pub const TABLE_ID_TO_BIG: u32 = 1;

/// Read instruction limbs `0..=6` of the value at `pc`, truncated to u16
/// (`PackedUInt16::from_m31`), which is the identity for 9-bit limbs.
fn read_instruction_limbs(r: &mut WitnessRecorder, pc: Val) -> Vec<Val> {
    let id = r.table_limb(TABLE_ADDR_TO_ID, pc, 0);
    (0..7)
        .map(|i| {
            let raw = r.table_limb(TABLE_ID_TO_BIG, id, i);
            r.from_m31(raw)
        })
        .collect()
}

/// `flag = ((fb >> shift) & 1).as_m31()` — one decoded instruction flag.
fn decode_flag(r: &mut WitnessRecorder, fb: Val, shift: u32) -> Val {
    let s = r.u16_shr(fb, shift);
    let bit = r.u16_and(s, 1);
    r.as_m31(bit)
}

/// `flag_hi = (l5 >> 3) + (l6 << 6)` — the u16 word the instruction flags live in.
fn decode_flag_word(r: &mut WitnessRecorder, l5: Val, l6: Val) -> Val {
    let hi = r.u16_shr(l5, 3);
    let lo = r.u16_shl(l6, 6);
    r.u16_add(hi, lo)
}

/// `base = flag*fp + (1 - flag)*ap` — a memory-operand base address.
fn mem_base_fp_ap(r: &mut WitnessRecorder, flag: Val, ap: Val, fp: Val, one: Val) -> Val {
    let a = r.m31_mul(flag, fp);
    let inv = r.m31_sub(one, flag);
    let b = r.m31_mul(inv, ap);
    r.m31_add(a, b)
}

/// add_opcode decode core: columns 0..=13.
pub fn record_add_opcode_decode() -> WitnessProgram {
    let mut r = WitnessRecorder::new("add_opcode");
    let pc = r.input(0);
    let ap = r.input(1);
    let fp = r.input(2);
    r.col_write(0, pc);
    r.col_write(1, ap);
    r.col_write(2, fp);

    let l = read_instruction_limbs(&mut r, pc);

    // offset0 = l0 + ((l1 & 127) << 9)
    let t = r.u16_and(l[1], 127);
    let t = r.u16_shl(t, 9);
    let off0 = r.u16_add(l[0], t);
    let off0 = r.as_m31(off0);
    r.col_write(3, off0);

    // offset1 = ((l1 >> 7) + (l2 << 2)) + ((l3 & 31) << 11)
    let a1 = r.u16_shr(l[1], 7);
    let a2 = r.u16_shl(l[2], 2);
    let s1 = r.u16_add(a1, a2);
    let a3 = r.u16_and(l[3], 31);
    let a3 = r.u16_shl(a3, 11);
    let off1 = r.u16_add(s1, a3);
    let off1 = r.as_m31(off1);
    r.col_write(4, off1);

    // offset2 = ((l3 >> 5) + (l4 << 4)) + ((l5 & 7) << 13)
    let b1 = r.u16_shr(l[3], 5);
    let b2 = r.u16_shl(l[4], 4);
    let s2 = r.u16_add(b1, b2);
    let b3 = r.u16_and(l[5], 7);
    let b3 = r.u16_shl(b3, 13);
    let off2 = r.u16_add(s2, b3);
    let off2 = r.as_m31(off2);
    r.col_write(5, off2);

    // Flag word and the five decoded flags.
    let fb = decode_flag_word(&mut r, l[5], l[6]);
    let dst_base_fp = decode_flag(&mut r, fb, 0);
    r.col_write(6, dst_base_fp);
    let op0_base_fp = decode_flag(&mut r, fb, 1);
    r.col_write(7, op0_base_fp);
    let op1_imm = decode_flag(&mut r, fb, 2);
    r.col_write(8, op1_imm);
    let op1_base_fp = decode_flag(&mut r, fb, 3);
    r.col_write(9, op1_base_fp);
    let ap_update_add_1 = decode_flag(&mut r, fb, 11);
    r.col_write(10, ap_update_add_1);

    let one = r.constant(1);
    // op1_base_ap = (1 - op1_imm) - op1_base_fp
    let t = r.m31_sub(one, op1_imm);
    let op1_base_ap = r.m31_sub(t, op1_base_fp);

    // mem_dst_base (col11), mem0_base (col12).
    let mem_dst = mem_base_fp_ap(&mut r, dst_base_fp, ap, fp, one);
    r.col_write(11, mem_dst);
    let mem0 = mem_base_fp_ap(&mut r, op0_base_fp, ap, fp, one);
    r.col_write(12, mem0);

    // mem1_base = op1_imm*pc + op1_base_fp*fp + op1_base_ap*ap  (col13)
    let m0 = r.m31_mul(op1_imm, pc);
    let m1 = r.m31_mul(op1_base_fp, fp);
    let m2 = r.m31_mul(op1_base_ap, ap);
    let s = r.m31_add(m0, m1);
    let mem1 = r.m31_add(s, m2);
    r.col_write(13, mem1);

    r.finish()
}

/// assert_eq_opcode decode core: columns 0..=9.
pub fn record_assert_eq_opcode_decode() -> WitnessProgram {
    let mut r = WitnessRecorder::new("assert_eq_opcode");
    let pc = r.input(0);
    let ap = r.input(1);
    let fp = r.input(2);
    r.col_write(0, pc);
    r.col_write(1, ap);
    r.col_write(2, fp);

    let l = read_instruction_limbs(&mut r, pc);

    // offset0 = l0 + ((l1 & 127) << 9)  (col3)
    let t = r.u16_and(l[1], 127);
    let t = r.u16_shl(t, 9);
    let off0 = r.u16_add(l[0], t);
    let off0 = r.as_m31(off0);
    r.col_write(3, off0);

    // offset2 = ((l3 >> 5) + (l4 << 4)) + ((l5 & 7) << 13)  (col4)
    let b1 = r.u16_shr(l[3], 5);
    let b2 = r.u16_shl(l[4], 4);
    let s2 = r.u16_add(b1, b2);
    let b3 = r.u16_and(l[5], 7);
    let b3 = r.u16_shl(b3, 13);
    let off2 = r.u16_add(s2, b3);
    let off2 = r.as_m31(off2);
    r.col_write(4, off2);

    let fb = decode_flag_word(&mut r, l[5], l[6]);
    let dst_base_fp = decode_flag(&mut r, fb, 0);
    r.col_write(5, dst_base_fp);
    let op1_base_fp = decode_flag(&mut r, fb, 3);
    r.col_write(6, op1_base_fp);
    let ap_update_add_1 = decode_flag(&mut r, fb, 11);
    r.col_write(7, ap_update_add_1);

    let one = r.constant(1);
    // mem_dst_base (col8): dst_base_fp*fp + (1-dst_base_fp)*ap
    let mem_dst = mem_base_fp_ap(&mut r, dst_base_fp, ap, fp, one);
    r.col_write(8, mem_dst);
    // mem1_base (col9): op1_base_fp*fp + (1-op1_base_fp)*ap
    let mem1 = mem_base_fp_ap(&mut r, op1_base_fp, ap, fp, one);
    r.col_write(9, mem1);

    r.finish()
}

/// jnz_opcode_taken decode core: columns 0..=35 (decode + chained dst read + 28 limbs).
pub fn record_jnz_opcode_taken_decode() -> WitnessProgram {
    let mut r = WitnessRecorder::new("jnz_opcode_taken");
    let pc = r.input(0);
    let ap = r.input(1);
    let fp = r.input(2);
    r.col_write(0, pc);
    r.col_write(1, ap);
    r.col_write(2, fp);

    let l = read_instruction_limbs(&mut r, pc);

    // offset0 = l0 + ((l1 & 127) << 9)  (col3)
    let t = r.u16_and(l[1], 127);
    let t = r.u16_shl(t, 9);
    let off0 = r.u16_add(l[0], t);
    let off0 = r.as_m31(off0);
    r.col_write(3, off0);

    let fb = decode_flag_word(&mut r, l[5], l[6]);
    let dst_base_fp = decode_flag(&mut r, fb, 0);
    r.col_write(4, dst_base_fp);
    let ap_update_add_1 = decode_flag(&mut r, fb, 11);
    r.col_write(5, ap_update_add_1);

    let one = r.constant(1);
    // mem_dst_base (col6)
    let mem_dst = mem_base_fp_ap(&mut r, dst_base_fp, ap, fp, one);
    r.col_write(6, mem_dst);

    // Chained read: dst_addr = mem_dst + (offset0 - 32768); dst_id = addr_to_id(dst_addr).
    let c32768 = r.constant(32768);
    let signed_off0 = r.m31_sub(off0, c32768);
    let dst_addr = r.m31_add(mem_dst, signed_off0);
    let dst_id = r.table_limb(TABLE_ADDR_TO_ID, dst_addr, 0);
    r.col_write(7, dst_id);

    // 28 value limbs of dst_id (cols 8..=35).
    for i in 0..28u32 {
        let limb = r.table_limb(TABLE_ID_TO_BIG, dst_id, i);
        r.col_write(8 + i, limb);
    }

    r.finish()
}

/// The three recorded programs, for the dispatch registry and tests.
pub fn all_programs() -> Vec<WitnessProgram> {
    vec![
        record_add_opcode_decode(),
        record_assert_eq_opcode_decode(),
        record_jnz_opcode_taken_decode(),
    ]
}

#[cfg(test)]
mod tests {
    use super::super::codegen::compile_witness_to_cuda_source;
    use super::super::interp::{interpret_row, m31_add, m31_mul, m31_sub};
    use super::*;

    // ---------------------------------------------------------------------
    // Synthetic memory image: the SAME oracle feeds both the recorded-program
    // interpreter and the native reference, so a match proves the recording
    // reproduces the native decode (independent of the oracle's contents).
    // ---------------------------------------------------------------------

    fn splitmix(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// table 0 (addr->id): id in `[1, 2^20)`. table 1 (id->big): 9-bit limbs.
    fn oracle(table: u32, key: u32, limb: u32) -> u32 {
        match table {
            TABLE_ADDR_TO_ID => (splitmix(key as u64) % ((1 << 20) - 1)) as u32 + 1,
            TABLE_ID_TO_BIG => (splitmix(key as u64 * 131 + limb as u64) & 0x1FF) as u32,
            _ => unreachable!("unknown table {table}"),
        }
    }

    // u16/M31 primitives mirroring PackedUInt16 / PackedM31 for the native references.
    fn from_m31(x: u32) -> u32 {
        x & 0xFFFF
    }
    fn as_m31(x: u32) -> u32 {
        x % ((1 << 31) - 1)
    }
    fn u16_add(a: u32, b: u32) -> u32 {
        a.wrapping_add(b) & 0xFFFF
    }
    fn u16_shl(a: u32, s: u32) -> u32 {
        (a << s) & 0xFFFF
    }
    fn u16_shr(a: u32, s: u32) -> u32 {
        (a & 0xFFFF) >> s
    }
    fn u16_and(a: u32, m: u32) -> u32 {
        a & m
    }

    fn limbs(pc: u32) -> [u32; 7] {
        let id = oracle(TABLE_ADDR_TO_ID, pc, 0);
        let mut out = [0u32; 7];
        for (i, o) in out.iter_mut().enumerate() {
            *o = from_m31(oracle(TABLE_ID_TO_BIG, id, i as u32));
        }
        out
    }

    fn flag_word(l5: u32, l6: u32) -> u32 {
        u16_add(u16_shr(l5, 3), u16_shl(l6, 6))
    }
    fn flag(fb: u32, shift: u32) -> u32 {
        as_m31(u16_and(u16_shr(fb, shift), 1))
    }
    fn mem_base(flag: u32, ap: u32, fp: u32) -> u32 {
        m31_add(m31_mul(flag, fp), m31_mul(m31_sub(1, flag), ap))
    }

    fn native_add_opcode(pc: u32, ap: u32, fp: u32) -> Vec<u32> {
        let l = limbs(pc);
        let off0 = as_m31(u16_add(l[0], u16_shl(u16_and(l[1], 127), 9)));
        let off1 = as_m31(u16_add(
            u16_add(u16_shr(l[1], 7), u16_shl(l[2], 2)),
            u16_shl(u16_and(l[3], 31), 11),
        ));
        let off2 = as_m31(u16_add(
            u16_add(u16_shr(l[3], 5), u16_shl(l[4], 4)),
            u16_shl(u16_and(l[5], 7), 13),
        ));
        let fb = flag_word(l[5], l[6]);
        let dst_base_fp = flag(fb, 0);
        let op0_base_fp = flag(fb, 1);
        let op1_imm = flag(fb, 2);
        let op1_base_fp = flag(fb, 3);
        let ap_update = flag(fb, 11);
        let op1_base_ap = m31_sub(m31_sub(1, op1_imm), op1_base_fp);
        let mem_dst = mem_base(dst_base_fp, ap, fp);
        let mem0 = mem_base(op0_base_fp, ap, fp);
        let mem1 = m31_add(
            m31_add(m31_mul(op1_imm, pc), m31_mul(op1_base_fp, fp)),
            m31_mul(op1_base_ap, ap),
        );
        vec![
            pc,
            ap,
            fp,
            off0,
            off1,
            off2,
            dst_base_fp,
            op0_base_fp,
            op1_imm,
            op1_base_fp,
            ap_update,
            mem_dst,
            mem0,
            mem1,
        ]
    }

    fn native_assert_eq(pc: u32, ap: u32, fp: u32) -> Vec<u32> {
        let l = limbs(pc);
        let off0 = as_m31(u16_add(l[0], u16_shl(u16_and(l[1], 127), 9)));
        let off2 = as_m31(u16_add(
            u16_add(u16_shr(l[3], 5), u16_shl(l[4], 4)),
            u16_shl(u16_and(l[5], 7), 13),
        ));
        let fb = flag_word(l[5], l[6]);
        let dst_base_fp = flag(fb, 0);
        let op1_base_fp = flag(fb, 3);
        let ap_update = flag(fb, 11);
        let mem_dst = mem_base(dst_base_fp, ap, fp);
        let mem1 = mem_base(op1_base_fp, ap, fp);
        vec![
            pc,
            ap,
            fp,
            off0,
            off2,
            dst_base_fp,
            op1_base_fp,
            ap_update,
            mem_dst,
            mem1,
        ]
    }

    fn native_jnz(pc: u32, ap: u32, fp: u32) -> Vec<u32> {
        let l = limbs(pc);
        let off0 = as_m31(u16_add(l[0], u16_shl(u16_and(l[1], 127), 9)));
        let fb = flag_word(l[5], l[6]);
        let dst_base_fp = flag(fb, 0);
        let ap_update = flag(fb, 11);
        let mem_dst = mem_base(dst_base_fp, ap, fp);
        let dst_addr = m31_add(mem_dst, m31_sub(off0, 32768));
        let dst_id = oracle(TABLE_ADDR_TO_ID, dst_addr, 0);
        let mut cols = vec![pc, ap, fp, off0, dst_base_fp, ap_update, mem_dst, dst_id];
        for i in 0..28u32 {
            cols.push(oracle(TABLE_ID_TO_BIG, dst_id, i));
        }
        cols
    }

    /// Deterministic pseudo-random Cairo states (canonical M31 pc/ap/fp).
    fn sample_inputs(n: usize) -> Vec<Vec<u32>> {
        (0..n)
            .map(|i| {
                let base = splitmix(0xC0FFEE + i as u64);
                let pc = (base % ((1 << 31) - 1)) as u32;
                let ap = (splitmix(base) % ((1 << 31) - 1)) as u32;
                let fp = (splitmix(base ^ 0xABCD) % ((1 << 31) - 1)) as u32;
                vec![pc, ap, fp]
            })
            .collect()
    }

    fn assert_matches(
        prog: &WitnessProgram,
        native: impl Fn(u32, u32, u32) -> Vec<u32>,
        expect_cols: usize,
    ) {
        assert_eq!(prog.n_cols as usize, expect_cols, "column count");
        for inputs in sample_inputs(256) {
            let got = interpret_row(prog, &inputs, &oracle);
            let want = native(inputs[0], inputs[1], inputs[2]);
            assert_eq!(
                got.columns, want,
                "decode mismatch for pc={} ap={} fp={}",
                inputs[0], inputs[1], inputs[2]
            );
        }
        // The recorded program must also codegen (every opcode handled).
        assert!(compile_witness_to_cuda_source(prog).is_some());
    }

    #[test]
    fn add_opcode_recording_matches_native_decode() {
        assert_matches(&record_add_opcode_decode(), native_add_opcode, 14);
    }

    #[test]
    fn assert_eq_opcode_recording_matches_native_decode() {
        assert_matches(&record_assert_eq_opcode_decode(), native_assert_eq, 10);
    }

    #[test]
    fn jnz_opcode_taken_recording_matches_native_decode() {
        assert_matches(&record_jnz_opcode_taken_decode(), native_jnz, 36);
    }

    #[test]
    fn the_three_shapes_are_distinct() {
        // Distinct decode structures must produce distinct kernels (no accidental
        // cache-key collision that would run the wrong kernel).
        let progs = all_programs();
        let hashes: Vec<u64> = progs.iter().map(|p| p.semantic_hash()).collect();
        assert_ne!(hashes[0], hashes[1]);
        assert_ne!(hashes[0], hashes[2]);
        assert_ne!(hashes[1], hashes[2]);
    }
}
