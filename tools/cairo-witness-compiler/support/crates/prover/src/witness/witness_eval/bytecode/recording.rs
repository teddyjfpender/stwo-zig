//! Recording builder for backend-neutral witness programs.
//!
//! The source rewriter turns each monomorphic `write_trace_simd` row body into calls on
//! `WitnessEval`. [`WitnessRecorder`] captures those calls as a [`WitnessProgram`].
//!
//! Values are opaque [`Val`] handles (Copy — an SSA register index). Every builder
//! method appends exactly one instruction, so the register file stays in pure SSA form
//! (each register written once), allowing every backend to consume a straight linear
//! instruction stream.

use super::isa::{DeduceKind, WitnessInst, WitnessOp, WitnessProgram};

/// Handle to an SSA register produced by the recorder.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Val(pub(crate) u16);

/// Records a witness component's per-row semantics into [`WitnessProgram`] bytecode.
pub struct WitnessRecorder {
    label: String,
    insts: Vec<WitnessInst>,
    next_reg: u16,
    n_inputs: u32,
    n_cols: u32,
    mult_tables: Vec<u32>,
    n_lookup_words: u32,
    n_sub_words: u32,
}

impl WitnessRecorder {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            insts: Vec::new(),
            next_reg: 0,
            n_inputs: 0,
            n_cols: 0,
            mult_tables: Vec::new(),
            n_lookup_words: 0,
            n_sub_words: 0,
        }
    }

    fn alloc(&mut self) -> u16 {
        let reg = self.next_reg;
        self.next_reg = reg.checked_add(1).expect("witness register overflow");
        reg
    }

    fn emit(&mut self, op: WitnessOp, a: u32, b: u32, imm: u32) -> Val {
        debug_assert!(op.writes_dst());
        let dst = self.alloc();
        self.insts.push(WitnessInst::new(op, dst, a, b, imm));
        Val(dst)
    }

    // --- Leaves ---

    /// Read packed input field `slot` (e.g. CasmState pc=0/ap=1/fp=2).
    pub fn input(&mut self, slot: u32) -> Val {
        self.n_inputs = self.n_inputs.max(slot + 1);
        self.emit(WitnessOp::Input, slot, 0, 0)
    }

    /// Materialize a constant. M31 constants must already be canonical (`< P`); raw
    /// constants (shift amounts, masks) are stored as-is in `imm`.
    pub fn constant(&mut self, value: u32) -> Val {
        self.emit(WitnessOp::Const, 0, 0, value)
    }

    // --- M31 field arithmetic ---

    pub fn m31_add(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::M31Add, a.0 as u32, b.0 as u32, 0)
    }
    pub fn m31_sub(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::M31Sub, a.0 as u32, b.0 as u32, 0)
    }
    pub fn m31_mul(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::M31Mul, a.0 as u32, b.0 as u32, 0)
    }
    pub fn m31_neg(&mut self, a: Val) -> Val {
        self.emit(WitnessOp::M31Neg, a.0 as u32, 0, 0)
    }

    // --- 16-bit wrapping / bit ops (PackedUInt16) ---

    pub fn u16_add(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::U16Add, a.0 as u32, b.0 as u32, 0)
    }
    pub fn u16_shl(&mut self, a: Val, amount: u32) -> Val {
        self.emit(WitnessOp::U16Shl, a.0 as u32, 0, amount)
    }
    pub fn u16_shr(&mut self, a: Val, amount: u32) -> Val {
        self.emit(WitnessOp::U16Shr, a.0 as u32, 0, amount)
    }
    pub fn u16_and(&mut self, a: Val, mask: u32) -> Val {
        self.emit(WitnessOp::U16And, a.0 as u32, 0, mask)
    }

    // --- 32-bit wrapping / bit ops ---

    pub fn u32_add(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::U32Add, a.0 as u32, b.0 as u32, 0)
    }
    pub fn u32_sub(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::U32Sub, a.0 as u32, b.0 as u32, 0)
    }
    pub fn u32_mul(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::U32Mul, a.0 as u32, b.0 as u32, 0)
    }
    pub fn u32_shl(&mut self, a: Val, amount: u32) -> Val {
        self.emit(WitnessOp::U32Shl, a.0 as u32, 0, amount)
    }
    pub fn u32_shr(&mut self, a: Val, amount: u32) -> Val {
        self.emit(WitnessOp::U32Shr, a.0 as u32, 0, amount)
    }
    pub fn u32_and(&mut self, a: Val, mask: u32) -> Val {
        self.emit(WitnessOp::U32And, a.0 as u32, 0, mask)
    }
    pub fn u32_xor(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::U32Xor, a.0 as u32, b.0 as u32, 0)
    }

    // --- Conversions ---

    /// `PackedUInt16::as_m31` — canonical reduction (identity for 16-bit values).
    pub fn as_m31(&mut self, a: Val) -> Val {
        self.emit(WitnessOp::AsM31, a.0 as u32, 0, 0)
    }
    /// `PackedUInt16::from_m31` — truncate to 16 bits.
    pub fn from_m31(&mut self, a: Val) -> Val {
        self.emit(WitnessOp::Trunc16, a.0 as u32, 0, 0)
    }

    // --- Table reads (deduce_output) ---

    /// Read limb `limb` of table `table` at `key`. See [`WitnessOp::TableLimb`].
    pub fn table_limb(&mut self, table: u32, key: Val, limb: u32) -> Val {
        self.emit(WitnessOp::TableLimb, key.0 as u32, table, limb)
    }

    // --- Outputs (no dst) ---

    /// Commit `value` to trace column `col`.
    pub fn col_write(&mut self, col: u32, value: Val) {
        self.n_cols = self.n_cols.max(col + 1);
        self.insts.push(WitnessInst::new(
            WitnessOp::ColWrite,
            0,
            value.0 as u32,
            0,
            col,
        ));
    }

    /// Push one multiplicity into `table` keyed by `key`.
    pub fn mult_push(&mut self, table: u32, key: Val) {
        if !self.mult_tables.contains(&table) {
            self.mult_tables.push(table);
        }
        self.insts.push(WitnessInst::new(
            WitnessOp::MultPush,
            0,
            key.0 as u32,
            0,
            table,
        ));
    }

    /// Emit lookup-tuple coordinate `word_index` = `value`.
    pub fn lookup_word(&mut self, word_index: u32, value: Val) {
        self.n_lookup_words = self.n_lookup_words.max(word_index + 1);
        self.insts.push(WitnessInst::new(
            WitnessOp::LookupWord,
            0,
            value.0 as u32,
            0,
            word_index,
        ));
    }

    /// Emit a sub-component input word (see [`WitnessOp::SubWord`]).
    /// dst = a^(P-2) (ISA-V2; total: inverse(0) = 0).
    pub fn m31_inverse(&mut self, a: Val) -> Val {
        self.emit(WitnessOp::M31Inverse, a.0 as u32, 0, 0)
    }

    /// dst = (a == b) ? 1 : 0 (ISA-V2 mask representation).
    pub fn m31_eq(&mut self, a: Val, b: Val) -> Val {
        self.emit(WitnessOp::M31Eq, a.0 as u32, b.0 as u32, 0)
    }

    pub fn sub_word(&mut self, word_index: u32, value: Val) {
        self.n_sub_words = self.n_sub_words.max(word_index + 1);
        self.insts.push(WitnessInst::new(
            WitnessOp::SubWord,
            0,
            value.0 as u32,
            0,
            word_index,
        ));
    }

    /// Finish recording and package the program.
    /// Computed deduce (ISA-V3): pushes `args` (fixed width per kind, asserted), then
    /// one `DeduceCall` defining a contiguous bank of output registers. Argument and
    /// output ORDER is the host `fast_deduction` signature order, felts flattened to
    /// their 28 canonical limbs — the device functions and the `DeduceHost` reference
    /// use exactly the same flattening.
    pub fn deduce(&mut self, kind: DeduceKind, args: &[Val]) -> Vec<Val> {
        let (n_args, n_outs) = kind.shape();
        assert_eq!(
            args.len(),
            n_args,
            "deduce {kind:?}: wrong arg count (recorder bug)"
        );
        for arg in args {
            self.insts.push(WitnessInst::new(
                WitnessOp::DeduceArg,
                0,
                arg.0 as u32,
                0,
                0,
            ));
        }
        let base = self.next_reg;
        let outs: Vec<Val> = (0..n_outs).map(|_| Val(self.alloc())).collect();
        self.insts.push(WitnessInst::new(
            WitnessOp::DeduceCall,
            base,
            0,
            n_outs as u32,
            kind as u32,
        ));
        outs
    }

    pub fn finish(self) -> WitnessProgram {
        WitnessProgram {
            label: self.label,
            insts: self.insts,
            n_regs: self.next_reg as u32,
            n_inputs: self.n_inputs,
            n_cols: self.n_cols,
            n_mult_tables: self.mult_tables.len() as u32,
            n_lookup_words: self.n_lookup_words,
            n_sub_words: self.n_sub_words,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_is_ssa_and_counts_shape() {
        let mut r = WitnessRecorder::new("toy");
        let pc = r.input(0);
        let ap = r.input(1);
        let c1 = r.constant(1);
        let sum = r.m31_add(pc, ap);
        let dec = r.m31_sub(sum, c1);
        r.col_write(0, dec);
        r.mult_push(7, dec);
        r.lookup_word(0, pc);
        let prog = r.finish();

        // SSA: every writing instruction has a unique, monotonically increasing dst.
        let mut expected = 0u16;
        for inst in &prog.insts {
            if WitnessOp::from_raw(inst.op).unwrap().writes_dst() {
                assert_eq!(inst.dst, expected);
                expected += 1;
            }
        }
        assert_eq!(prog.n_regs, expected as u32);
        assert_eq!(prog.n_inputs, 2);
        assert_eq!(prog.n_cols, 1);
        assert_eq!(prog.n_mult_tables, 1);
        assert_eq!(prog.n_lookup_words, 1);
    }
}
