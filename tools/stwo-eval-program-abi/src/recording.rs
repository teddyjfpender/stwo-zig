//! Recording evaluator for lowering `FrameworkEval` constraint trees to V1
//! bytecode.
//!
//! The [`RecordingEvaluator`] implements the [`EvalAtRow`] trait from the stwo
//! constraint framework.  Instead of computing concrete field values it records
//! symbolic operations as V1 base/ext instructions and constraint roots.

// Ported intact from the prototype; the non-fused entry points are unused by this
// trimmed lane but kept so the module stays diffable against the source project.
#![allow(dead_code)]

use std::cell::RefCell;
use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};
use std::rc::Rc;
use std::vec::Vec;

use num_traits::{One, Zero};
use stwo::core::Fraction;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::EvalAtRow;
use stwo_constraint_framework::logup::LogupAtRow;

use super::program::{
    MetalEvaluationProgramBaseInstV1, MetalEvaluationProgramBaseOpcodeV1,
    MetalEvaluationProgramExtInstV1, MetalEvaluationProgramExtOpcodeV1,
};

// =========================================================================
// Shared recording state
// =========================================================================

/// Accumulated recording state shared (via `Rc<RefCell<..>>`) between the
/// evaluator and every symbolic value it produces.
#[allow(dead_code)]
pub(crate) struct RecordingState {
    pub base_insts: Vec<MetalEvaluationProgramBaseInstV1>,
    pub ext_insts: Vec<MetalEvaluationProgramExtInstV1>,
    pub constraint_roots: Vec<u32>,
    next_base_reg: u16,
    next_ext_reg: u16,
    max_interaction: usize,
    columns_per_interaction: Vec<u32>,
    n_base_params: u32,
    n_ext_params: u32,
}

impl RecordingState {
    fn new() -> Self {
        Self {
            base_insts: Vec::new(),
            ext_insts: Vec::new(),
            constraint_roots: Vec::new(),
            next_base_reg: 0,
            next_ext_reg: 0,
            max_interaction: 0,
            columns_per_interaction: Vec::new(),
            n_base_params: 0,
            n_ext_params: 0,
        }
    }

    fn alloc_base_reg(&mut self) -> u16 {
        let reg = self.next_base_reg;
        self.next_base_reg = reg.checked_add(1).expect("base register overflow");
        reg
    }

    fn alloc_ext_reg(&mut self) -> u16 {
        let reg = self.next_ext_reg;
        self.next_ext_reg = reg.checked_add(1).expect("ext register overflow");
        reg
    }

    fn tracker_next_column(&mut self, interaction: usize) -> u32 {
        if interaction >= self.columns_per_interaction.len() {
            self.columns_per_interaction.resize(interaction + 1, 0);
        }
        let col = self.columns_per_interaction[interaction];
        self.columns_per_interaction[interaction] = col + 1;
        col
    }

    /// Ensure there is a `Const(0)` base instruction and return its register.
    fn ensure_zero_const(&mut self) -> u16 {
        for inst in &self.base_insts {
            if inst.op == MetalEvaluationProgramBaseOpcodeV1::Const as u8 && inst.a == 0 {
                return inst.dst;
            }
        }
        let dst = self.alloc_base_reg();
        self.base_insts
            .push(MetalEvaluationProgramBaseInstV1::const_value(dst, 0));
        dst
    }

    /// Emit an ext `Const` instruction for a `SecureField` value and return
    /// the allocated ext register.
    fn emit_ext_const(&mut self, value: SecureField) -> u16 {
        let limbs = value.to_m31_array();
        let dst = self.alloc_ext_reg();
        self.ext_insts.push(MetalEvaluationProgramExtInstV1 {
            op: MetalEvaluationProgramExtOpcodeV1::Const as u8,
            reserved0: 0,
            dst,
            a: limbs[0].0,
            b: limbs[1].0,
            c: limbs[2].0,
            d: limbs[3].0,
        });
        dst
    }

    /// Promote a base register to an ext register using SecureCol with zero
    /// padding for the upper 3 limbs.
    fn promote_base_to_ext(&mut self, base_reg: u16) -> u16 {
        let zero_reg = self.ensure_zero_const();
        let ext_dst = self.alloc_ext_reg();
        self.ext_insts
            .push(MetalEvaluationProgramExtInstV1::secure_col(
                ext_dst,
                base_reg as u32,
                zero_reg as u32,
                zero_reg as u32,
                zero_reg as u32,
            ));
        ext_dst
    }

    /// Emit an ext binary instruction (Add, Sub, Mul).
    fn emit_ext_binary(
        &mut self,
        op: MetalEvaluationProgramExtOpcodeV1,
        src1: u16,
        src2: u16,
    ) -> u16 {
        let dst = self.alloc_ext_reg();
        self.ext_insts.push(MetalEvaluationProgramExtInstV1 {
            op: op as u8,
            reserved0: 0,
            dst,
            a: src1 as u32,
            b: src2 as u32,
            c: 0,
            d: 0,
        });
        dst
    }

    /// Emit an ext Neg instruction.
    fn emit_ext_neg(&mut self, src: u16) -> u16 {
        let dst = self.alloc_ext_reg();
        self.ext_insts.push(MetalEvaluationProgramExtInstV1 {
            op: MetalEvaluationProgramExtOpcodeV1::Neg as u8,
            reserved0: 0,
            dst,
            a: src as u32,
            b: 0,
            c: 0,
            d: 0,
        });
        dst
    }

    /// Number of interactions (1-indexed count).
    #[allow(dead_code)]
    pub fn n_interactions(&self) -> u32 {
        if self.columns_per_interaction.is_empty() && self.n_base_params == 0 {
            0
        } else {
            (self.max_interaction as u32) + 1
        }
    }

    #[allow(dead_code)]
    pub fn n_base_params(&self) -> u32 {
        self.n_base_params
    }

    #[allow(dead_code)]
    pub fn n_ext_params(&self) -> u32 {
        self.n_ext_params
    }

    pub fn max_base_regs(&self) -> u32 {
        self.next_base_reg as u32
    }

    pub fn max_ext_regs(&self) -> u32 {
        self.next_ext_reg as u32
    }
}

type SharedState = Rc<RefCell<RecordingState>>;

mod base;
use base::RecordedBaseValue;

// =========================================================================
// RecordedExtValue  (EvalAtRow::EF)
// =========================================================================

/// The kind of a symbolic extension-field value.
///
/// Values start as detached (Zero, LazyConst, PromotedBase) and become
/// "Realized" (owning an ext register in the shared recording state) when they
/// participate in arithmetic with another Realized value.
#[derive(Clone)]
enum RecordedExtValueKind {
    /// Has a register allocation in the shared recording state.
    Realized { reg: u16, state: SharedState },
    /// A base-field value promoted to the ext type.  Holds the base register
    /// index and shared state.  Will emit a `SecureCol` when realized.
    PromotedBase { base_reg: u16, state: SharedState },
    /// A lazy SecureField constant.  Will emit an ext `Const` when realized.
    LazyConst(SecureField),
    /// Detached zero — placeholder for `Zero::zero()` / `One::one()`.
    Zero,
}

/// Symbolic extension-field value.
#[derive(Clone)]
pub(crate) struct RecordedExtValue {
    kind: RecordedExtValueKind,
}

impl RecordedExtValue {
    /// Create a realized ext value with an already-allocated ext register.
    fn realized(reg: u16, state: &SharedState) -> Self {
        Self {
            kind: RecordedExtValueKind::Realized {
                reg,
                state: Rc::clone(state),
            },
        }
    }

    /// Create a detached zero placeholder.
    fn detached() -> Self {
        Self {
            kind: RecordedExtValueKind::Zero,
        }
    }

    /// Resolve this value to a (register, SharedState) pair, emitting any
    /// pending instructions into `target_state`.  If `self` already has state,
    /// its own state is used; otherwise `target_state` provides it.
    fn realize(&self, target_state: &SharedState) -> (u16, SharedState) {
        match &self.kind {
            RecordedExtValueKind::Realized { reg, state } => (*reg, Rc::clone(state)),
            RecordedExtValueKind::PromotedBase { base_reg, state } => {
                let mut st = state.borrow_mut();
                let reg = st.promote_base_to_ext(*base_reg);
                drop(st);
                (reg, Rc::clone(state))
            }
            RecordedExtValueKind::LazyConst(value) => {
                let mut st = target_state.borrow_mut();
                let reg = st.emit_ext_const(*value);
                drop(st);
                (reg, Rc::clone(target_state))
            }
            RecordedExtValueKind::Zero => {
                // Emit a const 0 ext value.
                let mut st = target_state.borrow_mut();
                let reg = st.emit_ext_const(SecureField::zero());
                drop(st);
                (reg, Rc::clone(target_state))
            }
        }
    }

    /// Get the shared state from this value, if it has one.
    fn state(&self) -> Option<&SharedState> {
        match &self.kind {
            RecordedExtValueKind::Realized { state, .. } => Some(state),
            RecordedExtValueKind::PromotedBase { state, .. } => Some(state),
            RecordedExtValueKind::LazyConst(_) => None,
            RecordedExtValueKind::Zero => None,
        }
    }

    /// Pick the "real" shared state from either `self` or `other`.
    /// Panics if neither has state.
    fn pick_state<'a>(&'a self, other: &'a Self) -> &'a SharedState {
        self.state()
            .or_else(|| other.state())
            .expect("at least one ext value must have recording state for arithmetic")
    }

    /// Emit a binary ext operation between `self` and `rhs`.
    fn emit_ext_binary_op(&self, op: MetalEvaluationProgramExtOpcodeV1, rhs: &Self) -> Self {
        let target_state = self.pick_state(rhs);
        let (lhs_reg, _) = self.realize(target_state);
        let (rhs_reg, state) = rhs.realize(target_state);
        let mut st = state.borrow_mut();
        let dst = st.emit_ext_binary(op, lhs_reg, rhs_reg);
        drop(st);
        RecordedExtValue::realized(dst, &state)
    }
}

impl fmt::Debug for RecordedExtValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            RecordedExtValueKind::Realized { reg, .. } => {
                write!(f, "RecordedExtValue(r{reg})")
            }
            RecordedExtValueKind::PromotedBase { base_reg, .. } => {
                write!(f, "RecordedExtValue(promoted_base r{base_reg})")
            }
            RecordedExtValueKind::LazyConst(v) => {
                write!(f, "RecordedExtValue(lazy_const {v:?})")
            }
            RecordedExtValueKind::Zero => {
                write!(f, "RecordedExtValue(zero)")
            }
        }
    }
}

// --- Ext arithmetic trait impls ---

impl Add for RecordedExtValue {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        // Optimization: adding zero is identity.
        if matches!(self.kind, RecordedExtValueKind::Zero) {
            return rhs;
        }
        if matches!(rhs.kind, RecordedExtValueKind::Zero) {
            return self;
        }
        self.emit_ext_binary_op(MetalEvaluationProgramExtOpcodeV1::Add, &rhs)
    }
}

impl Sub for RecordedExtValue {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        if matches!(rhs.kind, RecordedExtValueKind::Zero) {
            return self;
        }
        self.emit_ext_binary_op(MetalEvaluationProgramExtOpcodeV1::Sub, &rhs)
    }
}

impl Mul for RecordedExtValue {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        // Optimization: multiplying by one is identity.
        // (One::one() creates a Zero-kind, but real multiplications use
        // concrete values, so this optimization only helps detached ones.)
        self.emit_ext_binary_op(MetalEvaluationProgramExtOpcodeV1::Mul, &rhs)
    }
}

impl MulAssign for RecordedExtValue {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl Neg for RecordedExtValue {
    type Output = Self;
    fn neg(self) -> Self {
        match self.kind {
            RecordedExtValueKind::Zero => RecordedExtValue {
                kind: RecordedExtValueKind::Zero,
            },
            RecordedExtValueKind::LazyConst(v) => RecordedExtValue {
                kind: RecordedExtValueKind::LazyConst(-v),
            },
            _ => {
                let state = self.state().unwrap().clone();
                let (src_reg, state) = self.realize(&state);
                let mut st = state.borrow_mut();
                let dst = st.emit_ext_neg(src_reg);
                drop(st);
                RecordedExtValue::realized(dst, &state)
            }
        }
    }
}

impl AddAssign for RecordedExtValue {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl Add<BaseField> for RecordedExtValue {
    type Output = Self;
    fn add(self, rhs: BaseField) -> Self {
        // Emit a base const, promote it to ext, then add.
        let state = self
            .state()
            .expect("RecordedExtValue + BaseField: ext value must have recording state");
        let state = Rc::clone(state);
        let rhs_ext = {
            let mut st = state.borrow_mut();
            let base_dst = st.alloc_base_reg();
            st.base_insts
                .push(MetalEvaluationProgramBaseInstV1::const_value(
                    base_dst, rhs.0,
                ));

            st.promote_base_to_ext(base_dst)
        };
        let (self_reg, _) = self.realize(&state);
        let mut st = state.borrow_mut();
        let dst = st.emit_ext_binary(MetalEvaluationProgramExtOpcodeV1::Add, self_reg, rhs_ext);
        drop(st);
        RecordedExtValue::realized(dst, &state)
    }
}

impl Mul<BaseField> for RecordedExtValue {
    type Output = Self;
    fn mul(self, rhs: BaseField) -> Self {
        // Emit a base const, promote it to ext, then mul.
        let state = self
            .state()
            .expect("RecordedExtValue * BaseField: ext value must have recording state");
        let state = Rc::clone(state);
        let rhs_ext = {
            let mut st = state.borrow_mut();
            let base_dst = st.alloc_base_reg();
            st.base_insts
                .push(MetalEvaluationProgramBaseInstV1::const_value(
                    base_dst, rhs.0,
                ));

            st.promote_base_to_ext(base_dst)
        };
        let (self_reg, _) = self.realize(&state);
        let mut st = state.borrow_mut();
        let dst = st.emit_ext_binary(MetalEvaluationProgramExtOpcodeV1::Mul, self_reg, rhs_ext);
        drop(st);
        RecordedExtValue::realized(dst, &state)
    }
}

impl Add<SecureField> for RecordedExtValue {
    type Output = Self;
    fn add(self, rhs: SecureField) -> Self {
        let rhs_ext = RecordedExtValue {
            kind: RecordedExtValueKind::LazyConst(rhs),
        };
        self + rhs_ext
    }
}

impl Sub<SecureField> for RecordedExtValue {
    type Output = Self;
    fn sub(self, rhs: SecureField) -> Self {
        let rhs_ext = RecordedExtValue {
            kind: RecordedExtValueKind::LazyConst(rhs),
        };
        self - rhs_ext
    }
}

impl Mul<SecureField> for RecordedExtValue {
    type Output = Self;
    fn mul(self, rhs: SecureField) -> Self {
        let rhs_ext = RecordedExtValue {
            kind: RecordedExtValueKind::LazyConst(rhs),
        };
        self * rhs_ext
    }
}

impl Add<RecordedBaseValue> for RecordedExtValue {
    type Output = Self;
    fn add(self, mut rhs: RecordedBaseValue) -> Self {
        // Fold Zero/LazyConst + pending-base at record time.
        if rhs.is_pending() {
            match &self.kind {
                RecordedExtValueKind::Zero => {
                    let base_val = BaseField::from_u32_unchecked(rhs.pending_const.unwrap());
                    return RecordedExtValue {
                        kind: RecordedExtValueKind::LazyConst(SecureField::from(base_val)),
                    };
                }
                RecordedExtValueKind::LazyConst(ext_val) => {
                    let base_val = BaseField::from_u32_unchecked(rhs.pending_const.unwrap());
                    return RecordedExtValue {
                        kind: RecordedExtValueKind::LazyConst(
                            *ext_val + SecureField::from(base_val),
                        ),
                    };
                }
                _ => {
                    let target = self.state().cloned().unwrap_or_else(|| rhs.state.clone());
                    rhs.materialize_if_pending(&target);
                }
            }
        }
        let rhs_ext = RecordedExtValue {
            kind: RecordedExtValueKind::PromotedBase {
                base_reg: rhs.reg,
                state: rhs.state,
            },
        };
        self + rhs_ext
    }
}

impl Mul<RecordedBaseValue> for RecordedExtValue {
    type Output = Self;
    fn mul(self, mut rhs: RecordedBaseValue) -> Self {
        // Fold LazyConst × pending-base at record time to avoid creating a
        // detached-state ext value that would later cause cross-state
        // register references.
        if rhs.is_pending() {
            if let RecordedExtValueKind::LazyConst(ext_val) = &self.kind {
                let base_val = BaseField::from_u32_unchecked(rhs.pending_const.unwrap());
                return RecordedExtValue {
                    kind: RecordedExtValueKind::LazyConst(*ext_val * base_val),
                };
            }
            let target = self.state().cloned().unwrap_or_else(|| rhs.state.clone());
            rhs.materialize_if_pending(&target);
        }
        let rhs_ext = RecordedExtValue {
            kind: RecordedExtValueKind::PromotedBase {
                base_reg: rhs.reg,
                state: rhs.state,
            },
        };
        self * rhs_ext
    }
}

impl From<SecureField> for RecordedExtValue {
    fn from(value: SecureField) -> Self {
        RecordedExtValue {
            kind: RecordedExtValueKind::LazyConst(value),
        }
    }
}

impl From<RecordedBaseValue> for RecordedExtValue {
    fn from(v: RecordedBaseValue) -> Self {
        if v.is_pending() {
            // Convert pending base constant directly to a LazyConst ext
            // value to avoid creating a detached-state PromotedBase that
            // would cause cross-state register references.
            let base_val = BaseField::from_u32_unchecked(v.pending_const.unwrap());
            // Mark logup as finalized before dropping v (it carries a
            // detached LogupAtRow via its state, but we don't need it).
            return RecordedExtValue {
                kind: RecordedExtValueKind::LazyConst(SecureField::from(base_val)),
            };
        }
        RecordedExtValue {
            kind: RecordedExtValueKind::PromotedBase {
                base_reg: v.reg,
                state: v.state,
            },
        }
    }
}

impl Zero for RecordedExtValue {
    fn zero() -> Self {
        RecordedExtValue::detached()
    }
    fn is_zero(&self) -> bool {
        false
    }
}

impl One for RecordedExtValue {
    fn one() -> Self {
        RecordedExtValue {
            kind: RecordedExtValueKind::LazyConst(SecureField::one()),
        }
    }
}

// =========================================================================
// RecordingEvaluator  (implements EvalAtRow)
// =========================================================================

/// A recording evaluator that implements [`EvalAtRow`] by emitting V1 bytecode
/// into a shared [`RecordingState`].
pub(crate) struct RecordingEvaluator {
    state: SharedState,
    pub logup: LogupAtRow<Self>,
}

impl RecordingEvaluator {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(RecordingState::new())),
            logup: LogupAtRow::dummy(),
        }
    }

    /// Inject a base-parameter read.  Returns a symbolic value that maps to a
    /// `Param` instruction.  Must be called *before* passing this evaluator to
    /// `FrameworkEval::evaluate`.
    pub fn inject_base_param(&self, interaction: u8, slot: u32) -> RecordedBaseValue {
        let mut st = self.state.borrow_mut();
        let dst = st.alloc_base_reg();
        st.base_insts.push(MetalEvaluationProgramBaseInstV1 {
            op: MetalEvaluationProgramBaseOpcodeV1::Param as u8,
            interaction,
            dst,
            a: slot,
            b: 0,
            imm: 0,
        });
        st.n_base_params += 1;
        if interaction as usize > st.max_interaction {
            st.max_interaction = interaction as usize;
        }
        RecordedBaseValue::new(dst, &self.state)
    }

    /// Consume the evaluator and return the accumulated recording state.
    ///
    /// Panics if any symbolic values still hold references to the shared state.
    pub fn finish(self) -> RecordingState {
        // Explicitly drop logup first so its Rc references are released
        // before we try to unwrap.
        drop(self.logup);
        match Rc::try_unwrap(self.state) {
            Ok(cell) => cell.into_inner(),
            Err(_) => panic!("RecordingEvaluator::finish: dangling symbolic value references"),
        }
    }
}

impl EvalAtRow for RecordingEvaluator {
    type F = RecordedBaseValue;
    type EF = RecordedExtValue;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        // Allocate ONE column index for all offsets — each offset reads the
        // same column at a different row.  The previous implementation
        // incorrectly called tracker_next_column once per offset, inflating
        // the column count and producing out-of-range accesses.
        let col = {
            let mut st = self.state.borrow_mut();
            if interaction > st.max_interaction {
                st.max_interaction = interaction;
            }
            st.tracker_next_column(interaction)
        };
        std::array::from_fn(|i| {
            let mut st = self.state.borrow_mut();
            let dst = st.alloc_base_reg();
            st.base_insts
                .push(MetalEvaluationProgramBaseInstV1::trace_col(
                    dst,
                    interaction as u8,
                    col,
                    offsets[i] as i32,
                ));
            RecordedBaseValue::new(dst, &self.state)
        })
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>,
    {
        // Convert the constraint to an ext-field symbolic value.
        let ext_val: Self::EF = Self::EF::from(constraint);

        match &ext_val.kind {
            RecordedExtValueKind::Realized { reg, .. } => {
                // Already a native ext register — use it directly as a
                // constraint root.
                let mut st = self.state.borrow_mut();
                st.constraint_roots.push(*reg as u32);
            }
            RecordedExtValueKind::PromotedBase { base_reg, .. } => {
                // Base value promoted to ext — emit SecureCol to lift it to
                // a constraint root.
                let mut st = self.state.borrow_mut();
                let zero_reg = st.ensure_zero_const();
                let ext_dst = st.alloc_ext_reg();
                st.ext_insts
                    .push(MetalEvaluationProgramExtInstV1::secure_col(
                        ext_dst,
                        *base_reg as u32,
                        zero_reg as u32,
                        zero_reg as u32,
                        zero_reg as u32,
                    ));
                st.constraint_roots.push(ext_dst as u32);
            }
            RecordedExtValueKind::LazyConst(value) => {
                // A constant constraint — emit a Const ext instruction.
                let mut st = self.state.borrow_mut();
                let reg = st.emit_ext_const(*value);
                st.constraint_roots.push(reg as u32);
            }
            RecordedExtValueKind::Zero => {
                // Zero constraint — emit a zero ext constant.
                let mut st = self.state.borrow_mut();
                let reg = st.emit_ext_const(SecureField::zero());
                st.constraint_roots.push(reg as u32);
            }
        }
    }

    fn combine_ef(values: [Self::F; 4]) -> Self::EF {
        let state = &values[0].state;
        let mut st = state.borrow_mut();
        let ext_dst = st.alloc_ext_reg();
        st.ext_insts
            .push(MetalEvaluationProgramExtInstV1::secure_col(
                ext_dst,
                values[0].reg as u32,
                values[1].reg as u32,
                values[2].reg as u32,
                values[3].reg as u32,
            ));
        drop(st);
        RecordedExtValue::realized(ext_dst, state)
    }

    // --- Logup support (manual implementation of logup_proxy!()) ---

    fn write_logup_frac(&mut self, fraction: Fraction<Self::EF, Self::EF>) {
        if self.logup.fracs.is_empty() {
            self.logup.is_finalized = false;
        }
        self.logup.fracs.push(fraction.clone());
    }

    /// Mirrors the framework's `logup_proxy` semantics (consecutive chunks of
    /// `batch_size`); the macro itself is crate-private to the constraint framework.
    fn finalize_logup_batched(&mut self, batch_size: usize) {
        assert!(!self.logup.is_finalized, "LogupAtRow was already finalized");
        assert!(batch_size > 0, "Batch size must be positive");

        let mut batched: Vec<Fraction<Self::EF, Self::EF>> = self
            .logup
            .fracs
            .chunks(batch_size)
            .map(|chunk| chunk.iter().cloned().sum())
            .collect();

        let last_frac = batched.pop().expect("No fractions to finalize");

        let mut prev_col_cumsum = <Self::EF as Zero>::zero();

        // All batches except the last are cumulatively summed in new interaction columns.
        for cur_frac in batched {
            let [cur_cumsum] = self.next_extension_interaction_mask(self.logup.interaction, [0]);
            let diff = cur_cumsum.clone() - prev_col_cumsum.clone();
            prev_col_cumsum = cur_cumsum;
            self.add_constraint(diff * cur_frac.denominator - cur_frac.numerator);
        }

        let [prev_row_cumsum, cur_cumsum] =
            self.next_extension_interaction_mask(self.logup.interaction, [-1, 0]);

        let diff = cur_cumsum - prev_row_cumsum - prev_col_cumsum.clone();
        let shifted_diff = diff + self.logup.cumsum_shift;

        self.add_constraint(shifted_diff * last_frac.denominator - last_frac.numerator);

        self.logup.is_finalized = true;
    }

    fn finalize_logup(&mut self) {
        self.finalize_logup_batched(1)
    }

    fn finalize_logup_in_pairs(&mut self) {
        self.finalize_logup_batched(2)
    }
}

// The prototype's unit tests exercised the host-side interpreter, which this
// trimmed lane does not port; conformance is enforced end-to-end by the testkit
// (proof byte-equality on both channels, with the CPU lane as reference).
