//! Symbolic base-field values for the official AIR recorder.

use super::*;

#[derive(Clone)]
pub(crate) struct RecordedBaseValue {
    pub(super) reg: u16,
    pub(super) state: SharedState,
    pub(super) pending_const: Option<u32>,
}

impl RecordedBaseValue {
    pub(super) fn new(reg: u16, state: &SharedState) -> Self {
        Self {
            reg,
            state: Rc::clone(state),
            pending_const: None,
        }
    }

    fn detached() -> Self {
        Self {
            reg: u16::MAX,
            state: Rc::new(RefCell::new(RecordingState::new())),
            pending_const: None,
        }
    }

    pub(super) fn materialize_if_pending(&mut self, target_state: &SharedState) {
        if let Some(value) = self.pending_const.take() {
            let mut state = target_state.borrow_mut();
            let destination = state.alloc_base_reg();
            state
                .base_insts
                .push(MetalEvaluationProgramBaseInstV1::const_value(
                    destination,
                    value,
                ));
            drop(state);
            self.reg = destination;
            self.state = Rc::clone(target_state);
        }
    }

    pub(super) fn is_pending(&self) -> bool {
        self.pending_const.is_some()
    }

    fn emit_binary(mut self, operation: MetalEvaluationProgramBaseOpcodeV1, mut rhs: Self) -> Self {
        if self.is_pending() && rhs.is_pending() {
            let lhs_value = self.pending_const.take().unwrap();
            let rhs_value = rhs.pending_const.take().unwrap();
            let result = match operation {
                MetalEvaluationProgramBaseOpcodeV1::Add => {
                    BaseField::from_u32_unchecked(lhs_value)
                        + BaseField::from_u32_unchecked(rhs_value)
                }
                MetalEvaluationProgramBaseOpcodeV1::Sub => {
                    BaseField::from_u32_unchecked(lhs_value)
                        - BaseField::from_u32_unchecked(rhs_value)
                }
                MetalEvaluationProgramBaseOpcodeV1::Mul => {
                    BaseField::from_u32_unchecked(lhs_value)
                        * BaseField::from_u32_unchecked(rhs_value)
                }
                _ => {
                    self.pending_const = Some(lhs_value);
                    rhs.pending_const = Some(rhs_value);
                    self.materialize_if_pending(&self.state.clone());
                    rhs.materialize_if_pending(&self.state);
                    let mut state = self.state.borrow_mut();
                    let destination = state.alloc_base_reg();
                    state
                        .base_insts
                        .push(MetalEvaluationProgramBaseInstV1::binary(
                            operation,
                            destination,
                            self.reg as u32,
                            rhs.reg as u32,
                        ));
                    drop(state);
                    return Self::new(destination, &self.state);
                }
            };
            return Self {
                reg: u16::MAX,
                state: self.state,
                pending_const: Some(result.0),
            };
        } else if self.is_pending() {
            self.materialize_if_pending(&rhs.state);
        } else if rhs.is_pending() {
            rhs.materialize_if_pending(&self.state);
        }

        let mut state = self.state.borrow_mut();
        let destination = state.alloc_base_reg();
        state
            .base_insts
            .push(MetalEvaluationProgramBaseInstV1::binary(
                operation,
                destination,
                self.reg as u32,
                rhs.reg as u32,
            ));
        drop(state);
        Self::new(destination, &self.state)
    }
}

impl fmt::Debug for RecordedBaseValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RecordedBaseValue(r{})", self.reg)
    }
}

impl Add for RecordedBaseValue {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.emit_binary(MetalEvaluationProgramBaseOpcodeV1::Add, rhs)
    }
}

impl Sub for RecordedBaseValue {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.emit_binary(MetalEvaluationProgramBaseOpcodeV1::Sub, rhs)
    }
}

impl Mul for RecordedBaseValue {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        self.emit_binary(MetalEvaluationProgramBaseOpcodeV1::Mul, rhs)
    }
}

impl MulAssign for RecordedBaseValue {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl Neg for RecordedBaseValue {
    type Output = Self;

    fn neg(mut self) -> Self {
        if self.is_pending() {
            let value = self.pending_const.take().unwrap();
            return Self {
                reg: u16::MAX,
                state: self.state,
                pending_const: Some((-BaseField::from_u32_unchecked(value)).0),
            };
        }
        let mut state = self.state.borrow_mut();
        let destination = state.alloc_base_reg();
        state.base_insts.push(MetalEvaluationProgramBaseInstV1 {
            op: MetalEvaluationProgramBaseOpcodeV1::Neg as u8,
            interaction: 0,
            dst: destination,
            a: self.reg as u32,
            b: 0,
            imm: 0,
        });
        drop(state);
        Self::new(destination, &self.state)
    }
}

impl AddAssign for RecordedBaseValue {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl AddAssign<BaseField> for RecordedBaseValue {
    fn add_assign(&mut self, rhs: BaseField) {
        let rhs_value = {
            let mut state = self.state.borrow_mut();
            let destination = state.alloc_base_reg();
            state
                .base_insts
                .push(MetalEvaluationProgramBaseInstV1::const_value(
                    destination,
                    rhs.0,
                ));
            Self::new(destination, &self.state)
        };
        *self = self.clone() + rhs_value;
    }
}

impl Mul<BaseField> for RecordedBaseValue {
    type Output = Self;

    fn mul(self, rhs: BaseField) -> Self {
        let rhs_value = {
            let mut state = self.state.borrow_mut();
            let destination = state.alloc_base_reg();
            state
                .base_insts
                .push(MetalEvaluationProgramBaseInstV1::const_value(
                    destination,
                    rhs.0,
                ));
            Self::new(destination, &self.state)
        };
        self * rhs_value
    }
}

impl Add<SecureField> for RecordedBaseValue {
    type Output = RecordedExtValue;

    fn add(mut self, rhs: SecureField) -> RecordedExtValue {
        if self.is_pending() {
            let state = self.state.clone();
            self.materialize_if_pending(&state);
        }
        let mut state = self.state.borrow_mut();
        let promoted = state.promote_base_to_ext(self.reg);
        let rhs_register = state.emit_ext_const(rhs);
        let destination = state.emit_ext_binary(
            MetalEvaluationProgramExtOpcodeV1::Add,
            promoted,
            rhs_register,
        );
        drop(state);
        RecordedExtValue::realized(destination, &self.state)
    }
}

impl Mul<SecureField> for RecordedBaseValue {
    type Output = RecordedExtValue;

    fn mul(mut self, rhs: SecureField) -> RecordedExtValue {
        if self.is_pending() {
            let state = self.state.clone();
            self.materialize_if_pending(&state);
        }
        let mut state = self.state.borrow_mut();
        let promoted = state.promote_base_to_ext(self.reg);
        let rhs_register = state.emit_ext_const(rhs);
        let destination = state.emit_ext_binary(
            MetalEvaluationProgramExtOpcodeV1::Mul,
            promoted,
            rhs_register,
        );
        drop(state);
        RecordedExtValue::realized(destination, &self.state)
    }
}

impl From<BaseField> for RecordedBaseValue {
    fn from(value: BaseField) -> Self {
        let mut result = Self::detached();
        result.pending_const = Some(value.0);
        result
    }
}

impl FieldExpOps for RecordedBaseValue {
    fn inverse(&self) -> Self {
        let source = if self.is_pending() {
            let mut clone = self.clone();
            let state = clone.state.clone();
            clone.materialize_if_pending(&state);
            clone
        } else {
            self.clone()
        };
        let mut state = source.state.borrow_mut();
        let destination = state.alloc_base_reg();
        state.base_insts.push(MetalEvaluationProgramBaseInstV1 {
            op: MetalEvaluationProgramBaseOpcodeV1::Inv as u8,
            interaction: 0,
            dst: destination,
            a: source.reg as u32,
            b: 0,
            imm: 0,
        });
        drop(state);
        Self::new(destination, &source.state)
    }
}

impl Zero for RecordedBaseValue {
    fn zero() -> Self {
        let mut result = Self::detached();
        result.pending_const = Some(0);
        result
    }

    fn is_zero(&self) -> bool {
        false
    }
}

impl One for RecordedBaseValue {
    fn one() -> Self {
        let mut result = Self::detached();
        result.pending_const = Some(1);
        result
    }
}
