//! Core interpreter implementation and components.

/// Extended bytecode functionality.
pub mod ext_bytecode;
mod input;
mod return_data;
mod runtime_flags;
mod shared_memory;
mod stack;

// re-exports
pub use ext_bytecode::ExtBytecode;
pub use input::InputsImpl;
pub use return_data::ReturnDataImpl;
pub use runtime_flags::RuntimeFlags;
pub use shared_memory::{num_words, resize_memory, SharedMemory};
pub use stack::{Stack, STACK_LIMIT};

// imports
use crate::{
    instruction_context::InstructionContext, interpreter_types::*, Gas, GasTable, Host,
    InstructionExecResult, InstructionResult, InstructionTable, InterpreterAction,
};
use bytecode::Bytecode;
use context_interface::{cfg::GasParams, host::LoadError};
use primitives::{hardfork::SpecId, hints_util::cold_path, Bytes};

/// Main interpreter structure that contains all components defined in [`InterpreterTypes`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Interpreter<WIRE: InterpreterTypes = EthInterpreter> {
    /// Bytecode being executed.
    pub bytecode: WIRE::Bytecode,
    /// Gas tracking for execution costs.
    pub gas: Gas,
    /// EVM stack for computation.
    pub stack: WIRE::Stack,
    /// Buffer for return data from calls.
    pub return_data: WIRE::ReturnData,
    /// EVM memory for data storage.
    pub memory: WIRE::Memory,
    /// Input data for current execution context.
    pub input: WIRE::Input,
    /// Runtime flags controlling execution behavior.
    pub runtime_flag: WIRE::RuntimeFlag,
    /// Extended functionality and customizations.
    pub extend: WIRE::Extend,
}

impl<EXT: Default> Interpreter<EthInterpreter<EXT>> {
    /// Create new interpreter
    pub fn new(
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
    ) -> Self {
        Self::new_inner(
            Stack::new(),
            memory,
            bytecode,
            input,
            is_static,
            spec_id,
            gas_limit,
        )
    }

    /// Create a new interpreter with default extended functionality.
    pub fn default_ext() -> Self {
        Self::do_default(Stack::new(), SharedMemory::new())
    }

    /// Create a new invalid interpreter.
    pub fn invalid() -> Self {
        Self::do_default(Stack::invalid(), SharedMemory::invalid())
    }

    fn do_default(stack: Stack, memory: SharedMemory) -> Self {
        Self::new_inner(
            stack,
            memory,
            ExtBytecode::default(),
            InputsImpl::default(),
            false,
            SpecId::default(),
            u64::MAX,
        )
    }

    fn new_inner(
        stack: Stack,
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
    ) -> Self {
        Self {
            bytecode,
            gas: Gas::new(gas_limit),
            stack,
            return_data: Default::default(),
            memory,
            input,
            runtime_flag: RuntimeFlags { is_static, spec_id },
            extend: Default::default(),
        }
    }

    /// Clears and reinitializes the interpreter with new parameters.
    #[expect(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn clear(
        &mut self,
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
        reservoir_remaining_gas: u64,
    ) {
        let Self {
            bytecode: bytecode_ref,
            gas,
            stack,
            return_data,
            memory: memory_ref,
            input: input_ref,
            runtime_flag,
            extend,
        } = self;
        *bytecode_ref = bytecode;
        *gas = Gas::new_with_regular_gas_and_reservoir(gas_limit, reservoir_remaining_gas);
        if stack.data().capacity() == 0 {
            *stack = Stack::new();
        } else {
            stack.clear();
        }
        return_data.0.clear();
        *memory_ref = memory;
        *input_ref = input;
        *runtime_flag = RuntimeFlags { spec_id, is_static };
        *extend = EXT::default();
    }

    /// Sets the bytecode that is going to be executed
    pub fn with_bytecode(mut self, bytecode: Bytecode) -> Self {
        self.bytecode = ExtBytecode::new(bytecode);
        self
    }
}

impl Default for Interpreter<EthInterpreter> {
    fn default() -> Self {
        Self::default_ext()
    }
}

/// Default types for Ethereum interpreter.
#[derive(Debug)]
pub struct EthInterpreter<EXT = (), MG = SharedMemory> {
    _phantom: core::marker::PhantomData<fn() -> (EXT, MG)>,
}

impl<EXT> InterpreterTypes for EthInterpreter<EXT> {
    type Stack = Stack;
    type Memory = SharedMemory;
    type Bytecode = ExtBytecode;
    type ReturnData = ReturnDataImpl;
    type Input = InputsImpl;
    type RuntimeFlag = RuntimeFlags;
    type Extend = EXT;
    type Output = InterpreterAction;
}

impl<IW: InterpreterTypes> Interpreter<IW> {
    /// Performs EVM memory resize.
    #[inline]
    pub fn resize_memory(
        &mut self,
        gas_params: &GasParams,
        offset: usize,
        len: usize,
    ) -> Result<(), InstructionResult> {
        resize_memory(&mut self.gas, &mut self.memory, gas_params, offset, len)
    }

    /// Takes the next action from the control and returns it.
    #[inline]
    pub fn take_next_action(&mut self) -> InterpreterAction {
        self.bytecode.reset_action();
        // Return next action if it is some.
        let action = core::mem::take(self.bytecode.action()).expect("Interpreter to set action");
        action
    }

    /// Halt the interpreter with the given result.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    #[cold]
    #[inline(never)]
    pub fn halt(&mut self, result: InstructionResult) {
        if result == InstructionResult::OutOfGas {
            self.gas.spend_all();
        }
        self.bytecode
            .set_action(InterpreterAction::new_halt(result, self.gas));
    }

    /// Halt the interpreter with the given result.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    #[cold]
    #[inline(never)]
    pub fn halt_fatal(&mut self) {
        self.bytecode.set_action(InterpreterAction::new_halt(
            InstructionResult::FatalExternalError,
            self.gas,
        ));
    }

    /// Halt the interpreter due to a [`LoadError`].
    #[cold]
    #[inline(never)]
    pub fn halt_load_error(&mut self, err: LoadError) {
        match err {
            LoadError::ColdLoadSkipped => self.halt_oog(),
            LoadError::DBError => self.halt_fatal(),
        }
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    pub fn halt_oog(&mut self) {
        self.gas.spend_all();
        self.halt(InstructionResult::OutOfGas);
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    pub fn halt_memory_oog(&mut self) {
        self.halt(InstructionResult::MemoryOOG);
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    pub fn halt_memory_limit_oog(&mut self) {
        self.halt(InstructionResult::MemoryLimitOOG);
    }

    /// Halt the interpreter with and overflow error.
    #[cold]
    #[inline(never)]
    pub fn halt_overflow(&mut self) {
        self.halt(InstructionResult::StackOverflow);
    }

    /// Halt the interpreter with and underflow error.
    #[cold]
    #[inline(never)]
    pub fn halt_underflow(&mut self) {
        self.halt(InstructionResult::StackUnderflow);
    }

    /// Halt the interpreter with and not activated error.
    #[cold]
    #[inline(never)]
    pub fn halt_not_activated(&mut self) {
        self.halt(InstructionResult::NotActivated);
    }

    /// Return with the given output.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    pub fn return_with_output(&mut self, output: Bytes) {
        self.bytecode.set_action(InterpreterAction::new_return(
            InstructionResult::Return,
            output,
            self.gas,
        ));
    }

    /// Executes the instruction at the current instruction pointer.
    ///
    /// Internally it will increment instruction pointer by one.
    #[inline]
    pub fn step<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        gas_table: &GasTable,
        host: &mut H,
    ) -> InstructionExecResult {
        // Get current opcode.
        let opcode = self.bytecode.opcode();

        // SAFETY: In analysis we are doing padding of bytecode so that we are sure that last
        // byte instruction is STOP so we are safe to just increment program_counter bcs on last instruction
        // it will do noop and just stop execution of this contract
        self.bytecode.relative_jump(1);

        let instruction = instruction_table[opcode as usize];
        let static_gas = unsafe { *gas_table.get_unchecked(opcode as usize) };

        if self.gas.record_cost_unsafe(static_gas as u64) {
            cold_path();
            return Err(InstructionResult::OutOfGas);
        }

        instruction.execute(InstructionContext {
            interpreter: self,
            host,
        })
    }

    /// Executes the interpreter until it returns or stops.
    #[inline]
    pub fn run_plain<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        gas_table: &GasTable,
        host: &mut H,
    ) -> InterpreterAction {
        let e = if hot_ops_are_mainnet(instruction_table) {
            if !self.stack.stwo_base().is_null() && !self.bytecode.stwo_ip().is_null() {
                self.run_hot_regs(instruction_table, gas_table, host)
            } else {
                self.run_hot_inline(instruction_table, gas_table, host)
            }
        } else {
            loop {
                if let Err(e) = self.step(instruction_table, gas_table, host) {
                    cold_path();
                    break e;
                }
            }
        };
        if self.bytecode.action().is_none() {
            self.halt(e);
        }
        debug_assert!(self.bytecode.is_end());
        self.take_next_action()
    }
}

/// stwo: the opcodes dispatched inline by [`Interpreter::run_hot_inline`],
/// with the function the mainnet instruction table holds for each. They are
/// the bulk of executed EVM operations; dispatching them through a `match`
/// lets each body inline into the loop instead of an indirect call per op.
macro_rules! hot_ops {
    ($m:ident) => {
        $m! {
            STOP => control::stop::<IW, H>,
            PUSH1 => stack::push::<1, IW, H>,
            PUSH2 => stack::push::<2, IW, H>,
            PUSH4 => stack::push::<4, IW, H>,
            PUSH20 => stack::push::<20, IW, H>,
            PUSH32 => stack::push::<32, IW, H>,
            PUSH0 => stack::push0::<IW, H>,
            JUMPDEST => control::jumpdest::<IW, H>,
            JUMPI => control::jumpi::<IW, H>,
            JUMP => control::jump::<IW, H>,
            POP => stack::pop::<IW, H>,
            SWAP1 => stack::swap::<1, IW, H>,
            SWAP2 => stack::swap::<2, IW, H>,
            SWAP3 => stack::swap::<3, IW, H>,
            SWAP4 => stack::swap::<4, IW, H>,
            SWAP5 => stack::swap::<5, IW, H>,
            DUP1 => stack::dup::<1, IW, H>,
            DUP2 => stack::dup::<2, IW, H>,
            DUP3 => stack::dup::<3, IW, H>,
            DUP4 => stack::dup::<4, IW, H>,
            DUP5 => stack::dup::<5, IW, H>,
            DUP6 => stack::dup::<6, IW, H>,
            DUP7 => stack::dup::<7, IW, H>,
            ADD => arithmetic::add::<IW, H>,
            SUB => arithmetic::sub::<IW, H>,
            AND => bitwise::bitand::<IW, H>,
            OR => bitwise::bitor::<IW, H>,
            NOT => bitwise::not::<IW, H>,
            ISZERO => bitwise::iszero::<IW, H>,
            EQ => bitwise::eq::<IW, H>,
            LT => bitwise::lt::<IW, H>,
            GT => bitwise::gt::<IW, H>,
            SHL => bitwise::shl::<IW, H>,
            SHR => bitwise::shr::<IW, H>,
            MLOAD => memory::mload::<IW, H>,
            MSTORE => memory::mstore::<IW, H>,
            CALLDATALOAD => system::calldataload::<IW, H>,
            SELFDESTRUCT => host::selfdestruct::<IW, H>,
            PUSH3 => stack::push::<3, IW, H>,
            DUP8 => stack::dup::<8, IW, H>,
            SWAP6 => stack::swap::<6, IW, H>,
            XOR => bitwise::bitxor::<IW, H>,
        }
    };
}

#[inline]
fn hot_ops_are_mainnet<IW: InterpreterTypes, H: Host + ?Sized>(table: &InstructionTable<IW, H>) -> bool {
    use crate::instructions::{arithmetic, bitwise, control, host, memory, stack, system};
    use bytecode::opcode::*;
    macro_rules! check {
        ($($op:ident => $f:expr,)*) => { true $(&& table[$op as usize].is($f))* };
    }
    hot_ops!(check)
}

impl<IW: InterpreterTypes> Interpreter<IW> {
    /// stwo: [`Interpreter::run_plain`]'s loop with the hot opcodes dispatched
    /// through a `match` to the same functions the (mainnet) table holds, so
    /// their bodies inline; the rest go through the table. Static gas is
    /// charged exactly as in [`Interpreter::step`].
    #[inline(never)]
    fn run_hot_inline<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        gas_table: &GasTable,
        host: &mut H,
    ) -> InstructionResult {
        use crate::instructions::{arithmetic, bitwise, control, host, memory, stack, system};
        use bytecode::opcode::*;
        loop {
            let opcode = self.bytecode.opcode();
            self.bytecode.relative_jump(1);
            let static_gas = unsafe { *gas_table.get_unchecked(opcode as usize) };
            if self.gas.record_cost_unsafe(static_gas as u64) {
                cold_path();
                return InstructionResult::OutOfGas;
            }
            let ctx = InstructionContext { interpreter: &mut *self, host: &mut *host };
            macro_rules! dispatch {
                ($($op:ident => $f:expr,)*) => {
                    match opcode {
                        $($op => ($f)(ctx),)*
                        _ => instruction_table[opcode as usize].execute(ctx),
                    }
                };
            }
            if let Err(e) = hot_ops!(dispatch) {
                cold_path();
                return e;
            }
        }
    }
}

impl<IW: InterpreterTypes> Interpreter<IW> {
    /// stwo: the hot-opcode loop with the instruction pointer, remaining gas
    /// and stack length held in locals. Stack, jump and arithmetic opcodes are
    /// executed here on the raw stack (each mirrors the table function it
    /// replaces, including its error codes); every other opcode syncs the
    /// locals back, runs its function (the inlined ones of
    /// `run_hot_inline` or the table entry) and reloads them. Static gas is
    /// charged exactly as `Gas::record_cost_unsafe` does.
    #[inline(never)]
    fn run_hot_regs<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        gas_table: &GasTable,
        host: &mut H,
    ) -> InstructionResult {
        use crate::instructions::{bitwise, control, host as host_ops, memory, stack, system};
        use bytecode::opcode::*;
        use primitives::U256;
        use crate::interpreter::STACK_LIMIT;

        let mut base: *mut U256 = self.stack.stwo_base();
        let mut ip: *const u8 = self.bytecode.stwo_ip();
        let mut gas: u64 = self.gas.remaining();
        let mut len: usize = self.stack.len();

        macro_rules! sync {
            () => {{
                self.bytecode.stwo_set_ip(ip);
                self.gas.set_remaining(gas);
                // SAFETY: `len` only moves over initialized slots below STACK_LIMIT
                unsafe { self.stack.stwo_set_len(len) };
            }};
        }
        macro_rules! reload {
            () => {{
                base = self.stack.stwo_base();
                ip = self.bytecode.stwo_ip();
                gas = self.gas.remaining();
                len = self.stack.len();
            }};
        }
        macro_rules! fail {
            ($e:expr) => {{
                cold_path();
                sync!();
                return $e;
            }};
        }
        // slot `i` from the top (0 = top)
        macro_rules! slot {
            ($i:expr) => {
                unsafe { &mut *base.add(len - 1 - $i) }
            };
        }
        macro_rules! push_n {
            ($n:literal) => {{
                if len == STACK_LIMIT {
                    fail!(InstructionResult::StackOverflow);
                }
                unsafe {
                    *base.add(len) = crate::be_word::load_u256_n::<$n>(ip);
                    ip = ip.add($n);
                }
                len += 1;
            }};
        }
        macro_rules! dup_n {
            ($n:literal) => {{
                if (len < $n) | (len + 1 > STACK_LIMIT) {
                    fail!(InstructionResult::StackOverflow);
                }
                unsafe { *base.add(len) = *base.add(len - $n) };
                len += 1;
            }};
        }
        macro_rules! swap_n {
            ($n:literal) => {{
                if $n >= len {
                    fail!(InstructionResult::StackUnderflow);
                }
                unsafe {
                    let a = base.add(len - 1);
                    let b = base.add(len - 1 - $n);
                    let t = *a;
                    *a = *b;
                    *b = t;
                }
            }};
        }
        // popn_top!([op1], op2): op2 = f(op1, op2)
        macro_rules! binop {
            (|$a:ident, $b:ident| $e:expr) => {{
                if len < 2 {
                    fail!(InstructionResult::StackUnderflow);
                }
                let $a = *slot!(0);
                let $b = *slot!(1);
                *slot!(1) = $e;
                len -= 1;
            }};
        }
        macro_rules! unop {
            (|$a:ident| $e:expr) => {{
                if len < 1 {
                    fail!(InstructionResult::StackUnderflow);
                }
                let $a = *slot!(0);
                *slot!(0) = $e;
            }};
        }
        macro_rules! jump_to {
            ($target:expr) => {{
                let target = usize::try_from($target).unwrap_or(usize::MAX);
                if !self.bytecode.is_valid_legacy_jump(target) {
                    fail!(InstructionResult::InvalidJump);
                }
                self.bytecode.absolute_jump(target);
                ip = self.bytecode.stwo_ip();
            }};
        }
        // any other opcode: run its function on synced state
        macro_rules! call {
            ($f:expr) => {{
                sync!();
                let r = ($f)(InstructionContext { interpreter: &mut *self, host: &mut *host });
                reload!();
                if let Err(e) = r {
                    cold_path();
                    return e;
                }
            }};
        }

        loop {
            // SAFETY: bytecode is padded so execution never runs past it
            let opcode = unsafe { *ip };
            ip = unsafe { ip.add(1) };
            let static_gas = unsafe { *gas_table.get_unchecked(opcode as usize) } as u64;
            if gas < static_gas {
                gas = gas.wrapping_sub(static_gas);
                fail!(InstructionResult::OutOfGas);
            }
            gas -= static_gas;
            match opcode {
                STOP => call!(control::stop::<IW, H>),
                PUSH1 => push_n!(1),
                PUSH2 => push_n!(2),
                PUSH3 => push_n!(3),
                PUSH4 => push_n!(4),
                PUSH20 => push_n!(20),
                PUSH32 => push_n!(32),
                JUMPDEST => {}
                POP => {
                    if len < 1 {
                        fail!(InstructionResult::StackUnderflow);
                    }
                    len -= 1;
                }
                JUMP => {
                    if len < 1 {
                        fail!(InstructionResult::StackUnderflow);
                    }
                    let target = *slot!(0);
                    len -= 1;
                    jump_to!(target);
                }
                JUMPI => {
                    if len < 2 {
                        fail!(InstructionResult::StackUnderflow);
                    }
                    let target = *slot!(0);
                    let cond = *slot!(1);
                    len -= 2;
                    if !cond.is_zero() {
                        jump_to!(target);
                    }
                }
                DUP1 => dup_n!(1),
                DUP2 => dup_n!(2),
                DUP3 => dup_n!(3),
                DUP4 => dup_n!(4),
                DUP5 => dup_n!(5),
                DUP6 => dup_n!(6),
                DUP7 => dup_n!(7),
                DUP8 => dup_n!(8),
                SWAP1 => swap_n!(1),
                SWAP2 => swap_n!(2),
                SWAP3 => swap_n!(3),
                SWAP4 => swap_n!(4),
                SWAP5 => swap_n!(5),
                SWAP6 => swap_n!(6),
                ADD => binop!(|a, b| a.wrapping_add(b)),
                SUB => binop!(|a, b| a.wrapping_sub(b)),
                AND => binop!(|a, b| a & b),
                OR => binop!(|a, b| a | b),
                XOR => binop!(|a, b| a ^ b),
                EQ => binop!(|a, b| U256::from(a == b)),
                LT => binop!(|a, b| U256::from(a < b)),
                GT => binop!(|a, b| U256::from(a > b)),
                NOT => unop!(|a| !a),
                ISZERO => unop!(|a| U256::from(a.is_zero())),
                PUSH0 => call!(stack::push0::<IW, H>),
                SHL => call!(bitwise::shl::<IW, H>),
                SHR => call!(bitwise::shr::<IW, H>),
                MLOAD => call!(memory::mload::<IW, H>),
                MSTORE => call!(memory::mstore::<IW, H>),
                CALLDATALOAD => call!(system::calldataload::<IW, H>),
                SELFDESTRUCT => call!(host_ops::selfdestruct::<IW, H>),
                _ => call!(|ctx| instruction_table[opcode as usize].execute(ctx)),
            }
        }
    }
}

/*
#[doc(hidden)]
#[unsafe(no_mangle)]
pub fn asm_run(
    interpreter: &mut Interpreter<EthInterpreter>,
    host: &mut context_interface::DummyHost,
) {
    let table = crate::instruction_table();
    let gas_table = crate::gas_table();
    interpreter.run_plain(&table, &gas_table, host);
}
*/

/// The result of an interpreter operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct InterpreterResult {
    /// The result of the instruction execution.
    pub result: InstructionResult,
    /// The output of the instruction execution.
    pub output: Bytes,
    /// The gas usage information.
    pub gas: Gas,
}

impl InterpreterResult {
    /// Returns a new `InterpreterResult` with the given values.
    pub const fn new(result: InstructionResult, output: Bytes, gas: Gas) -> Self {
        Self {
            result,
            output,
            gas,
        }
    }

    /// Returns a new `InterpreterResult` for an out-of-gas error with the given gas limit.
    pub fn new_oog(gas_limit: u64, reservoir: u64) -> Self {
        Self {
            result: InstructionResult::OutOfGas,
            output: Bytes::default(),
            gas: Gas::new_spent_with_reservoir(gas_limit, reservoir),
        }
    }

    /// Returns whether the instruction result is a success.
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Returns whether the instruction result is a revert.
    #[inline]
    pub const fn is_revert(&self) -> bool {
        self.result.is_revert()
    }

    /// Returns whether the instruction result is an error.
    #[deprecated(note = "use `is_halt` instead")]
    #[inline]
    pub const fn is_error(&self) -> bool {
        self.result.is_halt()
    }

    /// Returns whether the instruction result is a halt (error).
    #[inline]
    pub const fn is_halt(&self) -> bool {
        self.result.is_halt()
    }
}

// Special implementation for types where Output can be created from InterpreterAction
impl<IW: InterpreterTypes> Interpreter<IW>
where
    IW::Output: From<InterpreterAction>,
{
    /// Takes the next action from the control and returns it as the specific Output type.
    #[inline]
    pub fn take_next_action_as_output(&mut self) -> IW::Output {
        From::from(self.take_next_action())
    }

    /// Executes the interpreter until it returns or stops, returning the specific Output type.
    #[inline]
    pub fn run_plain_as_output<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        gas_table: &GasTable,
        host: &mut H,
    ) -> IW::Output {
        From::from(self.run_plain(instruction_table, gas_table, host))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_interpreter_serde() {
        use super::*;
        use bytecode::Bytecode;
        use primitives::Bytes;

        let bytecode = Bytecode::new_raw(Bytes::from(&[0x60, 0x00, 0x60, 0x00, 0x01][..]));
        let interpreter = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(bytecode),
            InputsImpl::default(),
            false,
            SpecId::default(),
            u64::MAX,
        );

        let serialized = serde_json::to_string_pretty(&interpreter).unwrap();
        let deserialized: Interpreter<EthInterpreter> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            interpreter.bytecode.pc(),
            deserialized.bytecode.pc(),
            "Program counter should be preserved"
        );
    }
}

#[test]
fn test_mstore_big_offset_memory_oog() {
    use super::*;
    use crate::{
        host::DummyHost,
        instructions::{gas_table, instruction_table},
    };
    use bytecode::Bytecode;
    use primitives::Bytes;

    let code = Bytes::from(
        &[
            0x60, 0x00, // PUSH1 0x00
            0x61, 0x27, 0x10, // PUSH2 0x2710  (10,000)
            0x52, // MSTORE
            0x00, // STOP
        ][..],
    );
    let bytecode = Bytecode::new_raw(code);

    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new(),
        ExtBytecode::new(bytecode),
        InputsImpl::default(),
        false,
        SpecId::default(),
        1000,
    );

    let table = instruction_table::<EthInterpreter, DummyHost>();
    let gas = gas_table();
    let mut host = DummyHost::default();
    let action = interpreter.run_plain(&table, &gas, &mut host);

    assert!(action.is_return());
    assert_eq!(
        action.instruction_result(),
        Some(InstructionResult::MemoryOOG)
    );
}

#[test]
#[cfg(feature = "memory_limit")]
fn test_mstore_big_offset_memory_limit_oog() {
    use super::*;
    use crate::{
        host::DummyHost,
        instructions::{gas_table, instruction_table},
    };
    use bytecode::Bytecode;
    use primitives::Bytes;

    let code = Bytes::from(
        &[
            0x60, 0x00, // PUSH1 0x00
            0x61, 0x27, 0x10, // PUSH2 0x2710  (10,000)
            0x52, // MSTORE
            0x00, // STOP
        ][..],
    );
    let bytecode = Bytecode::new_raw(code);

    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new_with_memory_limit(1000),
        ExtBytecode::new(bytecode),
        InputsImpl::default(),
        false,
        SpecId::default(),
        100000,
    );

    let table = instruction_table::<EthInterpreter, DummyHost>();
    let gas = gas_table();
    let mut host = DummyHost::default();
    let action = interpreter.run_plain(&table, &gas, &mut host);

    assert!(action.is_return());
    assert_eq!(
        action.instruction_result(),
        Some(InstructionResult::MemoryLimitOOG)
    );
}
