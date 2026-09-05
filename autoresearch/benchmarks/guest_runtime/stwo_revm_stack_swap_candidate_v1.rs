//! Non-production Revm 42 factory/handler contract for an authenticated U256 swap.
//!
//! Version custody is exact: this adapter targets bluealloy/revm git revision
//! `45f05bd88fd09e32ea43cf5e94190759ea6ace7c` (`revm` 42.0.1,
//! `revm-interpreter` 42.0.0). It is not installed by any production guest.
//! A registry-owned CUSTOM-0 word must be supplied as a const generic by a
//! distinct candidate guest build. The stateless guest does not own an EVM
//! after construction, so the only supported installation seam is
//! `EthEvmConfig::new_with_evm_factory`: this factory delegates to Alloy's
//! exact Ethereum factory, unwraps the returned EVM, patches its public Revm
//! instruction provider, and rewraps it without changing inspector behavior.

extern crate alloc;

use alloc::sync::Arc;
#[cfg(target_arch = "riscv32")]
use core::arch::asm;

use alloy_evm::{
    eth::{EthEvmContext, EthEvmFactory},
    precompiles::PrecompilesMap,
    revm::{
        context::{BlockEnv, DBErrorMarker, TxEnv},
        context_interface::result::{EVMError, HaltReason},
        inspector::{Inspector, NoOpInspector},
        primitives::hardfork::SpecId,
    },
    Database, EthEvm, EvmEnv, EvmFactory,
};
use reth_evm_ethereum::EthEvmConfig;

use revm::{
    bytecode::opcode::{
        SWAP1, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16, SWAP2, SWAP3, SWAP4, SWAP5,
        SWAP6, SWAP7, SWAP8, SWAP9,
    },
    handler::instructions::EthInstructions,
    interpreter::{
        interpreter::EthInterpreter, Host, Instruction, InstructionContext, InstructionExecResult,
        InstructionResult,
    },
};

pub const PRODUCTION_ACTIVATION: bool = false;
pub const REVM_GIT_REVISION: &str = "45f05bd88fd09e32ea43cf5e94190759ea6ace7c";
pub const REVM_VERSION: &str = "42.0.1";
pub const REVM_INTERPRETER_VERSION: &str = "42.0.0";
pub const ALLOY_EVM_VERSION: &str = "0.38.0";
pub const ALLOY_EVM_GIT_REVISION: &str = "065a125cde3a5c69990323aecab97ce4ed048237";
pub const RETH_GIT_REVISION: &str = "3d270d933daeeb90c5735d81ff7f80c00322d6de";

const CUSTOM_0_MAJOR_OPCODE: u32 = 0x0b;
const RD_X0: u32 = 0;
const RS1_A0: u32 = 10;
const RS2_A1: u32 = 11;
const STATIC_GAS: u16 = 3;

/// Additive EVM factory used only by a registry-bound candidate guest.
///
/// The current guest conversion must construct its config as
/// `EthEvmConfig::new_with_evm_factory(chain_spec, factory)`. Merely declaring
/// this type cannot alter the production instruction table.
#[derive(Debug, Clone, Copy, Default)]
pub struct StwoStackSwapEvmFactory<const FIXED_WORD: u32>;

impl<const FIXED_WORD: u32> StwoStackSwapEvmFactory<FIXED_WORD> {
    /// Exact replacement for the current `EthEvmConfig::new(chain_spec)` seam.
    ///
    /// # Safety
    ///
    /// `FIXED_WORD` and the candidate ELF must be bound to the same registry
    /// allocation validated by the prover. This constructor is intentionally
    /// absent from all production guest paths.
    pub unsafe fn new_candidate_config<C>(chain_spec: Arc<C>) -> EthEvmConfig<C, Self> {
        assert!(!PRODUCTION_ACTIVATION);
        assert!(valid_fixed_word(FIXED_WORD));
        EthEvmConfig::new_with_evm_factory(chain_spec, Self)
    }
}

impl<const FIXED_WORD: u32> EvmFactory for StwoStackSwapEvmFactory<FIXED_WORD> {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = EthEvm<DB, I, Self::Precompiles>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let evm = EthEvmFactory::default().create_evm(db, input);
        unsafe { install_into_evm::<FIXED_WORD, _, _>(evm, false) }
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let evm = EthEvmFactory::default().create_evm_with_inspector(db, input, inspector);
        unsafe { install_into_evm::<FIXED_WORD, _, _>(evm, true) }
    }
}

/// Preserve Alloy's context, precompiles, frame stack, and inspector; replace
/// only SWAP1..SWAP16 in the existing spec-configured instruction provider.
unsafe fn install_into_evm<const FIXED_WORD: u32, DB, I>(
    evm: EthEvm<DB, I, PrecompilesMap>,
    inspect: bool,
) -> EthEvm<DB, I, PrecompilesMap>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
{
    let mut inner = evm.into_inner();
    unsafe { install_candidate::<FIXED_WORD, EthEvmContext<DB>>(&mut inner.instruction) };
    EthEvm::new(inner, inspect)
}

/// Install only SWAP1..SWAP16 into an already spec-configured Revm 42 table.
///
/// # Safety
///
/// `FIXED_WORD` must have been allocated by the shared opcode registry and its
/// semantics must be the authenticated atomic swap of two disjoint 32-byte
/// spans addressed by a0/a1. The candidate ELF/program identity must bind the
/// same registry allocation consumed by the prover.
pub unsafe fn install_candidate<const FIXED_WORD: u32, H: Host>(
    instructions: &mut EthInstructions<EthInterpreter, H>,
) {
    assert!(!PRODUCTION_ACTIVATION);
    assert!(valid_fixed_word(FIXED_WORD));

    macro_rules! install {
        ($opcode:expr, $depth:literal) => {
            instructions.insert_instruction(
                $opcode,
                Instruction::new(swap::<$depth, FIXED_WORD, H>),
                STATIC_GAS,
            );
        };
    }

    install!(SWAP1, 1);
    install!(SWAP2, 2);
    install!(SWAP3, 3);
    install!(SWAP4, 4);
    install!(SWAP5, 5);
    install!(SWAP6, 6);
    install!(SWAP7, 7);
    install!(SWAP8, 8);
    install!(SWAP9, 9);
    install!(SWAP10, 10);
    install!(SWAP11, 11);
    install!(SWAP12, 12);
    install!(SWAP13, 13);
    install!(SWAP14, 14);
    install!(SWAP15, 15);
    install!(SWAP16, 16);
}

#[inline]
fn swap<const N: usize, const FIXED_WORD: u32, H: ?Sized>(
    context: InstructionContext<'_, H, EthInterpreter>,
) -> InstructionExecResult {
    assert!(N != 0);
    let data = context.interpreter.stack.data_mut();
    let len = data.len();
    if N >= len {
        return Err(InstructionResult::StackUnderflow);
    }

    // Revm owns the bounds check. Only explicit U256 pointers cross the ABI;
    // neither the Vec header nor the logical depth is trusted by the runner.
    unsafe {
        let top = data.as_mut_ptr().add(len - 1);
        let depth = top.sub(N);
        execute_authenticated::<FIXED_WORD>(top.cast(), depth.cast());
    }
    Ok(())
}

#[inline(always)]
unsafe fn execute_authenticated<const FIXED_WORD: u32>(lhs: *mut u8, rhs: *mut u8) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        asm!(
            ".word {instruction}",
            instruction = const FIXED_WORD,
            in("a0") lhs,
            in("a1") rhs,
            // Deliberately omit `nomem`: the opcode reads and writes both
            // pointed-to U256 values.
            options(nostack),
        );
    }

    #[cfg(not(target_arch = "riscv32"))]
    unsafe {
        // Host tests exercise Revm handler semantics only. This fallback is
        // never an authenticated opcode and cannot enable production.
        core::ptr::swap_nonoverlapping(lhs, rhs, 32);
    }
}

const fn valid_fixed_word(word: u32) -> bool {
    let funct7 = word >> 25;
    funct7 != 0
        && word & 0x7f == CUSTOM_0_MAJOR_OPCODE
        && (word >> 7) & 0x1f == RD_X0
        && (word >> 12) & 0x7 == 0
        && (word >> 15) & 0x1f == RS1_A0
        && (word >> 20) & 0x1f == RS2_A1
}

const _: () = assert!(!PRODUCTION_ACTIVATION);
