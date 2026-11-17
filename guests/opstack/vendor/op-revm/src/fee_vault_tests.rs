//! Regression: a pre-Isthmus transaction must not request the future fee vault.
use super::*;
use crate::{DefaultOp, OpBuilder, OpTransaction};
use revm::{
    context::{BlockEnv, CfgEnv, Context, TxEnv},
    handler::EthFrame,
    interpreter::{CallOutcome, Gas, InstructionResult, InterpreterResult},
    primitives::{B256, Bytes},
};

#[test]
fn operator_vault_activation_preserves_all_fee_credits() {
    for (spec, scalar, constant, expected) in [
        (OpSpecId::ECOTONE, 1_000_000u64, 3u64, None),
        (OpSpecId::ISTHMUS, 1_000_000, 3, Some(13u64)),
        (OpSpecId::ISTHMUS, 0, 0, Some(0)),
        (OpSpecId::JOVIAN, 1, 3, Some(1003)),
    ] {
        let ctx = Context::op()
            .with_cfg(CfgEnv::new_with_spec(spec))
            .with_block(BlockEnv {
                basefee: 2,
                ..Default::default()
            })
            .with_tx(
                OpTransaction::builder()
                    .base(TxEnv::builder().gas_price(2).gas_priority_fee(None))
                    .enveloped_tx(Some(Bytes::from_static(&[0x01])))
                    .source_hash(B256::ZERO)
                    .build_fill(),
            );
        let mut evm = ctx.build_op();
        evm.ctx().chain.tx_l1_cost = Some(U256::from(7));
        evm.ctx().chain.operator_fee_scalar = Some(U256::from(scalar));
        evm.ctx().chain.operator_fee_constant = Some(U256::from(constant));
        let handler =
            OpHandler::<_, EVMError<_, OpTransactionError>, EthFrame<EthInterpreter>>::new();
        let mut gas = Gas::new(100);
        gas.set_spent(10);
        let mut result = FrameResult::Call(CallOutcome::new(
            InterpreterResult {
                result: InstructionResult::Return,
                output: Bytes::new(),
                gas,
            },
            0..0,
        ));
        handler.reward_beneficiary(&mut evm, &mut result).unwrap();
        let state = &evm.ctx().journaled_state.state;
        assert_eq!(
            state.get(&L1_FEE_RECIPIENT).unwrap().info.balance,
            U256::from(7)
        );
        assert_eq!(
            state.get(&BASE_FEE_RECIPIENT).unwrap().info.balance,
            U256::from(20)
        );
        assert_eq!(
            state.get(&OPERATOR_FEE_RECIPIENT).map(|a| a.info.balance),
            expected.map(U256::from)
        );
    }
}
