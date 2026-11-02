use super::*;
use crate::{
    host::DummyHost,
    instructions::{Instruction, control, gas_table, instruction_table},
};
use bytecode::{Bytecode, opcode};
use primitives::{U256, hardfork::SpecId};

fn make(code: &[u8], height: usize, condition: u64, gas: u64) -> Interpreter {
    let mut i = Interpreter::new(
        SharedMemory::new(),
        ExtBytecode::new(Bytecode::new_legacy(Bytes::copy_from_slice(code))),
        InputsImpl::default(),
        false,
        SpecId::OSAKA,
        gas,
    );
    for _ in 0..height {
        assert!(i.stack.push(U256::from(condition)));
    }
    i
}
fn compare(code: &[u8], height: usize, condition: u64, gas: u64, custom: u8) {
    let mut fast = make(code, height, condition, gas);
    let mut reference = make(code, height, condition, gas);
    let mut table = instruction_table::<EthInterpreter, DummyHost>();
    let mut gas_table = gas_table();
    if custom == 1 {
        table[opcode::PUSH2 as usize] = Instruction::new(control::invalid);
    }
    if custom == 2 {
        table[opcode::JUMP as usize] = Instruction::new(control::invalid);
        table[opcode::JUMPI as usize] = Instruction::new(control::invalid);
    }
    if custom == 3 {
        gas_table[opcode::JUMP as usize] = 25;
        gas_table[opcode::JUMPI as usize] = 27;
    }
    let a = fast.run_plain(&table, &gas_table, &mut DummyHost::new(SpecId::OSAKA));
    let mut host = DummyHost::new(SpecId::OSAKA);
    let result = loop {
        if let Err(e) = reference.step(&table, &gas_table, &mut host) {
            break e;
        }
    };
    if reference.bytecode.action().is_none() {
        reference.halt(result);
    }
    let b = reference.take_next_action();
    assert_eq!(
        a, b,
        "code {code:?}, height {height}, cond {condition}, gas {gas}, custom {custom}"
    );
    assert_eq!(fast.stack, reference.stack);
    assert_eq!(fast.gas, reference.gas);
    assert_eq!(fast.bytecode.pc(), reference.bytecode.pc());
    assert_eq!(fast.memory, reference.memory);
}
#[test]
fn fused_jumps_match_single_steps_at_every_exception_boundary() {
    for next in [opcode::JUMP, opcode::JUMPI, opcode::ADD, opcode::STOP] {
        for target in [0u16, 4, 5, 6, 8191] {
            let code = [
                opcode::PUSH2,
                (target >> 8) as u8,
                target as u8,
                next,
                opcode::STOP,
                opcode::JUMPDEST,
                opcode::STOP,
            ];
            for height in [0, 1, 2, 1023, 1024] {
                for condition in [0, 1, u64::MAX] {
                    for gas in 0..=32 {
                        for custom in 0..=3 {
                            compare(&code, height, condition, gas, custom);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn truncated_pushes_and_step_api_remain_unfused() {
    for code in [
        &[opcode::PUSH2][..],
        &[opcode::PUSH2, 0][..],
        &[opcode::PUSH2, 0, 5][..],
    ] {
        for gas in 0..=16 {
            compare(code, 1, 1, gas, 0);
        }
    }
    let mut i = make(
        &[
            opcode::PUSH2,
            0,
            5,
            opcode::JUMP,
            opcode::STOP,
            opcode::JUMPDEST,
            opcode::STOP,
        ],
        0,
        0,
        100,
    );
    i.step(
        &instruction_table(),
        &gas_table(),
        &mut DummyHost::new(SpecId::OSAKA),
    )
    .unwrap();
    assert_eq!(i.stack.data(), &[U256::from(5)]);
    assert_eq!(i.bytecode.pc(), 3);
}
