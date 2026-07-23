use super::*;

fn slots() -> ExecutionTablesWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    ExecutionTablesWorkspaceSlots {
        raw_addr_to_id: id(),
        raw_f252_words: id(),
        raw_small_words: id(),
        big_limbs: (0..EXECUTION_TABLE_BIG_LIMBS).map(|_| id()).collect(),
        small_limbs: (0..EXECUTION_TABLE_SMALL_LIMBS).map(|_| id()).collect(),
        table_pointers: id(),
        table_strides: id(),
    }
}

#[test]
fn pure_requirements_are_exact_and_fail_closed() {
    let requirements = execution_tables_workspace_requirements(19, 17, 5).unwrap();
    assert_eq!(requirements.raw_addr_to_id_words, 19);
    assert_eq!(requirements.raw_f252_words, 17 * 8);
    assert_eq!(requirements.raw_small_words, 5 * 4);
    assert_eq!(requirements.big_column_words, 32);
    assert_eq!(requirements.small_column_words, 16);
    assert_eq!(requirements.table_pointer_words, 37 * POINTER_WORDS);
    assert_eq!(requirements.table_stride_words, 3);
    assert_eq!(
        requirements
            .arena_slot_requirements(&slots())
            .unwrap()
            .len(),
        3 + 28 + 8 + 2
    );

    let empty = execution_tables_workspace_requirements(0, 0, 0).unwrap();
    assert_eq!(empty.raw_addr_to_id_words, 1);
    assert_eq!(empty.raw_f252_words, 1);
    assert_eq!(empty.raw_small_words, 1);
    assert_eq!(empty.big_column_words, 16);
    assert_eq!(empty.small_column_words, 16);
    let mut duplicate = slots();
    duplicate.small_limbs[0] = duplicate.big_limbs[0];
    assert_eq!(
        requirements
            .arena_slot_requirements(&duplicate)
            .unwrap_err(),
        PreparedExecutionTablesError::DuplicateSlot(duplicate.big_limbs[0])
    );
    let mut short = slots();
    short.big_limbs.pop();
    assert_eq!(
        requirements.arena_slot_requirements(&short).unwrap_err(),
        PreparedExecutionTablesError::SlotShapeMismatch {
            role: "big_limbs",
            expected: 28,
            actual: 27,
        }
    );
}
