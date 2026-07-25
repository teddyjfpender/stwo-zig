use crate::model::{
    BlakeStatement, PoseidonStatement, XorStatement, BLAKE_ROUND_INPUT_FELTS,
    POSEIDON_LOG_INSTANCES_PER_ROW,
};
use anyhow::{anyhow, bail, Result};
use num_traits::{One, Zero};
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::FieldExpOps;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::prover::backend::ColumnOps;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

pub(crate) fn backend_eval<B: ColumnOps<M31>>(
    log_size: u32,
    values: Vec<M31>,
) -> CircleEvaluation<B, M31, BitReversedOrder> {
    CircleEvaluation::new(
        CanonicCoset::new(log_size).circle_domain(),
        values.into_iter().collect(),
    )
}

pub(crate) fn checked_pow2(log_size: u32) -> Result<usize> {
    if log_size >= usize::BITS {
        bail!("invalid log_size {log_size}");
    }
    Ok(1usize << log_size)
}

pub(crate) fn gen_is_first(log_size: u32) -> Result<Vec<M31>> {
    let n = checked_pow2(log_size)?;
    let mut values = vec![M31::zero(); n];
    values[0] = M31::one();
    Ok(values)
}

pub(crate) fn gen_wide_fibonacci_trace(
    log_n_rows: u32,
    sequence_len: u32,
) -> Result<Vec<Vec<M31>>> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid log_n_rows");
    }
    if sequence_len < 2 {
        bail!("invalid sequence_len");
    }

    let n = checked_pow2(log_n_rows)?;
    let n_cols = sequence_len as usize;
    let mut trace = vec![vec![M31::zero(); n]; n_cols];

    for row in 0..n {
        let bit_rev_index = bit_reverse_index(
            coset_index_to_circle_domain_index(row, log_n_rows),
            log_n_rows,
        );
        let mut a = M31::one();
        let mut b = M31::from(row as u32);
        trace[0][bit_rev_index] = a;
        trace[1][bit_rev_index] = b;
        for col in trace.iter_mut().skip(2) {
            let c = a.square() + b.square();
            col[bit_rev_index] = c;
            a = b;
            b = c;
        }
    }

    Ok(trace)
}

pub(crate) fn gen_is_step_with_offset(
    log_size: u32,
    log_step: u32,
    offset: usize,
) -> Result<Vec<M31>> {
    if log_step > log_size {
        bail!("invalid step");
    }
    let n = checked_pow2(log_size)?;
    let step = checked_pow2(log_step)?;

    let mut values = vec![M31::zero(); n];
    let mut i = offset % step;
    while i < n {
        let circle_domain_index = coset_index_to_circle_domain_index(i, log_size);
        let bit_rev_index = bit_reverse_index(circle_domain_index, log_size);
        values[bit_rev_index] = M31::one();
        i += step;
    }

    Ok(values)
}

pub(crate) fn gen_xor_lookup_trace(
    statement: XorStatement,
) -> Result<(Vec<Vec<M31>>, Vec<Vec<M31>>)> {
    if statement.log_size < 2 || statement.log_step > statement.log_size {
        bail!("invalid xor statement");
    }
    let n = checked_pow2(statement.log_size)?;
    let is_first = gen_is_first(statement.log_size)?;
    let is_step =
        gen_is_step_with_offset(statement.log_size, statement.log_step, statement.offset)?;
    let mut preprocessed = vec![vec![M31::zero(); n]; 7];
    preprocessed[0] = is_first;
    preprocessed[1] = is_step;

    for row in 0..n {
        let storage = xor_storage_index(row, statement.log_size);
        preprocessed[2][storage] = M31::from(((row >> 1) & 1) as u32);
    }
    for table_row in 0..4 {
        let storage = xor_storage_index(table_row, statement.log_size);
        let a = ((table_row >> 1) & 1) as u32;
        let b = (table_row & 1) as u32;
        preprocessed[3][storage] = M31::one();
        preprocessed[4][storage] = M31::from(a);
        preprocessed[5][storage] = M31::from(b);
        preprocessed[6][storage] = M31::from(a ^ b);
    }

    let mut main = vec![vec![M31::zero(); n]; 4];
    let mut counts = [0usize; 4];
    for storage in 0..n {
        let a = preprocessed[2][storage];
        let b = preprocessed[1][storage];
        let c = M31::from(a.0 ^ b.0);
        main[0][storage] = a;
        main[1][storage] = b;
        main[2][storage] = c;
        counts[((a.0 as usize) << 1) | b.0 as usize] += 1;
    }
    for (table_row, count) in counts.into_iter().enumerate() {
        main[3][xor_storage_index(table_row, statement.log_size)] = M31::from(count);
    }
    Ok((preprocessed, main))
}

pub(crate) fn xor_storage_index(row: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(row, log_size), log_size)
}

pub(crate) fn gen_plonk_trace(log_n_rows: u32) -> Result<([Vec<M31>; 4], [Vec<M31>; 4])> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid plonk log_n_rows");
    }
    let n = checked_pow2(log_n_rows)?;

    let mut preprocessed = std::array::from_fn(|_| vec![M31::zero(); n]);
    let mut main = std::array::from_fn(|_| vec![M31::zero(); n]);

    let mut fib = vec![M31::zero(); n + 2];
    fib[0] = M31::one();
    fib[1] = M31::one();
    for i in 2..fib.len() {
        fib[i] = fib[i - 1] + fib[i - 2];
    }

    for i in 0..n {
        preprocessed[0][i] = M31::from(i as u32);
        preprocessed[1][i] = M31::from((i + 1) as u32);
        preprocessed[2][i] = M31::from((i + 2) as u32);
        preprocessed[3][i] = M31::one();

        main[0][i] = M31::one();
        main[1][i] = fib[i];
        main[2][i] = fib[i + 1];
        main[3][i] = fib[i + 2];
    }

    if n >= 2 {
        main[0][n - 1] = M31::zero();
        main[0][n - 2] = M31::one();
    }

    Ok((preprocessed, main))
}

pub(crate) fn poseidon_log_n_rows(statement: PoseidonStatement) -> Result<u32> {
    if statement.log_n_instances < POSEIDON_LOG_INSTANCES_PER_ROW {
        bail!("invalid poseidon log_n_instances");
    }
    let log_n_rows = statement.log_n_instances - POSEIDON_LOG_INSTANCES_PER_ROW;
    if log_n_rows >= 31 {
        bail!("invalid poseidon log_n_rows");
    }
    Ok(log_n_rows)
}

pub(crate) fn blake_validate_statement(statement: BlakeStatement) -> Result<()> {
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid blake log_n_rows");
    }
    if statement.n_rounds == 0 {
        bail!("invalid blake n_rounds");
    }
    let _ = blake_n_columns(statement)?;
    Ok(())
}

pub(crate) fn blake_n_columns(statement: BlakeStatement) -> Result<usize> {
    (statement.n_rounds as usize)
        .checked_mul(BLAKE_ROUND_INPUT_FELTS)
        .ok_or_else(|| anyhow!("blake column count overflow"))
}

pub(crate) fn blake_next_seed(seed: u64) -> u64 {
    let mut x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

pub(crate) fn gen_blake_trace(statement: BlakeStatement) -> Result<Vec<Vec<M31>>> {
    blake_validate_statement(statement)?;
    let n = checked_pow2(statement.log_n_rows)?;
    let n_columns = blake_n_columns(statement)?;
    let mut trace = vec![vec![M31::zero(); n]; n_columns];

    for row in 0..n {
        let mut col_index = 0usize;
        let mut seed = row as u64 + 1;
        for round in 0..statement.n_rounds as usize {
            for cell in 0..BLAKE_ROUND_INPUT_FELTS {
                seed = blake_next_seed(seed);
                let mixed = seed
                    ^ ((round as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
                    ^ (((cell + 1) as u64).wrapping_mul(0x517c_c1b7_2722_0a95));
                trace[col_index][row] = M31::from((mixed % P as u64) as u32);
                col_index += 1;
            }
        }
        debug_assert_eq!(col_index, n_columns);
    }

    Ok(trace)
}
