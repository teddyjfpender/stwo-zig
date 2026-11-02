//! EEST blockchain fixtures -> canonical SSZ `StatelessInput` per block.
//!
//! For every test in one `blockchain_tests` fixture file this tool replays the
//! chain on reth (the pinned stateless workspace's reth, as in its `ef-tests`
//! crate), records each block's execution witness, and writes the schema-prefixed
//! SSZ input both of our guests read. The new-payload request comes from the
//! matching `blockchain_tests_engine` fixture (what a consensus client sends)
//! when one is given, otherwise it is rebuilt from the block and reth's
//! requests. One JSON line per block goes to stdout.
//!
//! Valid blocks get reth's minimal witness (canonical mode). Invalid blocks
//! (`expectException`) get a witness of the whole parent state, every code and
//! up to 256 ancestor headers, so a guest has everything it needs and must
//! reject on the block itself.
//!
//! The witness is untrusted input for the guests: it is bound to the parent
//! state root, so a wrong witness can only make a guest reject. The expected
//! output of a valid block (request root, success, chain id, schema id) is
//! computed here from the payload request alone; a guest reproduces it only if
//! it re-derives the fixture's block hash, state root, receipts and requests.

use alloy_consensus::Transaction as _;
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::{Decodable, Encodable};
use ef_tests::models::{Block as FixtureBlock, Header as FixtureHeader, State as FixtureState};
use reth_chainspec::ChainSpec;
use reth_consensus::{Consensus, HeaderValidator};
use reth_db_api::{
    cursor::DbCursorRO,
    tables,
    transaction::DbTx,
};
use reth_db_common::init::{insert_genesis_hashes, insert_genesis_history, insert_genesis_state};
use reth_ethereum_consensus::{EthBeaconConsensus, validate_block_post_execution};
use reth_ethereum_primitives::{Block, TransactionSigned};
use reth_evm::{ConfigureEvm, execute::Executor};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_provider::{
    BlockWriter, DatabaseProviderFactory, ExecutionOutcome, HeaderProvider, HistoryWriter,
    OriginalValuesKnown, StateWriteConfig, StateWriter, StaticFileProviderFactory,
    StaticFileSegment, StaticFileWriter,
    test_utils::create_test_provider_factory_with_chain_spec_and_db_args,
};
use reth_revm::{State, database::StateProviderDatabase, witness::ExecutionWitnessRecord};
use reth_trie::{
    HashedPostState, HashedStorage, KeccakKeyHasher, StateRoot,
    hashed_cursor::zero_destroyed_account_storage,
};
use reth_trie_common::ExecutionWitnessMode;
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, LegacyKeyAdapter,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stateless_validator_common::{
    HashTreeRoot, Sha2Hasher, SszEncode,
    guest::{
        StatelessInput, StatelessValidationResult,
        input::{ExecutionWitness, ProtocolFork, new_payload_request::*},
    },
};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

type Res<T> = Result<T, String>;

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * b.len());
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn unhex(v: &Value) -> Res<Vec<u8>> {
    let s = v.as_str().ok_or("expected hex string")?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn fixed<const N: usize>(v: &Value) -> Res<[u8; N]> {
    unhex(v)?.try_into().map_err(|b: Vec<u8>| format!("expected {N} bytes, got {}", b.len()))
}

fn qty(v: &Value) -> Res<U256> {
    let s = v.as_str().ok_or("expected quantity")?;
    U256::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).map_err(|e| e.to_string())
}

fn qty64(v: &Value) -> Res<u64> {
    let x = qty(v)?;
    u64::try_from(x).map_err(|_| format!("quantity does not fit u64: {x}"))
}

/// Fork schedule of one EEST network: (activation timestamp, fork), ascending.
fn schedule(network: &str) -> Option<Vec<(u64, ProtocolFork)>> {
    use ProtocolFork::*;
    Some(match network {
        "Prague" => vec![(0, Prague)],
        "Osaka" => vec![(0, Osaka)],
        "BPO1" => vec![(0, BPO1)],
        "BPO2" => vec![(0, BPO2)],
        "CancunToPragueAtTime15k" => vec![(0, Cancun), (15_000, Prague)],
        "PragueToOsakaAtTime15k" => vec![(0, Prague), (15_000, Osaka)],
        "OsakaToBPO1AtTime15k" => vec![(0, Osaka), (15_000, BPO1)],
        "BPO1ToBPO2AtTime15k" => vec![(0, BPO1), (15_000, BPO2)],
        _ => return None,
    })
}

fn fork_at(sched: &[(u64, ProtocolFork)], ts: u64) -> ProtocolFork {
    sched.iter().rev().find(|(t, _)| ts >= *t).map(|(_, f)| *f).unwrap_or(sched[0].1)
}

/// Same shape as the stateless guest's `to_reth_chain_config`, with the
/// network's activation times instead of "everything at genesis".
fn chain_spec(sched: &[(u64, ProtocolFork)]) -> Arc<ChainSpec> {
    use ProtocolFork::*;
    use alloy_eips::eip7840::BlobParams;
    let at = |target: ProtocolFork| -> Option<u64> {
        // A fork is active from the first schedule row at or after it.
        sched.iter().find(|(_, f)| *f >= target).map(|(t, _)| *t)
    };
    let mut blob = BTreeMap::new();
    blob.insert("cancun".to_string(), BlobParams::cancun());
    blob.insert("prague".to_string(), BlobParams::prague());
    blob.insert("osaka".to_string(), BlobParams::osaka());
    blob.insert("bpo1".to_string(), BlobParams::bpo1());
    blob.insert("bpo2".to_string(), BlobParams::bpo2());
    let config = alloy_genesis::ChainConfig {
        chain_id: 1,
        homestead_block: Some(0),
        dao_fork_block: Some(0),
        dao_fork_support: true,
        eip150_block: Some(0),
        eip155_block: Some(0),
        eip158_block: Some(0),
        byzantium_block: Some(0),
        constantinople_block: Some(0),
        petersburg_block: Some(0),
        istanbul_block: Some(0),
        muir_glacier_block: Some(0),
        berlin_block: Some(0),
        london_block: Some(0),
        arrow_glacier_block: Some(0),
        gray_glacier_block: Some(0),
        merge_netsplit_block: Some(0),
        shanghai_time: Some(0),
        cancun_time: Some(0),
        prague_time: at(Prague),
        osaka_time: at(Osaka),
        bpo1_time: at(BPO1),
        bpo2_time: at(BPO2),
        terminal_total_difficulty: Some(U256::ZERO),
        terminal_total_difficulty_passed: true,
        blob_schedule: blob,
        deposit_contract_address: Some(alloy_eips::eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS),
        ..Default::default()
    };
    Arc::new(ChainSpec::from(alloy_genesis::Genesis { config, ..Default::default() }))
}

/// EIP-7685 request list (type-prefixed byte strings) -> SSZ request lists.
fn requests_ssz(list: &[Vec<u8>]) -> Res<ExecutionRequestsElectraFulu> {
    let mut deposits = Vec::new();
    let mut withdrawals = Vec::new();
    let mut consolidations = Vec::new();
    let mut last: i32 = -1;
    for r in list {
        let (&ty, data) = r.split_first().ok_or("na:empty_request")?;
        if i32::from(ty) <= last {
            return Err("na:request_types_not_ascending".into());
        }
        last = i32::from(ty);
        if data.is_empty() {
            return Err("na:empty_request_data".into());
        }
        let size = match ty {
            0 => 192,
            1 => 76,
            2 => 116,
            _ => return Err(format!("na:unknown_request_type_{ty}")),
        };
        if data.len() % size != 0 {
            return Err("na:npr_partial_requests".into());
        }
        for c in data.chunks(size) {
            let u64le = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
            match ty {
                0 => deposits.push(DepositRequest {
                    pubkey: c[0..48].try_into().unwrap(),
                    withdrawal_credentials: c[48..80].try_into().unwrap(),
                    amount: u64le(&c[80..88]),
                    signature: c[88..184].try_into().unwrap(),
                    index: u64le(&c[184..192]),
                }),
                1 => withdrawals.push(WithdrawalRequest {
                    source_address: c[0..20].try_into().unwrap(),
                    validator_pubkey: c[20..68].try_into().unwrap(),
                    amount: u64le(&c[68..76]),
                }),
                _ => consolidations.push(ConsolidationRequest {
                    source_address: c[0..20].try_into().unwrap(),
                    source_pubkey: c[20..68].try_into().unwrap(),
                    target_pubkey: c[68..116].try_into().unwrap(),
                }),
            }
        }
    }
    Ok(ExecutionRequestsElectraFulu {
        deposits: deposits.into(),
        withdrawals: withdrawals.into(),
        consolidations: consolidations.into(),
    })
}

/// Engine API `engine_newPayloadV4` params -> SSZ request. Also returns the raw
/// transactions for public-key recovery.
fn request_from_engine(params: &Value) -> Res<(NewPayloadRequestElectraFulu, Vec<Vec<u8>>)> {
    let p = params.get(0).ok_or("engine params: no payload")?;
    let g = |k: &str| p.get(k).ok_or(format!("engine payload: missing {k}"));
    let txs: Vec<Vec<u8>> =
        g("transactions")?.as_array().ok_or("txs")?.iter().map(unhex).collect::<Res<_>>()?;
    let withdrawals = g("withdrawals")?
        .as_array()
        .ok_or("withdrawals")?
        .iter()
        .map(|w| {
            Ok(Withdrawal {
                index: qty64(&w["index"])?,
                validator_index: qty64(&w["validatorIndex"])?,
                address: fixed::<20>(&w["address"])?,
                amount: qty64(&w["amount"])?,
            })
        })
        .collect::<Res<Vec<_>>>()?;
    let extra = unhex(g("extraData")?)?;
    let payload = ExecutionPayloadV3 {
        parent_hash: fixed(g("parentHash")?)?,
        fee_recipient: fixed(g("feeRecipient")?)?,
        state_root: fixed(g("stateRoot")?)?,
        receipts_root: fixed(g("receiptsRoot")?)?,
        logs_bloom: fixed(g("logsBloom")?)?,
        prev_randao: fixed(g("prevRandao")?)?,
        block_number: qty64(g("blockNumber")?)?,
        gas_limit: qty64(g("gasLimit")?)?,
        gas_used: qty64(g("gasUsed")?)?,
        timestamp: qty64(g("timestamp")?)?,
        extra_data: extra.try_into().map_err(|_| "na:ssz_extra_data_too_long".to_string())?,
        base_fee_per_gas: qty(g("baseFeePerGas")?)?.to_le_bytes(),
        block_hash: fixed(g("blockHash")?)?,
        transactions: txs.iter().map(|t| t.clone().into()).collect::<Vec<_>>().into(),
        withdrawals: withdrawals.into(),
        blob_gas_used: qty64(g("blobGasUsed")?)?,
        excess_blob_gas: qty64(g("excessBlobGas")?)?,
    };
    let versioned_hashes = params
        .get(1)
        .and_then(Value::as_array)
        .ok_or("engine params: versioned hashes")?
        .iter()
        .map(fixed::<32>)
        .collect::<Res<Vec<_>>>()?;
    let pbr = fixed::<32>(params.get(2).ok_or("engine params: beacon root")?)?;
    let reqs = params
        .get(3)
        .and_then(Value::as_array)
        .ok_or("na:engine_payload_without_requests")?
        .iter()
        .map(unhex)
        .collect::<Res<Vec<_>>>()?;
    Ok((
        NewPayloadRequestElectraFulu {
            execution_payload: payload,
            versioned_hashes: versioned_hashes.into(),
            parent_beacon_block_root: pbr,
            execution_requests: requests_ssz(&reqs)?,
        },
        txs,
    ))
}

/// Rebuilds the request from a decoded block and its EIP-7685 requests.
fn request_from_block(
    block: &SealedBlock<Block>,
    requests: &[Vec<u8>],
) -> Res<(NewPayloadRequestElectraFulu, Vec<Vec<u8>>)> {
    let h = block.header();
    let txs: Vec<Vec<u8>> = block.body().transactions.iter().map(|t| t.encoded_2718()).collect();
    let mut versioned = Vec::new();
    for t in &block.body().transactions {
        if let Some(v) = t.blob_versioned_hashes() {
            versioned.extend(v.iter().map(|x| x.0));
        }
    }
    let payload = ExecutionPayloadV3 {
        parent_hash: h.parent_hash.0,
        fee_recipient: h.beneficiary.into_array(),
        state_root: h.state_root.0,
        receipts_root: h.receipts_root.0,
        logs_bloom: h.logs_bloom.0.0,
        prev_randao: h.mix_hash.0,
        block_number: h.number,
        gas_limit: h.gas_limit,
        gas_used: h.gas_used,
        timestamp: h.timestamp,
        extra_data: h
            .extra_data
            .to_vec()
            .try_into()
            .map_err(|_| "na:ssz_extra_data_too_long".to_string())?,
        base_fee_per_gas: U256::from(h.base_fee_per_gas.ok_or("na:no_base_fee")?).to_le_bytes(),
        block_hash: block.hash().0,
        transactions: txs.iter().map(|t| t.clone().into()).collect::<Vec<_>>().into(),
        withdrawals: block
            .body()
            .withdrawals
            .as_ref()
            .ok_or("na:no_withdrawals")?
            .iter()
            .map(|w| Withdrawal {
                index: w.index,
                validator_index: w.validator_index,
                address: w.address.into_array(),
                amount: w.amount,
            })
            .collect::<Vec<_>>()
            .into(),
        blob_gas_used: h.blob_gas_used.ok_or("na:no_blob_gas_used")?,
        excess_blob_gas: h.excess_blob_gas.ok_or("na:no_excess_blob_gas")?,
    };
    Ok((
        NewPayloadRequestElectraFulu {
            execution_payload: payload,
            versioned_hashes: versioned.into(),
            parent_beacon_block_root: h.parent_beacon_block_root.ok_or("na:no_beacon_root")?.0,
            execution_requests: requests_ssz(requests)?,
        },
        txs,
    ))
}

/// Uncompressed public keys of the payload's transactions. An undecodable or
/// unrecoverable transaction gets an all-zero key (the guest must reject).
fn public_keys(txs: &[Vec<u8>]) -> (Vec<[u8; 65]>, bool) {
    let mut synthetic = false;
    let keys = txs
        .iter()
        .map(|raw| {
            let key = TransactionSigned::decode_2718(&mut raw.as_slice()).ok().and_then(|tx| {
                tx.signature()
                    .recover_from_prehash(&tx.signature_hash())
                    .ok()
                    .and_then(|k| k.to_encoded_point(false).as_bytes().try_into().ok())
            });
            key.unwrap_or_else(|| {
                synthetic = true;
                [0u8; 65]
            })
        })
        .collect();
    (keys, synthetic)
}

fn witness_ssz(state: &[Vec<u8>], codes: &[Vec<u8>], headers: &[Vec<u8>]) -> Res<ExecutionWitness> {
    fn list<const N: usize>(v: &[Vec<u8>], what: &str) -> Res<Vec<stateless_validator_common::SszList<u8, N>>> {
        v.iter()
            .map(|b| b.clone().try_into().map_err(|_| format!("na:ssz_{what}_item_too_large")))
            .collect()
    }
    Ok(ExecutionWitness {
        state: list(state, "witness_node")?.into(),
        codes: list(codes, "code")?.into(),
        headers: list(headers, "header")?
            .try_into()
            .map_err(|_| "na:ssz_too_many_headers".to_string())?,
    })
}

struct Ctx {
    out: PathBuf,
    prefix: String,
    reference: bool,
    /// Also emit every valid block with a full parent-state witness (a control
    /// for the witness given to invalid blocks: guests must accept these).
    control: bool,
}

struct BlockRecord {
    rec: Value,
}

fn emit(ctx: &Ctx, rec: &mut Value, name: &str, fork: ProtocolFork, req: NewPayloadRequestElectraFulu, txs: &[Vec<u8>], w: Res<ExecutionWitness>, negative: bool) {
    let witness = match w {
        Ok(w) => w,
        Err(e) => {
            rec["status"] = json!("na");
            rec["reason"] = json!(e);
            return;
        }
    };
    let (keys, synthetic) = public_keys(txs);
    rec["synthetic_public_keys"] = json!(synthetic);
    rec["witness_counts"] = json!([witness.state.len(), witness.codes.len(), witness.headers.len()]);
    let request = NewPayloadRequest::ElectraFulu(req);
    let root = request.hash_tree_root(&Sha2Hasher);
    let input = StatelessInput { new_payload_request: request, witness, chain_id: 1, public_keys: keys.into() };
    let ssz = input.to_schema_prefixed_ssz(fork);
    let file = format!("{}{}.ssz", ctx.prefix, name);
    if let Err(e) = fs::write(ctx.out.join(&file), &ssz) {
        rec["status"] = json!("gen_fail");
        rec["reason"] = json!(format!("write: {e}"));
        return;
    }
    rec["status"] = json!("input");
    rec["input"] = json!(file);
    rec["input_bytes"] = json!(ssz.len());
    rec["input_sha256"] = json!(format!("{:x}", Sha256::digest(&ssz)));
    rec["request_root"] = json!(hexs(&root));
    rec["schema_id"] = json!(fork.schema_id());
    if !negative {
        let expected = StatelessValidationResult {
            new_payload_request_root: root,
            successful_validation: true,
            chain_id: 1,
            schema_id: fork.schema_id(),
        }
        .to_ssz();
        rec["expected_output"] = json!(hexs(&expected));
    }
    if ctx.reference {
        let out = stateless_validator_reth::guest::run_stateless_guest(&ssz);
        rec["reference_output"] = json!(hexs(&out));
    }
}

fn pre_execution_checks(spec: Arc<ChainSpec>, parent: &RecoveredBlock<Block>, block: &RecoveredBlock<Block>) -> Res<()> {
    let consensus: EthBeaconConsensus<ChainSpec> = EthBeaconConsensus::new(spec);
    let sh = block.sealed_header();
    <EthBeaconConsensus<ChainSpec> as Consensus<Block>>::validate_body_against_header(&consensus, block.body(), sh)
        .map_err(|e| format!("body: {e}"))?;
    consensus.validate_header_against_parent(sh, parent.sealed_header()).map_err(|e| format!("parent: {e}"))?;
    consensus.validate_header(sh).map_err(|e| format!("header: {e}"))?;
    consensus.validate_block_pre_execution(block).map_err(|e| format!("pre: {e}"))?;
    Ok(())
}

fn run_test(ctx: &Ctx, ti: usize, name: &str, t: &Value, engine: Option<&Value>) -> Vec<BlockRecord> {
    let mut out = Vec::new();
    let network = t["network"].as_str().unwrap_or("?").to_string();
    let blocks_v = t["blocks"].as_array().cloned().unwrap_or_default();
    let base = |i: usize, b: &Value| {
        json!({
            "test": name, "network": network, "block": i + 1,
            "negative": b.get("expectException").is_some(),
            "expect_exception": b.get("expectException").cloned().unwrap_or(Value::Null),
        })
    };
    let Some(sched) = schedule(&network) else {
        for (i, b) in blocks_v.iter().enumerate() {
            let mut r = base(i, b);
            r["status"] = json!("out_of_scope");
            r["reason"] = json!(format!("network {network}"));
            out.push(BlockRecord { rec: r });
        }
        return out;
    };
    let fail_all = |out: &mut Vec<BlockRecord>, from: usize, why: String| {
        for (i, b) in blocks_v.iter().enumerate().skip(from) {
            let mut r = base(i, b);
            r["status"] = json!("gen_fail");
            r["reason"] = json!(why.clone());
            out.push(BlockRecord { rec: r });
        }
    };
    let parse = || -> Res<(FixtureHeader, FixtureState, Vec<FixtureBlock>)> {
        Ok((
            serde_json::from_value(t["genesisBlockHeader"].clone()).map_err(|e| format!("genesis header: {e}"))?,
            serde_json::from_value(t["pre"].clone()).map_err(|e| format!("pre: {e}"))?,
            serde_json::from_value(t["blocks"].clone()).map_err(|e| format!("blocks: {e}"))?,
        ))
    };
    let (gh, pre, blocks) = match parse() {
        Ok(x) => x,
        Err(e) => {
            fail_all(&mut out, 0, format!("fixture parse: {e}"));
            return out;
        }
    };
    // Engine payloads by block hash.
    let mut engine_by_hash: BTreeMap<String, Value> = BTreeMap::new();
    let mut engine_seq: Vec<Value> = Vec::new();
    if let Some(e) = engine {
        for p in e["engineNewPayloads"].as_array().cloned().unwrap_or_default() {
            if let Some(h) = p["params"][0]["blockHash"].as_str() {
                engine_by_hash.insert(h.to_lowercase(), p.clone());
            }
            engine_seq.push(p);
        }
    }
    let spec = chain_spec(&sched);
    let factory = create_test_provider_factory_with_chain_spec_and_db_args(
        spec.clone(),
        // Throwaway per-test database: no fsync (the default durable mode makes
        // the run I/O-bound on many small commits).
        reth_db::mdbx::DatabaseArguments::test()
            .with_geometry_max_size(Some(1024 * 1024 * 1024))
            .with_sync_mode(Some(reth_db::mdbx::SyncMode::UtterlyNoSync)),
    );
    let provider = factory.database_provider_rw().unwrap();
    let genesis = match SealedBlock::<Block>::from_sealed_parts(gh.into(), Default::default()).try_recover() {
        Ok(g) => g,
        Err(e) => {
            fail_all(&mut out, 0, format!("genesis: {e}"));
            return out;
        }
    };
    let setup = || -> Res<()> {
        provider.insert_block(&genesis).map_err(|e| e.to_string())?;
        provider
            .static_file_provider()
            .latest_writer(StaticFileSegment::Receipts)
            .and_then(|mut w| w.increment_block(0))
            .map_err(|e| e.to_string())?;
        let gs = pre.clone().into_genesis_state();
        insert_genesis_state(&provider, gs.iter()).map_err(|e| e.to_string())?;
        insert_genesis_hashes(&provider, gs.iter()).map_err(|e| e.to_string())?;
        insert_genesis_history(&provider, gs.iter()).map_err(|e| e.to_string())?;
        // Make the genesis header readable before the first block commits.
        provider.static_file_provider().commit().map_err(|e| e.to_string())?;
        Ok(())
    };
    if let Err(e) = setup() {
        fail_all(&mut out, 0, format!("genesis setup: {e}"));
        return out;
    }
    let evm = EthEvmConfig::ethereum(spec.clone());
    let mut parent = genesis;
    for (i, fb) in blocks.iter().enumerate() {
        let mut rec = base(i, &blocks_v[i]);
        let negative = fb.expect_exception.is_some();
        let name_i = format!("{ti:04}-{:03}", i + 1);
        let decoded = SealedBlock::<Block>::decode(&mut fb.rlp.as_ref()).map_err(|e| e.to_string());
        let ts = match &decoded {
            Ok(b) => b.header().timestamp,
            Err(_) => blocks_v[i]["blockHeader"]["timestamp"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(parent.header().timestamp),
        };
        let fork = fork_at(&sched, ts);
        rec["fork"] = json!(format!("{fork:?}"));
        let in_scope = fork >= ProtocolFork::Prague;
        // Engine payload for this block: by hash, else by position.
        let eng = match &decoded {
            Ok(b) => engine_by_hash.get(&format!("{:#x}", b.hash())).cloned(),
            Err(_) => None,
        }
        .or_else(|| (engine_seq.len() == blocks.len()).then(|| engine_seq[i].clone()));

        if negative {
            // Reth's verdict, for information; the block is not applied.
            let verdict: Res<()> = (|| {
                let b = decoded.clone().map_err(|e| format!("rlp: {e}"))?;
                let rb = b.try_recover().map_err(|e| format!("senders: {e}"))?;
                pre_execution_checks(spec.clone(), &parent, &rb)?;
                let sp = provider.latest();
                let ex = evm.batch_executor(StateProviderDatabase(&sp));
                let o = ex.execute(&rb).map_err(|e| format!("exec: {e}"))?;
                validate_block_post_execution(&rb, &spec, &o.result, None, None).map_err(|e| format!("post: {e}"))?;
                let mut hs = HashedPostState::from_bundle_state::<KeccakKeyHasher>(o.state.state());
                zero_destroyed_account_storage(&DatabaseHashedCursorFactory::new(provider.tx_ref()), o.state.state(), &mut hs)
                    .map_err(|e| e.to_string())?;
                let (root, _) = <StateRoot<DatabaseTrieCursorFactory<_, LegacyKeyAdapter>, DatabaseHashedCursorFactory<_>> as DatabaseStateRoot<_>>::overlay_root_with_updates(provider.tx_ref(), &hs.clone_into_sorted()).map_err(|e| e.to_string())?;
                if root != rb.header().state_root {
                    return Err("state root mismatch".into());
                }
                Ok(())
            })();
            rec["reth"] = json!(match &verdict { Ok(()) => "accepted".to_string(), Err(e) => format!("rejected: {e}") });
            if !in_scope {
                rec["status"] = json!("out_of_scope");
                rec["reason"] = json!(format!("{fork:?} block"));
                out.push(BlockRecord { rec });
                continue;
            }
            let built = match (&eng, &decoded) {
                (Some(e), _) => request_from_engine(&e["params"]).map(|r| (r, "engine")),
                (None, Ok(b)) => request_from_block(b, &[]).map(|r| (r, "block_no_requests")),
                (None, Err(e)) => Err(format!("na:rlp_undecodable_no_engine_payload ({e})")),
            };
            match built {
                Err(e) => {
                    rec["status"] = json!("na");
                    rec["reason"] = json!(e);
                }
                Ok(((req, txs), src)) => {
                    rec["payload_source"] = json!(src);
                    let w = full_state_witness(&provider, i as u64 + 1, parent.header().number + 1);
                    rec["full_state_witness"] = json!(true);
                    emit(ctx, &mut rec, &name_i, fork, req, &txs, w, true);
                }
            }
            out.push(BlockRecord { rec });
            continue;
        }

        // Valid block: replay with witness recording, as ef-tests does.
        let control_witness = (ctx.control && in_scope)
            .then(|| full_state_witness(&provider, i as u64 + 1, parent.header().number + 1));
        let step = (|| -> Res<(RecoveredBlock<Block>, alloy_rpc_types_debug_like::Witness, Vec<Vec<u8>>)> {
            let b = decoded.clone().map_err(|e| format!("rlp: {e}"))?;
            let rb = b.try_recover().map_err(|e| format!("senders: {e}"))?;
            let number = rb.header().number;
            provider.insert_block(&rb).map_err(|e| e.to_string())?;
            provider.static_file_provider().commit().map_err(|e| e.to_string())?;
            pre_execution_checks(spec.clone(), &parent, &rb)?;
            let sp = provider.latest();
            let ex = evm.batch_executor(StateProviderDatabase(&sp));
            let mut wit = None;
            let o = ex
                .execute_with_state_closure_always(&rb, |db: &State<_>| {
                    wit = Some(ExecutionWitnessRecord::new(db).into_execution_witness(
                        &sp,
                        &provider,
                        number,
                        ExecutionWitnessMode::Canonical,
                    ));
                })
                .map_err(|e| format!("exec: {e}"))?;
            validate_block_post_execution(&rb, &spec, &o.result, None, None).map_err(|e| format!("post: {e}"))?;
            let w = wit.ok_or("no witness")?.map_err(|e| format!("witness: {e}"))?;
            let requests: Vec<Vec<u8>> = o.result.requests.iter().map(|r| r.to_vec()).collect();
            let mut hs = HashedPostState::from_bundle_state::<KeccakKeyHasher>(o.state.state());
            zero_destroyed_account_storage(&DatabaseHashedCursorFactory::new(provider.tx_ref()), o.state.state(), &mut hs)
                .map_err(|e| e.to_string())?;
            let (root, _) = <StateRoot<DatabaseTrieCursorFactory<_, LegacyKeyAdapter>, DatabaseHashedCursorFactory<_>> as DatabaseStateRoot<_>>::overlay_root_with_updates(provider.tx_ref(), &hs.clone_into_sorted()).map_err(|e| e.to_string())?;
            if root != rb.header().state_root {
                return Err("state root mismatch".into());
            }
            provider
                .write_state(&ExecutionOutcome::single(number, o), OriginalValuesKnown::Yes, StateWriteConfig::default())
                .map_err(|e| e.to_string())?;
            provider.write_hashed_state(&hs.into_sorted()).map_err(|e| e.to_string())?;
            provider.update_history_indices(number..=number).map_err(|e| e.to_string())?;
            let w = alloy_rpc_types_debug_like::Witness {
                state: w.state.iter().map(|b| b.to_vec()).collect(),
                codes: w.codes.iter().map(|b| b.to_vec()).collect(),
                headers: w.headers.iter().map(|b| b.to_vec()).collect(),
            };
            Ok((rb, w, requests))
        })();
        let (rb, w, requests) = match step {
            Ok(x) => x,
            Err(e) => {
                rec["status"] = json!("gen_fail");
                rec["reason"] = json!(format!("reth rejected a valid fixture block: {e}"));
                rec["reth"] = json!(format!("rejected: {e}"));
                // reth disagrees with the fixture, so it has no witness for this
                // block; the guests still get it with a full parent-state
                // witness and the engine payload (they must accept it).
                if let (Some(Ok(cw)), Some(eng)) = (control_witness, &eng) {
                    if let Ok((req, txs)) = request_from_engine(&eng["params"]) {
                        rec["payload_source"] = json!("engine");
                        rec["full_state_witness"] = json!(true);
                        rec["reth_disagrees_with_fixture"] = json!(true);
                        emit(ctx, &mut rec, &name_i, fork, req, &txs, Ok(cw), false);
                    }
                }
                out.push(BlockRecord { rec });
                fail_all(&mut out, i + 1, "earlier block failed".into());
                return out;
            }
        };
        rec["reth"] = json!("accepted");
        if !in_scope {
            rec["status"] = json!("out_of_scope");
            rec["reason"] = json!(format!("{fork:?} block"));
        } else {
            let sealed = rb.clone().into_sealed_block();
            let built = match &eng {
                Some(e) => request_from_engine(&e["params"]).map(|r| (r, "engine")),
                None => request_from_block(&sealed, &requests).map(|r| (r, "block")),
            };
            match built {
                Err(e) => {
                    rec["status"] = json!("na");
                    rec["reason"] = json!(e);
                }
                Ok(((req, txs), src)) => {
                    rec["payload_source"] = json!(src);
                    if req.execution_payload.block_hash != sealed.hash().0 {
                        rec["status"] = json!("gen_fail");
                        rec["reason"] = json!("engine payload hash differs from block");
                    } else {
                        if let Some(cw) = control_witness {
                            let mut c = rec.clone();
                            c["control"] = json!("full_state_witness");
                            c["full_state_witness"] = json!(true);
                            emit(ctx, &mut c, &format!("{name_i}-fw"), fork, req.clone(), &txs, cw, false);
                            out.push(BlockRecord { rec: c });
                        }
                        emit(ctx, &mut rec, &name_i, fork, req, &txs, witness_ssz(&w.state, &w.codes, &w.headers), false);
                    }
                }
            }
        }
        out.push(BlockRecord { rec });
        parent = rb;
    }
    out
}

mod alloy_rpc_types_debug_like {
    pub struct Witness {
        pub state: Vec<Vec<u8>>,
        pub codes: Vec<Vec<u8>>,
        pub headers: Vec<Vec<u8>>,
    }
}

/// Witness of the whole parent state: every account and storage trie node,
/// every code, and up to 256 ancestor headers.
fn full_state_witness<P>(provider: &P, _block_index: u64, number: u64) -> Res<ExecutionWitness>
where
    P: DbTxProvider + HeaderProvider,
    <P as HeaderProvider>::Header: Encodable,
{
    let tx = provider.tx();
    let mut target = HashedPostState::default();
    let mut ac = tx.cursor_read::<tables::HashedAccounts>().map_err(|e| e.to_string())?;
    for e in ac.walk(None).map_err(|e| e.to_string())? {
        let (k, a) = e.map_err(|e| e.to_string())?;
        target.accounts.insert(k, Some(a));
    }
    let mut sc = tx.cursor_dup_read::<tables::HashedStorages>().map_err(|e| e.to_string())?;
    for e in sc.walk(None).map_err(|e| e.to_string())? {
        let (addr, entry) = e.map_err(|e| e.to_string())?;
        target
            .storages
            .entry(addr)
            .or_insert_with(|| HashedStorage::new(false))
            .storage
            .insert(entry.key, entry.value);
    }
    let mut codes = Vec::new();
    let mut cc = tx.cursor_read::<tables::Bytecodes>().map_err(|e| e.to_string())?;
    for e in cc.walk(None).map_err(|e| e.to_string())? {
        let (_, code) = e.map_err(|e| e.to_string())?;
        let b = code.original_bytes();
        if !b.is_empty() {
            codes.push(b.to_vec());
        }
    }
    let state = provider.state_witness(target)?;
    let lo = number.saturating_sub(256);
    let headers: Vec<Vec<u8>> = provider
        .headers_range(lo..number)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|h| {
            let mut buf = Vec::new();
            h.encode(&mut buf);
            buf
        })
        .collect();
    witness_ssz(&state, &codes, &headers)
}

/// The two provider capabilities the full-state witness needs.
trait DbTxProvider {
    type Tx: DbTx;
    fn tx(&self) -> &Self::Tx;
    fn state_witness(&self, target: HashedPostState) -> Res<Vec<Vec<u8>>>;
}

impl<TX, N> DbTxProvider for reth_provider::DatabaseProvider<TX, N>
where
    TX: DbTx + 'static,
    N: reth_provider::providers::NodeTypesForProvider,
{
    type Tx = TX;
    fn tx(&self) -> &TX {
        self.tx_ref()
    }
    fn state_witness(&self, target: HashedPostState) -> Res<Vec<Vec<u8>>> {
        use reth_provider::StateProofProvider;
        let sp = reth_provider::LatestStateProviderRef::new(self);
        sp.witness(Default::default(), target, ExecutionWitnessMode::Canonical)
            .map(|v| v.into_iter().map(|b| b.to_vec()).collect())
            .map_err(|e| e.to_string())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut fixture = None;
    let mut engine = None;
    let mut out = None;
    let mut prefix = String::new();
    let mut reference = false;
    let mut control = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--fixture" => { fixture = Some(args[i + 1].clone()); i += 1; }
            "--engine" => { engine = Some(args[i + 1].clone()); i += 1; }
            "--out" => { out = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "--prefix" => { prefix = args[i + 1].clone(); i += 1; }
            "--reference" => reference = true,
            "--control" => control = true,
            a => { eprintln!("unknown argument {a}"); std::process::exit(2); }
        }
        i += 1;
    }
    let (Some(fixture), Some(out)) = (fixture, out) else {
        eprintln!("usage: stwo-eest-witness-gen --fixture BT.json [--engine BTE.json] --out DIR [--prefix P] [--reference] [--control]");
        std::process::exit(2);
    };
    fs::create_dir_all(&out).expect("out dir");
    let fx: serde_json::Map<String, Value> =
        serde_json::from_slice(&fs::read(&fixture).expect("read fixture")).expect("fixture json");
    let en: serde_json::Map<String, Value> = match &engine {
        Some(p) if std::path::Path::new(p).exists() => {
            serde_json::from_slice(&fs::read(p).expect("read engine fixture")).expect("engine json")
        }
        _ => Default::default(),
    };
    let ctx = Ctx { out, prefix, reference, control };
    for (ti, (name, t)) in fx.iter().enumerate() {
        // Engine counterpart: same id with the format name swapped.
        let ename = name.replacen("-blockchain_test", "-blockchain_test_engine", 1);
        let e = en.get(&ename);
        let recs = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_test(&ctx, ti, name, t, e)));
        match recs {
            Ok(recs) => {
                for r in recs {
                    let mut r = r.rec;
                    r["engine_fixture"] = json!(e.is_some());
                    println!("{r}");
                }
            }
            Err(_) => {
                println!("{}", json!({"test": name, "status": "gen_fail", "reason": "generator panic", "block": 0}));
            }
        }
    }
    let _ = (keccak256(b""), Address::ZERO, B256::ZERO);
}
