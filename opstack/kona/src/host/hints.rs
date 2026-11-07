//! Native witness failure context. Hints remain read-only and fetch no data.
use alloy_primitives::{Address, B256, U256};
use core::{cell::Cell, convert::Infallible, fmt};
use kona_mpt::TrieHinter;
use op_alloy_rpc_types_engine::OpPayloadAttributes;

#[derive(Debug, Clone, Copy)]
pub enum Hint {
    Account(Address),
    Storage(Address, U256),
    Node(B256),
}
impl fmt::Display for Hint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Account(address) => write!(f, "account {address}"),
            Self::Storage(address, slot) => write!(f, "storage {address} slot {slot}"),
            Self::Node(hash) => write!(f, "trie node {hash}"),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Hints<'a>(pub &'a Cell<Option<Hint>>);
impl TrieHinter for Hints<'_> {
    type Error = Infallible;
    fn hint_trie_node(&self, hash: B256) -> Result<(), Self::Error> {
        self.0.set(Some(Hint::Node(hash)));
        Ok(())
    }
    fn hint_account_proof(&self, address: Address, _: B256) -> Result<(), Self::Error> {
        self.0.set(Some(Hint::Account(address)));
        Ok(())
    }
    fn hint_storage_proof(&self, address: Address, slot: U256, _: B256) -> Result<(), Self::Error> {
        self.0.set(Some(Hint::Storage(address, slot)));
        Ok(())
    }
    fn hint_execution_witness(&self, _: B256, _: &OpPayloadAttributes) -> Result<(), Self::Error> {
        Ok(())
    }
}
