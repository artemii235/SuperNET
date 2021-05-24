extern crate bitcrypto as crypto;
extern crate primitives;
extern crate rustc_hex as hex;
extern crate serialization as ser;
#[macro_use] extern crate serialization_derive;
#[cfg(test)]
#[macro_use]
extern crate unwrap;

pub mod constants;

mod block;
mod block_header;
mod merkle_root;
mod transaction;

mod indexed_block;
mod indexed_header;
mod indexed_transaction;
/// `IndexedBlock` extension
mod read_and_hash;

pub trait RepresentH256 {
    fn h256(&self) -> hash::H256;
}

pub use primitives::{bigint, bytes, compact, hash};

pub use block::Block;
pub use block_header::BlockHeader;
pub use merkle_root::{merkle_node_hash, merkle_root};
pub use transaction::{JoinSplit, OutPoint, ShieldedOutput, ShieldedSpend, Transaction, TransactionInput,
                      TransactionOutput, TxHashAlgo};

pub use indexed_block::IndexedBlock;
pub use indexed_header::IndexedBlockHeader;
pub use indexed_transaction::IndexedTransaction;
pub use read_and_hash::{HashedData, ReadAndHash};

pub type ShortTransactionID = hash::H48;
