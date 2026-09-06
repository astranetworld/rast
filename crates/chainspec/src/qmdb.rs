//! Which state commitment a chain uses, and the genesis header that follows.
//!
//! gov5 declares the scheme in the chain config as `"stateScheme": "qmdb"`
//! (`params.ChainConfig.StateScheme`); a chain without the field is a
//! Merkle-Patricia chain. This reads the same field from the same place, so
//! one genesis file describes the chain to both clients.
//!
//! On a QMDB chain the genesis header's state root is the twig-forest root of
//! the alloc, not its Merkle-Patricia root — gov5 seeds the forest at init and
//! writes that root into the header (`internal/genesis_qmdb.go`). Two nodes
//! that disagree on the genesis state root disagree on the genesis hash and
//! never connect, so every path that builds a genesis header goes through
//! [`genesis_header`] here.

use alloy_consensus::Header;
use alloy_genesis::Genesis;
use alloy_primitives::B256;
use n42_qmdb_state::{changes_from_alloc, QmdbForest, StateError};
use reth_ethereum_forks::ChainHardforks;

/// The genesis config key gov5 reads the scheme from.
pub const STATE_SCHEME_KEY: &str = "stateScheme";

/// The value that selects QMDB.
pub const STATE_SCHEME_QMDB: &str = "qmdb";

/// How a chain commits to its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateScheme {
    /// Merkle-Patricia trie: Ethereum's, and what an unlabelled chain uses.
    Mpt,
    /// QMDB twig forest: the native chain's.
    Qmdb,
}

/// Reads the scheme a genesis declares.
///
/// Absent means MPT, matching gov5's default; a present value that is not
/// `"qmdb"` also means MPT, since gov5's other presets are all trie-shaped.
pub fn state_scheme(genesis: &Genesis) -> StateScheme {
    let declared: Option<String> = genesis
        .config
        .extra_fields
        .get_deserialized(STATE_SCHEME_KEY)
        .and_then(Result::ok);
    match declared.as_deref() {
        Some(STATE_SCHEME_QMDB) => StateScheme::Qmdb,
        _ => StateScheme::Mpt,
    }
}

/// Genesis `config` key that enables the 0x50 alternative-signature
/// transaction (`docs/spec/N42_TX_0x50.md`).
pub const ALT_SIG_TX_KEY: &str = "altSigTx";

/// Whether a genesis enables the 0x50 alternative-signature transaction.
/// Absent or anything but `true` means disabled: the type is rejected at
/// admission and in block validation.
pub fn alt_sig_tx_enabled(genesis: &Genesis) -> bool {
    genesis
        .config
        .extra_fields
        .get_deserialized::<bool>(ALT_SIG_TX_KEY)
        .and_then(Result::ok)
        .unwrap_or(false)
}

/// The QMDB root of a genesis allocation.
pub fn qmdb_genesis_root(genesis: &Genesis) -> Result<B256, StateError> {
    // The hash the forest is filed under does not affect the root; the real
    // genesis hash is not known until this root is in the header.
    let forest = QmdbForest::genesis(B256::ZERO, &changes_from_alloc(&genesis.alloc))?;
    Ok(forest.root())
}

/// The genesis header for `genesis` under the scheme it declares.
///
/// reth's header with, on a QMDB chain, the state root replaced by the forest
/// root of the alloc. Everything else — fork-dependent fields included — is
/// exactly what reth derives, which is also exactly what gov5's `ToBlock`
/// derives; the reproduction of gov5's `mainnet_qmdb` genesis hash in
/// `n42-qmdb-reth` is the test of that claim.
pub fn genesis_header(genesis: &Genesis, hardforks: &ChainHardforks) -> Header {
    let mut header = crate::make_genesis_header(genesis, hardforks);
    if state_scheme(genesis) == StateScheme::Qmdb {
        // The alloc is a fixed input; a root it cannot produce is a bug in the
        // conversion, and a genesis with a wrong root is a chain nobody else is
        // on. Neither is recoverable at runtime.
        header.state_root = qmdb_genesis_root(genesis)
            .expect("a genesis allocation always has a QMDB root");
    }
    header
}
