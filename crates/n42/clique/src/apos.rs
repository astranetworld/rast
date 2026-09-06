use alloy_primitives::Sealable;
use alloy_primitives::{hex, Address, BlockHash, Bytes, FixedBytes, B256, B64, U256};
use bytes::BytesMut;
use n42_primitives::{APosConfig, Snapshot};
use rand::prelude::IndexedRandom;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::SealedHeader;
// reth-primitives (deleted in reth 2.4.1) supplied this default type argument.
type SealedBlock<B = n42_tx_types::Block> = reth_primitives_traits::SealedBlock<B>;
use reth_primitives_traits::AlloyBlockHeader;
use n42_clique_utils::{recover_address_generic, seal_hash, SIGNATURE_LENGTH};
use reth_primitives_traits::{Header, RecoveredBlock};
use reth_primitives_traits::{
    Block as BlockTrait, BlockHeader as BlockHeaderTrait, NodePrimitives,
};
use reth_provider::{BlockIdReader, BlockReaderIdExt, HeaderProvider};
use reth_revm::cached::CachedReads;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use k256::ecdsa::SigningKey;
use n42_consensus_traits::SignerManager;
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderConsensusError, HeaderValidator,
};
// SnapshotProviderWriter removed in reth v1.5.0
use std::str::FromStr;

//
const CHECKPOINT_INTERVAL: u64 = 2048; // Number of blocks after which to save the vote snapshot to the database
const INMEMORY_SNAPSHOTS: u32 = 128; // Number of recent vote snapshots to keep in memory
const INMEMORY_TDS: u32 = 1024; // Number of recent total difficulty records to keep in memory
const INMEMORY_CACHED_READS: u32 = 32; // Number of recent cached reads records to keep in memory

const WIGGLE_TIME: Duration = Duration::from_millis(500); // Random delay (per signer) to allow concurrent signers

// APos proof-of-authority protocol constants

/// Default number of blocks after which to checkpoint and reset the pending votes
pub const EPOCH_LENGTH: u64 = 30000;

/// Fixed number of extra-data prefix bytes reserved for signer vanity
pub const EXTRA_VANITY: usize = 32;
/// Fixed number of extra-data prefix bytes reserved for seal
pub const EXTRA_SEAL: usize = 65;

/// Magic nonce number to vote on adding a new signer
pub const NONCE_AUTH_VOTE: [u8; 8] = hex!("ffffffffffffffff");

/// Magic nonce number to vote on removing a signer
pub const NONCE_DROP_VOTE: [u8; 8] = hex!("0000000000000000");

// Difficulty constants
/// Block difficulty for in-turn signatures
pub const DIFF_IN_TURN: U256 = U256::from_limbs([2u64, 0, 0, 0]);
/// Block difficulty for out-of-turn signatures
pub const DIFF_NO_TURN: U256 = U256::from_limbs([1u64, 0, 0, 0]);
/// full immutability threshold
pub const FULL_IMMUTABILITY_THRESHOLD: usize = 90000;

/// apos error
#[derive(Debug, Clone)]
pub enum AposError {
    /// `UnknownBlock`,
    UnknownBlock,
    /// `InvalidCheckpointBeneficiary`,
    InvalidCheckpointBeneficiary,
    /// `InvalidVote`,
    InvalidVote,
    /// `InvalidCheckpointVote`,
    InvalidCheckpointVote,
    /// `MissingVanity`,
    MissingVanity,
    /// `MissingSignature`,
    MissingSignature,
    /// `ExtraSigners`,
    ExtraSigners,
    /// `InvalidCheckpointSigners`,
    InvalidCheckpointSigners,
    /// `MismatchingCheckpointSigners`,
    MismatchingCheckpointSigners,
    /// `InvalidMixDigest`,
    InvalidMixDigest,
    /// `InvalidUncleHash`,
    InvalidUncleHash,
    /// `InvalidDifficulty`,
    InvalidDifficulty,
    /// `WrongDifficulty`,
    WrongDifficulty,
    /// `InvalidTimestamp`,
    InvalidTimestamp,
    /// `InvalidVotingChain`,
    InvalidVotingChain,
    /// `UnauthorizedSigner`,
    UnauthorizedSigner,
    /// `RecentlySigned`,
    RecentlySigned,
    /// `NoTransactions`,
    NoTransactions,
}

impl std::fmt::Display for AposError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::UnknownBlock => "unknown block",
                Self::InvalidCheckpointBeneficiary => "beneficiary in checkpoint block non-zero",
                Self::InvalidVote => "vote nonce not 0x00..0 or 0xff..f",
                Self::InvalidCheckpointVote => "vote nonce in checkpoint block non-zero",
                Self::MissingVanity => "extra-data 32 byte vanity prefix missing",
                Self::MissingSignature => "extra-data 65 byte signature suffix missing",
                Self::ExtraSigners => "non-checkpoint block contains extra signer list",
                Self::InvalidCheckpointSigners => "invalid signer list on checkpoint block",
                Self::MismatchingCheckpointSigners => "mismatching signer list on checkpoint block",
                Self::InvalidMixDigest => "non-zero mix digest",
                Self::InvalidUncleHash => "non-empty uncle hash",
                Self::InvalidDifficulty => "invalid difficulty",
                Self::WrongDifficulty => "wrong difficulty",
                Self::InvalidTimestamp => "invalid timestamp",
                Self::InvalidVotingChain => "invalid voting chain",
                Self::UnauthorizedSigner => "unauthorized signer",
                Self::RecentlySigned => "recently signed",
                Self::NoTransactions => "sealing paused while waiting for transactions",
            }
        )
    }
}

impl Error for AposError {}

/// `APos` is the proof-of-authority consensus engine proposed to support the
/// Ethereum testnet following the Ropsten attacks.
pub struct APos<Provider, ChainSpec>
where
    Provider: HeaderProvider<Header = reth_primitives_traits::Header>
        + BlockIdReader
        + BlockReaderIdExt
        + Clone
        + Unpin
        + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks,
{
    config: APosConfig, // Consensus engine configuration parameters
    /// Chain spec
    chain_spec: Arc<ChainSpec>,
    recents: RwLock<schnellru::LruMap<B256, Snapshot>>, // Snapshots for recent block to speed up reorgs
    proposals: Arc<RwLock<HashMap<Address, bool>>>,     // Current list of proposals we are pushing
    signer: RwLock<Option<Address>>,                    // Ethereum address of the signing key
    eth_signer: RwLock<Option<LocalSigner<SigningKey>>>,
    //  Provider,
    provider: Provider,
    recent_headers: RwLock<schnellru::LruMap<B256, Provider::Header>>, // Recent headers for snapshot
    recent_tds: RwLock<schnellru::LruMap<B256, U256>>,
    recent_tds_inited: AtomicBool,
    recent_cached_reads: RwLock<schnellru::LruMap<B256, CachedReads>>,
}

// New creates a APos proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
impl<Provider, ChainSpec> APos<Provider, ChainSpec>
where
    Provider: HeaderProvider<Header = reth_primitives_traits::Header>
        + BlockIdReader
        + BlockReaderIdExt
        + Clone
        + Unpin
        + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks,
{
    /// new
    pub fn new(
        provider: Provider,
        chain_spec: Arc<ChainSpec>,
        signer_private_key: Option<String>,
    ) -> Self {
        let recents = RwLock::new(schnellru::LruMap::new(schnellru::ByLength::new(
            INMEMORY_SNAPSHOTS,
        )));
        let recent_headers = RwLock::new(schnellru::LruMap::new(schnellru::ByLength::new(
            CHECKPOINT_INTERVAL as u32 * 2,
        )));
        let recent_tds = RwLock::new(schnellru::LruMap::new(schnellru::ByLength::new(
            INMEMORY_TDS,
        )));
        let recent_tds_inited = AtomicBool::new(false);
        let recent_cached_reads = RwLock::new(schnellru::LruMap::new(schnellru::ByLength::new(
            INMEMORY_CACHED_READS,
        )));

        let eth_signer: Option<PrivateKeySigner> = signer_private_key.and_then(|key| {
            match key.parse() {
                Ok(signer) => Some(signer),
                Err(e) => {
                    error!(target: "consensus::apos", "Failed to parse signer private key: {:?}", e);
                    None
                }
            }
        });

        let eth_signer_address = eth_signer.clone().map(|signer| signer.address());
        info!(target: "consensus::apos", "apos set signer address {:?}", eth_signer_address);

        let mut config = APosConfig::default();
        if let Some(clique) = chain_spec.genesis().config.clique {
            if let Some(period) = clique.period {
                config.period = period;
            }
            if let Some(epoch) = clique.epoch {
                config.epoch = epoch;
            }
        }

        Self {
            config,
            chain_spec,
            recents,
            recent_headers,
            recent_tds,
            recent_tds_inited,
            recent_cached_reads,
            proposals: Arc::new(RwLock::new(HashMap::new())),
            signer: RwLock::new(eth_signer_address),
            eth_signer: RwLock::new(eth_signer),
            provider,
        }
    }

    fn set_signer(&self, eth_signer: Option<LocalSigner<SigningKey>>) {
        let eth_signer_address = eth_signer.clone().map(|signer| signer.address());
        info!(target: "consensus::apos", "set_signer, new signer={:?}", eth_signer_address);
        match (self.signer.write(), self.eth_signer.write()) {
            (Ok(mut signer_guard), Ok(mut eth_signer_guard)) => {
                *signer_guard = eth_signer_address;
                *eth_signer_guard = eth_signer;
            }
            (Err(e), _) => {
                error!(target: "consensus::apos", "signer lock poisoned: {}", e);
            }
            (_, Err(e)) => {
                error!(target: "consensus::apos", "eth_signer lock poisoned: {}", e);
            }
        }
    }

    /// verifySeal checks whether the signature contained in the header satisfies the
    /// consensus protocol requirements. The method accepts an optional list of parent
    /// headers that aren't yet part of the local blockchain to generate the snapshots
    /// from.
    pub fn verify_seal<H>(
        &self,
        snap: &Snapshot,
        header: &H,
        _parents: Option<Vec<H>>,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        H: BlockHeaderTrait,
    {
        // Verifying the genesis block is not supported
        if header.number() == 0 {
            return Err(AposError::UnknownBlock.into());
        }
        debug!(target: "consensus::apos", "verify_seal() header number: {}", header.number());

        //Analyze the signer and check if they are in the signer list
        let signer = recover_address_generic(header)?;
        if !snap.signers.contains(&signer) {
            info!(target: "consensus::apos", "err signer not in list: {}", signer);
            return Err(AposError::UnauthorizedSigner.into());
        }
        debug!(target: "consensus::apos", "recovered address: {}", signer);

        // TODO: SnapshotProvider removed in reth v1.5.0 - need to implement alternative storage
        // #[cfg(debug_assertions)]
        // {
        //     self.provider.save_signer_by_hash(&header.hash_slow(), signer).map_err(|_| ConsensusError::UnknownBlock)?;
        // }

        //Check the list of recent signatories
        for (seen, recent) in &snap.recents {
            if *recent == signer {
                //If the signer is in the recent list, ensure that the current block can be removed
                let limit = (snap.signers.len() as u64 / 2) + 1;
                if header.number() < limit || *seen > header.number() - limit {
                    return Err(AposError::RecentlySigned.into());
                }
            }
        }

        //Ensure that the difficulty corresponds to the signer's round
        let in_turn = snap.inturn(header.number(), &signer);
        if in_turn && header.difficulty() != DIFF_IN_TURN {
            return Err(AposError::WrongDifficulty.into());
        }
        if !in_turn && header.difficulty() == DIFF_IN_TURN {
            return Err(AposError::WrongDifficulty.into());
        }

        Ok(())
    }

    /// `SealHash` returns the hash of a block prior to it being sealed.
    pub fn seal_hash(&self, header: &Header) -> B256 {
        seal_hash(header)
    }

    /// Close implements consensus.Engine. It's a noop for Apoa as there are no background threads.
    pub const fn close(&self) -> Result<(), ConsensusError> {
        Ok(())
    }

    // APIs implements consensus.Engine, returning the user facing RPC API to allow
    // controlling the signer voting.

    fn init_recent_tds(&self) {
        if self.recent_tds_inited.load(Ordering::Relaxed) {
            return;
        }
        let finalized_block_number = self
            .provider
            .finalized_block_number()
            .unwrap_or(Some(0))
            .unwrap_or(0);
        info!(target: "consensus::apos", ?finalized_block_number, "init_recent_tds");
        let best_block_number = match self.provider.best_block_number() {
            Ok(n) => n,
            Err(e) => {
                warn!(target: "consensus::apos", ?e, "failed to get best_block_number in init_recent_tds");
                return;
            }
        };
        info!(target: "consensus::apos", ?best_block_number, "init_recent_tds");
        let num_blocks = best_block_number - finalized_block_number + 1;
        let start_block_number = if num_blocks > INMEMORY_TDS.into() {
            warn!(target: "consensus::apos", ?finalized_block_number, ?best_block_number, td_cache_size=?INMEMORY_TDS,
                "the number of blocks from finalized block to best block is larger than td cache size, this may cause 'td not found' errors later",
            );
            best_block_number.saturating_sub(INMEMORY_TDS.saturating_sub(1) as u64)
        } else {
            finalized_block_number
        };
        for block_number in start_block_number..=best_block_number {
            debug!(target: "consensus::apos", ?block_number, "init_recent_tds");
            let header = match self.provider.header_by_number(block_number) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    warn!(target: "consensus::apos", ?block_number, "header not found during init_recent_tds");
                    continue;
                }
                Err(e) => {
                    warn!(target: "consensus::apos", ?block_number, ?e, "failed to get header during init_recent_tds");
                    continue;
                }
            };
            if block_number == start_block_number {
                // TD is no longer tracked in the database (removed in reth v1.11.0 for PoS).
                // For PoA (N42), we seed the starting TD as U256::ZERO and accumulate from there.
                let start_td = U256::ZERO;
                if let Ok(mut recent_tds) = self.recent_tds.write() {
                    recent_tds.insert(header.hash_slow(), start_td);
                }
            } else if let Ok(mut recent_tds) = self.recent_tds.write() {
                if let Some(parent_td) = recent_tds.get(&header.parent_hash()).copied() {
                    recent_tds.insert(header.hash_slow(), parent_td + header.difficulty());
                } else {
                    warn!(target: "consensus::apos", parent_hash=?header.parent_hash(), "parent td not found");
                }
            }
        }

        self.recent_tds_inited.store(true, Ordering::Relaxed);
    }

    fn save_total_difficulty<H>(&self, header: &H) -> Result<(), ConsensusError>
    where
        H: BlockHeaderTrait,
    {
        self.init_recent_tds();

        let total_difficulty = {
            let mut recent_tds = self.recent_tds.write().map_err(|e| {
                ConsensusError::AposErrorDetail {
                    detail: format!("lock poisoned: {}", e),
                }
            })?;
            let parent_td = recent_tds.get(&header.parent_hash()).ok_or_else(|| {
                ConsensusError::AposErrorDetail {
                    detail: format!(
                        "td not found for parent hash {:?}, current header number={}",
                        header.parent_hash(),
                        header.number()
                    ),
                }
            })?;
            *parent_td + header.difficulty()
        };

        let mut recent_tds = self.recent_tds.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        recent_tds.insert(header.hash_slow(), total_difficulty);
        debug!(target: "consensus::apos", "saved total_difficulty {}", total_difficulty);
        Ok(())
    }

    /// snapshot retrieves the authorization snapshot at a given point in time.
    fn snapshot_inner(
        &self,
        number: u64,
        hash: B256,
        parents: Option<Vec<Provider::Header>>,
    ) -> Result<Snapshot, ConsensusError> {
        let mut headers: Vec<Provider::Header> = Vec::new();
        let mut snap: Option<Snapshot> = None;
        let mut hash = hash;
        let mut number = number;
        let mut parents = parents;

        let mut recents = self.recents.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        let mut recent_headers = self.recent_headers.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;

        while snap.is_none() {
            //Attempt to retrieve a snapshot from memory
            if let Some(cached_snap) = recents.get(&hash) {
                snap = Some(cached_snap.clone());
                break;
            }

            // TODO: SnapshotProvider removed in reth v1.5.0 - need to implement alternative storage
            // Attempt to obtain a snapshot from the disk
            // if number != 0 && number % CHECKPOINT_INTERVAL == 0 {
            //     if let Ok(Some(s)) = self.provider.load_snapshot_by_hash(&hash) {
            //         snap = Some(s);
            //         break;
            //     }
            //     debug!(target: "consensus::apos", "Snapshot not found for hash: {}, at number: {}", hash, number);
            // }

            // If we're at the genesis, snapshot the initial state. Alternatively if we're
            // at a checkpoint block without a parent (light client CHT), or we have piled
            // up more headers than allowed to be reorged (chain reinit from a freezer),
            // consider the checkpoint trusted and snapshot it.
            if number == 0
                || (number % self.config.epoch == 0
                    && (headers.len() > FULL_IMMUTABILITY_THRESHOLD
                        || self
                            .provider
                            .header_by_number(number - 1)
                            .map_err(|_| ConsensusError::UnknownBlock)?
                            .is_none()))
            {
                if let Ok(Some(checkpoint)) = self.provider.header_by_number(number) {
                    debug!(target: "consensus::apos", "checkpoint={:?}", checkpoint);
                    let hash = checkpoint.hash_slow();
                    //info!(target: "consensus::apos", "snapshot() : number={}, hash_slow hash={:?}", number, hash);

                    //Calculate the list of signatories
                    let signers_count =
                        (checkpoint.extra_data().len() - EXTRA_VANITY - SIGNATURE_LENGTH)
                            / Address::len_bytes();

                    let mut signers = Vec::with_capacity(signers_count);

                    for i in 0..signers_count {
                        let start = EXTRA_VANITY + i * Address::len_bytes();
                        let end = start + Address::len_bytes();
                        signers.push(Address::from_slice(&checkpoint.extra_data()[start..end]));
                    }
                    debug!(target: "consensus::apos", ?signers,
                        "genesis signers:"
                    );

                    let s = Snapshot::new_snapshot(self.config.clone(), number, hash, signers);
                    // TODO: SnapshotProvider removed in reth v1.5.0 - need to implement alternative storage
                    // self.provider.save_snapshot_by_hash(&hash, s.clone()).map_err(|_| ConsensusError::UnknownBlock)?;
                    snap = Option::from(s);

                    debug!(target: "consensus::apos", ?snap,
                        "Stored checkpoint snapshot to disk, number: {}, hash: {}",
                        number,
                        hash
                    );
                    break;
                }
            }

            // No snapshot for this header, gather the header and move backward
            let from_parent = parents
                .as_mut()
                .and_then(|p| if p.is_empty() { None } else { p.pop() });
            let header = if let Some(header) = from_parent {
                if header.hash_slow() != hash || header.number() != number {
                    error!(target: "consensus::apos", "parent hash check failed: {:?}, {:?}, {:?}, {:?}", header.hash_slow(), hash, header.number(), number);
                    return Err(ConsensusError::UnknownBlock);
                }
                header
            } else if let Some(v) = recent_headers.get(&hash) {
                v.clone()
            } else if let Some(header) = self
                .provider
                .header_by_hash_or_number(hash.into())
                .map_err(|_| ConsensusError::UnknownBlock)?
            {
                header
            } else {
                error!(target: "consensus::apos", "hash not found: {:?}", hash);
                return Err(ConsensusError::UnknownBlock);
            };

            hash = header.parent_hash();
            headers.push(header);
            number -= 1;
        }

        //Find the previous snapshot and apply any pending headers to it
        let headers_len = headers.len();
        let half_len = headers_len / 2;
        for i in 0..half_len {
            headers.swap(i, headers_len - 1 - i);
        }

        let snap = snap
            .ok_or(ConsensusError::AposErrorDetail {
                detail: "snapshot not found".to_string(),
            })?
            .apply::<_, Provider::Header>(headers, |header| {
                let signer = recover_address_generic(&header)?;
                Ok(signer)
            })
            .map_err(|_| ConsensusError::InvalidDifficulty)?;

        recents.insert(snap.hash, snap.clone());

        // TODO: SnapshotProvider removed in reth v1.5.0 - need to implement alternative storage
        // If a new checkpoint snapshot is generated, save it to disk
        // if snap.number % CHECKPOINT_INTERVAL == 0 && headers_len > 0 {
        //     self.provider.save_snapshot_by_hash(&snap.hash, snap.clone()).map_err(|_|ConsensusError::SaveSnapshotError)?;
        //     debug!(
        //         "Stored voting snapshot to disk, number: {}, hash: {}",
        //         snap.number,
        //         snap.hash
        //     );
        // }

        Ok(snap)
    }
}

fn calc_difficulty(snap: &Snapshot, signer: &Address) -> U256 {
    if snap.inturn(snap.number + 1, signer) {
        DIFF_IN_TURN
    } else {
        DIFF_NO_TURN
    }
}

impl<Provider, ChainSpec> Debug for APos<Provider, ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks,
    Provider: 'static
        + Clone
        + HeaderProvider<Header = reth_primitives_traits::Header>
        + BlockIdReader
        + BlockReaderIdExt
        + Unpin,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("APos")
            .field("config", &self.config)
            .field("signer", &self.signer.read().ok())
            .finish_non_exhaustive()
    }
}

impl<Provider, ChainSpec> HeaderValidator for APos<Provider, ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks,
    Provider: 'static
        + Clone
        + HeaderProvider<Header = reth_primitives_traits::Header>
        + BlockIdReader
        + BlockReaderIdExt
        + Unpin,
{
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        let header = header.header();
        if header.number() == 0 {
            return Err(ConsensusError::UnknownBlock);
        }
        let number = header.number();

        // Don't waste time checking blocks from the future
        let present_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| ConsensusError::AposErrorDetail {
                detail: format!("system time error: {}", e),
            })?
            .as_secs();

        if header.timestamp()
            > present_timestamp + alloy_eips::merge::ALLOWED_FUTURE_BLOCK_TIME_SECONDS
        {
            return Err(ConsensusError::TimestampIsInFuture {
                timestamp: header.timestamp(),
                present_timestamp,
            });
        }

        // Checkpoint blocks need to enforce zero beneficiary
        let checkpoint = (number % self.config.epoch) == 0;
        if checkpoint && header.beneficiary() != Address::ZERO {
            return Err(ConsensusError::InvalidCheckpointBeneficiary);
        }

        // Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
        let nonce = header.nonce().ok_or(ConsensusError::AposErrorDetail {
            detail: "header nonce is missing".to_string(),
        })?;
        if nonce != NONCE_AUTH_VOTE && nonce != NONCE_DROP_VOTE {
            return Err(ConsensusError::InvalidVote);
        }

        if checkpoint && nonce != NONCE_DROP_VOTE {
            return Err(ConsensusError::InvalidCheckpointVote);
        }

        // Check that the extra-data contains both the vanity and signature
        if header.extra_data().len() < EXTRA_VANITY {
            return Err(ConsensusError::MissingVanity);
        }

        if header.extra_data().len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err(ConsensusError::MissingSignature);
        }

        // Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
        let signers_bytes = header.extra_data().len() - EXTRA_VANITY - EXTRA_SEAL;
        if !checkpoint && signers_bytes != 0 {
            return Err(ConsensusError::ErrExtraSigners);
        }

        //todo
        if checkpoint && signers_bytes % 20 != 0 {
            return Err(ConsensusError::InvalidCheckpointSigners);
        }

        // Ensure that the block's difficulty is meaningful (may not be correct at this point)
        if number > 0
            && (header.difficulty().is_zero()
                || (header.difficulty() != DIFF_IN_TURN && header.difficulty() != DIFF_NO_TURN))
        {
            return Err(ConsensusError::InvalidDifficulty);
        }

        //todo All basic checks passed, verify cascading fields
        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        debug!(target: "consensus::apos", ?header, "in validate_header_against_parent");

        let header_hash = header.hash();
        let header = header.header();
        let number = header.number();
        if number == 0 {
            return Ok(());
        }

        let snap = self.snapshot_inner(
            number - 1,
            header.parent_hash(),
            Some(vec![parent.header().clone()]),
        )?;
        if number % self.config.epoch == 0 {
            let signers: Vec<u8> = snap
                .signers
                .iter()
                .flat_map(|signer| signer.as_slice().to_vec())
                .collect();
            let extra_suffix = header.extra_data().len() - EXTRA_SEAL;
            if header.extra_data()[EXTRA_VANITY..extra_suffix] != signers[..] {
                return Err(ConsensusError::InvalidCheckpointSigners);
            }
        }

        self.verify_seal(&snap, header, None)
            .map_err(|e| ConsensusError::AposErrorDetail {
                detail: e.to_string(),
            })?;
        let mut recent_headers = self.recent_headers.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        recent_headers.insert(header_hash, header.clone());

        self.save_total_difficulty(header)?;

        Ok(())
    }

    /// Validates the given headers
    ///
    /// This ensures that the first header is valid on its own and all subsequent headers are valid
    /// on its own and valid against its parent.
    ///
    /// Note: this expects that the headers are in natural order (ascending block number)
    fn validate_header_range(
        &self,
        headers: &[SealedHeader],
    ) -> Result<(), HeaderConsensusError<reth_primitives_traits::Header>> {
        Ok(())
    }
}

impl<Provider, ChainSpec, N> FullConsensus<N> for APos<Provider, ChainSpec>
where
    Provider: HeaderProvider<Header = reth_primitives_traits::Header>
        + BlockIdReader
        + BlockReaderIdExt
        + Clone
        + Unpin
        + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks,
    N: NodePrimitives,
    APos<Provider, ChainSpec>: HeaderValidator<<N as NodePrimitives>::BlockHeader>,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
        _receipt_root_bloom: Option<reth_consensus::ReceiptRootBloom>,
        // EIP-7928 block access list hash, added upstream. APoS does not produce
        // one, so post-execution validation ignores it.
        _block_access_list_hash: Option<alloy_primitives::B256>,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }
}

impl<Provider, ChainSpec, B> Consensus<B> for APos<Provider, ChainSpec>
where
    Provider: HeaderProvider<Header = reth_primitives_traits::Header>
        + BlockIdReader
        + BlockReaderIdExt
        + Clone
        + Unpin
        + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks,
    B: BlockTrait,
    APos<Provider, ChainSpec>: HeaderValidator<<B as reth_primitives_traits::Block>::Header>,
{
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn validate_block_pre_execution(&self, _block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        Ok(())
    }

    /// Prepare implements consensus.Engine, preparing all the consensus fields of the
    /// header for running the transactions on top.
    fn prepare(&self, parent_header: &SealedHeader) -> Result<Header, ConsensusError> {
        let mut header = Header::default();
        //If the block is not a checkpoint, vote randomly
        header.beneficiary = Address::ZERO;
        header.nonce = B64::from(0u64);
        header.number = parent_header.number + 1;
        header.parent_hash = parent_header.hash();

        //Assemble voting snapshots to check which votes are meaningful
        let snap = self
            .snapshot_inner(parent_header.number, parent_header.hash(), None)
            .map_err(|_| ConsensusError::UnknownBlock)?;

        if header.number % self.config.epoch != 0 {
            //Collect all proposals to be voted on
            let proposals_lock = self.proposals.read().map_err(|e| {
                ConsensusError::AposErrorDetail {
                    detail: format!("lock poisoned: {}", e),
                }
            })?;
            let addresses: Vec<Address> = proposals_lock
                .iter()
                //.filter(|(&address, &authorize)| snap.valid_vote(address, authorize))
                .map(|(address, _)| *address)
                .collect();

            //If there are proposals to be voted on, proceed with the vote
            if !addresses.is_empty() {
                if let Some(&addr) = addresses.choose(&mut rand::rng()) {
                    header.beneficiary = addr;
                    if let Some(&authorize) = proposals_lock.get(&header.beneficiary) {
                        if authorize {
                            header.nonce = NONCE_AUTH_VOTE.into();
                        } else {
                            header.nonce = NONCE_DROP_VOTE.into();
                        }
                    }
                }
            }
        }

        debug!(target: "consensus::apos", ?snap, "snap");
        //Copy the signer to prevent data competition
        let signer_guard = self.signer.read().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        if let Some(signer) = *signer_guard {
            //Set the correct difficulty level
            header.difficulty = calc_difficulty(&snap, &signer);
        } else {
            return Err(ConsensusError::NoSignerSet);
        }

        let mut extra_data_mut = BytesMut::from(&header.extra_data[..]);
        //Ensure that the additional data has all its components
        extra_data_mut.resize(EXTRA_VANITY, 0x00);

        if header.number % self.config.epoch == 0 {
            for signer in snap.signers {
                extra_data_mut.extend(signer.iter());
            }
        }
        extra_data_mut.resize(extra_data_mut.len() + SIGNATURE_LENGTH, 0x00);
        header.extra_data = Bytes::from(extra_data_mut.freeze());

        header.mix_hash = Default::default();

        // Ensure the timestamp has the correct delay
        if let Ok(Some(parent)) = self
            .provider
            .header_by_hash_or_number(header.parent_hash.into())
        {
            let parent_time = parent.timestamp();
            header.timestamp = parent_time + self.config.period;
        }

        Ok(header)
    }

    fn seal(&self, header: &mut Header) -> Result<(), ConsensusError> {
        // Sealing the genesis block is not supported
        if header.number == 0 {
            return Err(ConsensusError::UnknownBlock);
        }

        // For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
        // if self.config.period == 0 && header.body.transactions.is_empty() {
        //     return Err(AposError::UnTransion.into());
        // }
        //todo

        let signer = self
            .signer
            .read()
            .map_err(|e| ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            })?
            .ok_or(ConsensusError::NoSignerSet)?;
        debug!(target: "consensus::apos", "seal() signer={:?}", signer);
        // Bail out if we're unauthorized to sign a block
        let snap = self.snapshot_inner(header.number - 1, header.parent_hash, None)?;
        debug!(target: "consensus::apos", "signer list: {:?}, signer: {}", snap.signers, signer);
        if !snap.signers.contains(&signer) {
            error!(target: "consensus::apos", "err signer not in list: {:?}, signer: {}", snap.signers, signer);
            return Err(ConsensusError::UnauthorizedSigner);
        }

        // If we're amongst the recent signers, wait for the next block
        for (seen, recent) in &snap.recents {
            if *recent == signer {
                let limit = (snap.signers.len() as u64 / 2) + 1;
                if header.number < limit || *seen > header.number - limit {
                    error!(target: "consensus::engine", "Signed recently, must wait for others: limit: {}, seen: {}, number: {}, signer: {}", limit, seen, header.number, signer);
                    return Err(ConsensusError::RecentlySigned);
                }
            }
        }

        // // Beijing hard fork logic (if applicable)
        // if self.chain_spec.is_beijing_active_at_block(block.number)
        //
        // }

        let eth_signer_guard = self.eth_signer.read().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        let eth_signer = eth_signer_guard
            .as_ref()
            .ok_or(ConsensusError::NoSignerSet)?;
        // Sign all the things!
        let header_bytes = seal_hash(header);
        let sighash = eth_signer
            .sign_hash_sync(&header_bytes)
            .map_err(|_| ConsensusError::SignHeaderError)?;

        let mut extra_data_mut = BytesMut::from(&header.extra_data[..]);
        extra_data_mut[header.extra_data.len().saturating_sub(SIGNATURE_LENGTH)..]
            .copy_from_slice(&sighash.as_bytes());
        if let Some(last) = extra_data_mut.last_mut() {
            *last -= 27;
        } else {
            return Err(ConsensusError::AposErrorDetail {
                detail: "extra_data is empty after signature copy".to_string(),
            });
        }
        header.extra_data = Bytes::from(extra_data_mut.freeze());

        let mut recent_headers = self.recent_headers.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        recent_headers.insert(header.hash_slow(), header.clone());

        self.save_total_difficulty(header)?;

        Ok(())
    }

    fn set_eth_signer_by_key(&self, eth_signer_key: Option<String>) -> Result<(), ConsensusError> {
        let eth_signer = match eth_signer_key {
            Some(key) => {
                let fixed_bytes = FixedBytes::from_str(&key).map_err(|e| {
                    ConsensusError::AposErrorDetail {
                        detail: format!("Invalid signer key format: {}", e),
                    }
                })?;
                let signer = PrivateKeySigner::from_bytes(&fixed_bytes).map_err(|e| {
                    ConsensusError::AposErrorDetail {
                        detail: format!("Failed to create signer from key: {}", e),
                    }
                })?;
                Some(signer)
            }
            None => None,
        };
        self.set_signer(eth_signer);
        Ok(())
    }

    fn get_eth_signer_address(&self) -> Result<Option<Address>, ConsensusError> {
        Ok(*self
            .signer
            .read()
            .map_err(|err| ConsensusError::AposErrorDetail {
                detail: err.to_string(),
            })?)
    }

    fn snapshot(
        &self,
        number: u64,
        hash: B256,
        parents: Option<Vec<Header>>,
    ) -> Result<Snapshot, ConsensusError> {
        self.snapshot_inner(number, hash, parents)
    }

    fn propose(&self, address: Address, auth: bool) -> Result<(), ConsensusError> {
        info!(target: "consensus::apos", "propose(), address={}, auth={}", address, auth);
        let mut proposals_guard = self.proposals.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        proposals_guard.insert(address, auth);
        Ok(())
    }

    fn discard(&self, address: Address) -> Result<(), ConsensusError> {
        info!(target: "consensus::apos", "discard(), address={}", address);
        let mut proposals_guard = self.proposals.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        proposals_guard.remove(&address);
        Ok(())
    }

    fn proposals(&self) -> Result<HashMap<Address, bool>, ConsensusError> {
        info!(target: "consensus::apos", "proposals()");
        let proposals_guard = self.proposals.read().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        Ok(proposals_guard.clone())
    }

    fn total_difficulty(&self, hash: B256) -> U256 {
        self.init_recent_tds();

        // First try the in-memory cache
        {
            match self.recent_tds.write() {
                Ok(mut recent_tds) => {
                    if let Some(td) = recent_tds.get(&hash) {
                        debug!(target: "consensus::apos", ?hash, total_difficulty=?td, "get total_difficulty from cache");
                        return *td;
                    }
                }
                Err(e) => {
                    warn!(target: "consensus::apos", "recent_tds lock poisoned: {}", e);
                    return U256::ZERO;
                }
            }
        }

        // TD is no longer stored in the database (removed in reth v1.11.0 for PoS).
        // Try to calculate from parent TD in the in-memory cache.
        if let Ok(Some(header)) = self.provider.header(hash) {
            let parent_hash = header.parent_hash();
            let parent_td = match self.recent_tds.write() {
                Ok(mut recent_tds) => recent_tds.get(&parent_hash).copied(),
                Err(e) => {
                    warn!(target: "consensus::apos", "recent_tds lock poisoned: {}", e);
                    return U256::ZERO;
                }
            };

            if let Some(parent_td) = parent_td {
                let td = parent_td + header.difficulty();
                debug!(target: "consensus::apos", ?hash, total_difficulty=?td, "calculated total_difficulty from parent");
                match self.recent_tds.write() {
                    Ok(mut recent_tds) => {
                        recent_tds.insert(hash, td);
                    }
                    Err(e) => {
                        warn!(target: "consensus::apos", "recent_tds lock poisoned: {}", e);
                    }
                }
                return td;
            }
        }

        // Last resort: return zero with a warning
        warn!(target: "consensus::apos", ?hash, "td not found for hash, returning zero");
        U256::ZERO
    }

    fn wiggle(&self, parent_number: u64, parent_hash: BlockHash, difficulty: U256) -> Duration {
        let mut wiggle = Duration::from_millis(0);
        if let Ok(snapshot) = self.snapshot_inner(parent_number, parent_hash, None) {
            // https://eips.ethereum.org/EIPS/eip-225
            // If the signer is out-of-turn, delay signing by rand(SIGNER_COUNT * 500ms)
            if difficulty != DIFF_IN_TURN {
                wiggle = Duration::from_millis(
                    (rand::random::<f64>()
                        * snapshot.signers.len() as f64
                        * WIGGLE_TIME.as_millis() as f64) as u64,
                )
            }
        }
        wiggle
    }

    fn set_cached_reads(
        &self,
        block_hash: BlockHash,
        cached_reads: CachedReads,
    ) -> Result<(), ConsensusError> {
        let mut recent_cached_reads = self.recent_cached_reads.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        recent_cached_reads.insert(block_hash, cached_reads);
        Ok(())
    }

    fn get_cached_reads(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<CachedReads>, ConsensusError> {
        let mut recent_cached_reads = self.recent_cached_reads.write().map_err(|e| {
            ConsensusError::AposErrorDetail {
                detail: format!("lock poisoned: {}", e),
            }
        })?;
        Ok(recent_cached_reads.get(&block_hash).cloned())
    }
}

impl<Provider, ChainSpec> SignerManager for APos<Provider, ChainSpec>
where
    Provider: HeaderProvider<Header = reth_primitives_traits::Header>
        + BlockIdReader
        + BlockReaderIdExt
        + Clone
        + Unpin
        + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks,
{
    fn set_signer_key(&self, key: Option<String>) -> n42_consensus_traits::AposResult<()> {
        let eth_signer: Option<PrivateKeySigner> = match key {
            Some(k) => match k.parse() {
                Ok(signer) => Some(signer),
                Err(e) => {
                    error!(target: "consensus::apos", "Failed to parse signer key: {:?}", e);
                    return Err(n42_consensus_traits::AposError::InvalidSignerKey(
                        format!("{:?}", e),
                    ));
                }
            },
            None => None,
        };
        self.set_signer(eth_signer);
        Ok(())
    }

    fn get_signer_address(&self) -> n42_consensus_traits::AposResult<Option<Address>> {
        let signer_guard = self.signer.read().map_err(|e| {
            n42_consensus_traits::AposError::Other(format!("signer lock poisoned: {}", e))
        })?;
        Ok(*signer_guard)
    }
}
